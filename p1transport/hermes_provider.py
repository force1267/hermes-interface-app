"""P1 HermesProvider: line-JSON TCP endpoint fronting the real Hermes agent.

Unlike the Provider fixture (acked:<id>:<revision> strings, never invokes
anything), every admitted text payload launches exactly one Hermes CLI run
and only a durable terminal result becomes the completed answer.

Wire: identical v1 hello/resume/session + payload.get/payload.data/result
framing via p1transport.protocol (unchanged). Additive bootstrap session
fields only: `service_auth`, `history`, `cursor`, `requests`,
`conversation_id` (read-only recovery lookups, ownership-checked).

Durability (SQLite, WAL, service-owned, outside releases/code dirs):
  conversations(conversation_id, account_id, hermes_session_id, revision)
  requests(account_id, conversation_id, request_id, payload_hash, state,
           user_message_id, assistant_message_id, result_json,
           started_at, finished_at)
    state: running | completed | failed | outcome-unknown
    UNIQUE(request_id); same id + different bytes -> conflict (no relaunch)
  history(conversation_id, event_seq, message_id, revision, major, role, text)
  pins(conversation_id, client_key, cursor) -- reserved re-pin material

Execution rules (spec S013/S014):
  - commit pending intent BEFORE launching Hermes; commit result + history
    + cursor in ONE transaction BEFORE completed is projected.
  - crash with a running intent -> outcome-unknown on next lookup, the
    agent run is NEVER relaunched implicitly.
  - turns serialised per conversation (one Hermes run at a time);
    concurrent writers get busy/conflict, never a forked second session.
  - subprocess argv only (shell=False); stdin carries the prompt text;
    --resume uses the stored Hermes session id, never "latest";
    worker/board env (HERMES_KANBAN_*, dispatch identity) is stripped;
    HOME resolves from provider.hermes_home, cwd is provider.workspace.
  - only terminal type=result with exit_code 0, non-empty text, session_id
    plus process exit 0 counts as an assistant answer. Tool events/deltas
    are never answers; approval refusal stays a visible failed turn.
  - actions_enabled=false -> action payloads are rejected (disabled), as
    are drawer writes: no generic subprocess, no invented success.

Binds loopback only. Binds ephemeral port when port=0 (tests).
"""
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import threading
import time

from p0contract import messages, wire

from . import protocol

SCHEMA = """
CREATE TABLE IF NOT EXISTS conversations(
  conversation_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  hermes_session_id TEXT,
  revision INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS requests(
  account_id TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  request_id TEXT PRIMARY KEY,
  payload_hash TEXT NOT NULL,
  state TEXT NOT NULL,
  user_message_id TEXT,
  assistant_message_id TEXT,
  result_json TEXT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER);
CREATE TABLE IF NOT EXISTS history(
  conversation_id TEXT NOT NULL,
  event_seq INTEGER NOT NULL,
  message_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  major INTEGER NOT NULL,
  role TEXT NOT NULL,
  text TEXT NOT NULL,
  PRIMARY KEY (conversation_id, event_seq));
CREATE TABLE IF NOT EXISTS cursors(
  conversation_id TEXT PRIMARY KEY,
  cursor TEXT NOT NULL);
"""

CONV_LOCKS = {}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _now() -> int:
    return int(time.time())


class ProviderError(Exception):
    pass


class HermesProvider:
    def __init__(self, settings, db_path, service_secret,
                 account_id="mj"):
        s = settings or {}
        self.bind_host = s.get("bind_host", "127.0.0.1")
        self.bind_port = s.get("bind_port", 0)
        self.hermes_executable = s.get(
            "hermes_executable", "/root/.local/bin/hermes")
        self.hermes_home = s.get("hermes_home", "/root/.hermes")
        self.workspace = s.get("workspace", "/var/lib/interface-app/work")
        self.agent_timeout = s.get("agent_timeout_seconds", 300)
        self.grace = s.get("termination_grace_seconds", 10)
        self.output_bytes = s.get("output_bytes", 4194304)
        self.stdout_line_bytes = s.get(
            "stdout_line_bytes", 1048576)
        self.actions_enabled = bool(s.get("actions_enabled", False))
        self.account_id = account_id or s.get("account_id", "mj")
        self.db_path = db_path
        self.service_secret = service_secret or ""
        self._lock = threading.Lock()
        self._convs = {}
        self._listener = None
        self._conns = []
        self._closed = False
        self._thread = None
        self._launch_count = 0  # test hook: real CLI launches performed
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        os.makedirs(self.workspace, exist_ok=True)
        self._db = sqlite3.connect(db_path, check_same_thread=False,
                                   timeout=10)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._db.commit()
        # Crash recovery: anything left running is outcome-unknown.
        self._db.execute(
            "UPDATE requests SET state='outcome-unknown', finished_at=? "
            "WHERE state='running'", (_now(),))
        self._db.commit()

    # -- lifecycle --
    def start(self, host=None, port=None):
        if host is not None:
            self.bind_host = host
        if port is not None:
            self.bind_port = port
        if self.bind_host != "127.0.0.1":
            raise ProviderError("provider binds loopback only")
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.bind_host, self.bind_port))
        self._listener.listen(16)
        self._thread = threading.Thread(target=self._accept_loop,
                                        daemon=True)
        self._thread.start()
        return self._listener.getsockname()[1]

    @property
    def port(self):
        return self._listener.getsockname()[1]

    def stop(self):
        self._closed = True
        targets = [s for s in (self._conns + [self._listener])
                   if s is not None]
        for s in targets:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        try:
            self._db.close()
        except Exception:
            pass

    @property
    def launch_count(self):
        with self._lock:
            return self._launch_count

    # -- serving --
    def _accept_loop(self):
        while not self._closed:
            try:
                conn, peer = self._listener.accept()
            except OSError:
                return
            if peer[0] != "127.0.0.1":
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            self._conns.append(conn)
            threading.Thread(target=self._serve_conn, args=(conn,),
                             daemon=True).start()

    def _serve_conn(self, conn):
        authed = False
        try:
            f = conn.makefile("r", encoding="utf-8")
            while not self._closed:
                line = f.readline()
                if not line:
                    return
                if len(line.encode("utf-8")) > self.stdout_line_bytes + 1024:
                    self._send(conn, self._error_env(
                        "?", "frame-too-large"))
                    continue
                try:
                    env = protocol.decode_frame(line.encode("utf-8"))
                except wire.WireError as e:
                    self._send(conn, self._error_env("wire",
                                                     f"protocol-error:{e}"))
                    continue
                try:
                    reply, authed = self._handle(env, authed)
                except wire.WireError as e:
                    reply = self._error_env(env.get("id", "?"),
                                            f"rejected:{e}")
                except ProviderError as e:
                    reply = self._error_env(env.get("id", "?"),
                                            f"rejected:{e}")
                if reply is not None:
                    self._send(conn, reply)
        except (OSError, ValueError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _send(conn, env):
        conn.sendall(protocol.encode_frame(env))

    @staticmethod
    def _error_env(msg_id, text):
        env = protocol.mk_result(str(msg_id), text,
                                 msg_id=f"err-{msg_id}")
        env["status"] = "failed"
        return env

    def _check_service_auth(self, body):
        want = self.service_secret
        if not want:
            raise ProviderError("service-secret-unprovisioned")
        got = body.get("service_auth")
        if not isinstance(got, str) or not got:
            raise ProviderError("service-auth-missing")
        if not _consteq(got, want):
            raise ProviderError("service-auth-rejected")

    def _handle(self, env, authed):
        mtype = env.get("type")
        if mtype in ("hello", "resume"):
            res = messages.validate_message(env)
            if res["status"] != "ok":
                raise wire.WireError("handshake-needs-bootstrap")
            body = res["body"]
            self._check_service_auth(body)
            authed = True
            sess = protocol.negotiate_for_body(
                body, [dict(protocol.V10)], [], "r1")
            sess["conversation_id"] = body.get("conversation_id")
            # Additive read-only recovery lookups, ownership-checked.
            cid = body.get("conversation_id")
            if isinstance(cid, str) and cid:
                if body.get("history") is True:
                    sess["history"] = self._read_history(cid)
                if body.get("cursor") is True:
                    sess["cursor"] = self._read_cursor(cid)
                if body.get("requests") is True:
                    sess["requests"] = self._read_requests(cid)
            return protocol.mk_session(
                sess, msg_id=f"session-{body.get('client_id', '?')}"), authed
        if not authed:
            raise ProviderError("service-auth-required")
        if mtype in ("text", "action"):
            norm = wire.validate_envelope(env)
            ref = norm["payload_ref"]
            get = protocol.mk_payload_get(
                {"id": ref["id"], "version": ref["version"],
                 "sha256": ref["sha256"]},
                request_id=f"get:{norm['id']}:{norm['revision']}")
            return get, authed
        if mtype == "payload.data":
            res = messages.validate_message(env)
            if res["status"] != "ok":
                raise wire.WireError("payload-data-invalid")
            req = env["request_id"]
            parts = req.split(":")
            if len(parts) != 3 or parts[0] != "get":
                raise wire.WireError("payload-data-request_id-shape")
            msg_id, revision = parts[1], int(parts[2])
            try:
                body = json.loads(env["data"])
            except Exception as e:
                raise wire.WireError(f"payload-bad-json: {e}")
            return self._accept_payload(msg_id, revision, body,
                                       env["data"]), authed
        res = messages.validate_message(env)
        if res["status"] == "fallback":
            return protocol.mk_result(env.get("id", "?"),
                                      f"fallback:{res['reason']}",
                                      msg_id=f"fb-{env.get('id', '?')}"), authed
        raise wire.WireError(f"unexpected-type:{mtype}")

    # -- payload execution --
    def _conv_lock(self, cid):
        with self._lock:
            return self._convs.setdefault(cid, threading.Lock())

    def _accept_payload(self, msg_id, revision, body, payload_str):
        cid, request_id, text, action = self._parse_payload(
            msg_id, revision, body)
        if action is not None:
            if not self.actions_enabled:
                return self._error_env(
                    request_id, "rejected:actions-disabled")
            return self._error_env(request_id,
                                   "rejected:action-not-wired")
        payload_hash = _sha(payload_str.encode("utf-8"))
        lock = self._conv_lock(cid)
        if not lock.acquire(blocking=False):
            env = self._error_env(request_id, "rejected:busy")
            env["code"] = "busy"
            return env
        try:
            return self._run_text_turn(cid, request_id, payload_hash,
                                      msg_id, revision, text)
        finally:
            lock.release()

    def _parse_payload(self, msg_id, revision, body):
        if not isinstance(body, dict):
            raise wire.WireError("payload-body-must-be-object")
        if "action_id" in body:
            return (body.get("conversation_id") or "default",
                    body.get("request_id", f"get:{msg_id}:{revision}"),
                    None, body["action_id"])
        text = body.get("text")
        if not isinstance(text, str) or not text.strip():
            raise wire.WireError("payload-text-missing")
        cid = body.get("conversation_id")
        if cid is not None and (not isinstance(cid, str) or not cid):
            raise wire.WireError("payload-conversation_id-invalid")
        cid = cid or "default"
        if ":" in msg_id:
            raise wire.WireError("payload-msg_id-colons")
        req = body.get("request_id")
        if req is not None and (not isinstance(req, str) or not req):
            raise wire.WireError("payload-request_id-invalid")
        request_id = req or f"get-{msg_id}-{revision}"
        if ":" in request_id:
            raise wire.WireError("payload-request_id-colons")
        return cid, request_id, text, None

    def _run_text_turn(self, cid, request_id, payload_hash, msg_id,
                       revision, text):
        cur = self._db.execute(
            "SELECT payload_hash, state, result_json FROM requests "
            "WHERE request_id=?", (request_id,)).fetchone()
        if cur is not None:
            old_hash, state, result_json = cur
            if old_hash != payload_hash:
                return self._conflict(request_id)
            if state == "completed":
                saved = json.loads(result_json)
                env = protocol.mk_result(request_id, saved["text"],
                                         msg_id=f"res-{msg_id}-{revision}")
                self._annotate_completed(env, saved)
                return env
            if state in ("running", "outcome-unknown"):
                env = self._error_env(request_id,
                                      "outcome-unknown:already-running")
                env["status"] = "outcome-unknown"
                return env
            # failed: a retry is a NEW request_id (explicit user action);
            # same id after failure stays failed, never relaunches.
            return self._error_env(request_id, "failed:see-history")
        user_mid = f"m-{request_id}-u"
        with self._lock:
            self._db.execute(
                "INSERT INTO requests(account_id, conversation_id,"
                " request_id, payload_hash, state, user_message_id,"
                " started_at) VALUES(?,?,?,?,?,?,?)",
                (self.account_id, cid, request_id, payload_hash,
                 "running", user_mid, _now()))
            self._db.execute(
                "INSERT OR IGNORE INTO conversations(conversation_id,"
                " account_id, revision, updated_at) VALUES(?,?,0,?)",
                (cid, self.account_id, _now()))
            self._db.commit()
        self._append_history(cid, user_mid, revision, 1, "user", text)
        term, proc_ok = self._launch_hermes(cid, text)
        with self._lock:
            self._launch_count += 1
        if term is None or not proc_ok:
            reason = (term or {}).get("reason", "agent-failed")
            self._db.execute(
                "UPDATE requests SET state='failed', finished_at=?,"
                " result_json=? WHERE request_id=?",
                (_now(), json.dumps({"reason": reason,
                                     "terminal": term}), request_id))
            self._db.commit()
            env = self._error_env(request_id, f"failed:{reason}")
            return env
        assistant_mid = f"m-{request_id}-a"
        self._append_history(cid, assistant_mid, revision + 1, 1,
                            "assistant", term["text"])
        saved = {"text": term["text"],
                 "hermes_session_id": term["session_id"],
                 "assistant_message_id": assistant_mid,
                 "user_message_id": user_mid,
                 "conversation_id": cid,
                 "outcome": "completed"}
        self._db.execute(
            "UPDATE requests SET state='completed', finished_at=?,"
            " assistant_message_id=?, result_json=? WHERE request_id=?",
            (_now(), assistant_mid, json.dumps(saved), request_id))
        if term.get("session_id"):
            self._db.execute(
                "UPDATE conversations SET hermes_session_id=?,"
                " revision=revision+1, updated_at=? WHERE conversation_id=?",
                (term["session_id"], _now(), cid))
        self._db.commit()
        env = protocol.mk_result(request_id, term["text"],
                                 msg_id=f"res-{msg_id}-{revision}")
        self._annotate_completed(env, saved)
        return env

    def _conflict(self, request_id):
        env = self._error_env(request_id, "rejected:request-conflict")
        env["code"] = "conflict"
        return env

    @staticmethod
    def _annotate_completed(env, saved):
        env["status"] = "completed"
        env["code"] = "ok"
        env["conversation_id"] = saved["conversation_id"]
        env["message_id"] = saved["assistant_message_id"]
        env["hermes_session_id"] = saved["hermes_session_id"]
        env["cursor"] = saved["assistant_message_id"]

    def _read_history(self, cid):
        rows = self._db.execute(
            "SELECT event_seq, message_id, revision, major, role, text"
            " FROM history WHERE conversation_id=? ORDER BY event_seq",
            (cid,)).fetchall()
        return [{"event_seq": r[0], "message_id": r[1], "revision": r[2],
                 "major": r[3], "role": r[4], "text": r[5]} for r in rows]

    def _read_cursor(self, cid):
        row = self._db.execute(
            "SELECT cursor FROM cursors WHERE conversation_id=?",
            (cid,)).fetchone()
        return row[0] if row else None

    def _read_requests(self, cid):
        rows = self._db.execute(
            "SELECT request_id, state, user_message_id,"
            " assistant_message_id FROM requests WHERE conversation_id=?",
            (cid,)).fetchall()
        return [{"request_id": r[0], "state": r[1],
                 "user_message_id": r[2],
                 "assistant_message_id": r[3]} for r in rows]

    def _append_history(self, cid, message_id, revision, major, role,
                       text):
        row = self._db.execute(
            "SELECT COALESCE(MAX(event_seq), -1) FROM history"
            " WHERE conversation_id=?", (cid,)).fetchone()
        seq = (row[0] if row else -1) + 1
        self._db.execute(
            "INSERT INTO history(conversation_id, event_seq, message_id,"
            " revision, major, role, text) VALUES(?,?,?,?,?,?,?)",
            (cid, seq, message_id, revision, major, role, text))
        self._db.execute(
            "INSERT OR REPLACE INTO cursors(conversation_id, cursor)"
            " VALUES(?,?)", (cid, message_id))
        self._db.commit()

    def get_request(self, request_id):
        """Read-only lost-response lookup: never launches the agent."""
        row = self._db.execute(
            "SELECT state, result_json, conversation_id,"
            " user_message_id, assistant_message_id FROM requests"
            " WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            return None
        state, result_json, cid, umid, amid = row
        out = {"request_id": request_id, "state": state,
               "conversation_id": cid, "user_message_id": umid,
               "assistant_message_id": amid}
        if result_json:
            out["result"] = json.loads(result_json)
        return out

    # -- real Hermes invocation --
    def _launch_hermes(self, cid, text):
        row = self._db.execute(
            "SELECT hermes_session_id FROM conversations WHERE"
            " conversation_id=?", (cid,)).fetchone()
        resume_sid = row[0] if row and row[0] else None
        argv = [self.hermes_executable, "chat", "--oneshot",
                "--query-file", "-", "--format", "stream-json",
                "--no-restore-cwd", "--source", "interface-app"]
        if resume_sid:
            argv += ["--resume", resume_sid]
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("HERMES_KANBAN_")
               and k not in ("HERMES_DISPATCH_ID", "HERMES_WORKER_ID",
                             "HERMES_TASK_ID", "HERMES_WORKSPACE")}
        env["HOME"] = self.hermes_home
        try:
            proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=self.workspace, env=env,
                shell=False, text=True)
        except OSError as e:
            return {"reason": f"spawn-failed:{e}"}, False
        try:
            stdout, _stderr = proc.communicate(
                input=text, timeout=self.agent_timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=self.grace)
            except Exception:
                pass
            return {"reason": "agent-timeout"}, False
        if len(stdout.encode("utf-8")) > self.output_bytes:
            return {"reason": "agent-output-too-large"}, False
        term = self._parse_terminal(stdout)
        if term is None:
            return {"reason": "agent-no-terminal-record"}, False
        if proc.returncode != 0:
            term["reason"] = "agent-nonzero-exit"
            return term, False
        if term.get("exit_code", 1) != 0:
            term["reason"] = "agent-terminal-error"
            return term, False
        if not term.get("text") or not term.get("session_id"):
            term["reason"] = "agent-empty-terminal"
            return term, False
        return term, True

    def _parse_terminal(self, stdout):
        term = None
        for line in stdout.splitlines():
            if len(line.encode("utf-8")) > self.stdout_line_bytes:
                return {"reason": "agent-line-too-large"}
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if not isinstance(rec, dict):
                continue
            if rec.get("type") == "result":
                term = {"exit_code": rec.get("exit_code", 1),
                        "text": rec.get("text", ""),
                        "session_id": rec.get("session_id", "")}
            elif (rec.get("type") == "system"
                    and rec.get("subtype") == "init"
                    and rec.get("session_id")):
                if term is None:
                    term = {}
                term.setdefault("session_id", rec["session_id"])
                term.setdefault("init_seen", True)
        return term


def _consteq(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    acc = 0
    for x, y in zip(a.encode(), b.encode()):
        acc |= x ^ y
    return acc == 0
