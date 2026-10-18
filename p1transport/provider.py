"""P1 provider: authenticated protocol endpoint over one real TCP hop.

Owns: version registry revision, ActionDispatcher (E04 request_id dedup),
RevisionStore (E02/E05 id+revision+major dedup), acked message log,
last-good fragments + regen counter (V05 re-upgrade without regen),
monotonic cursor. No renderer, no policy beyond the handshake.
"""
import socket
import threading

from p0contract import evolution, messages, wire

from . import protocol


class Provider:
    def __init__(self, server_versions=None, server_caps=(),
                 registry_revision="r1"):
        self.server_versions = [dict(v) for v in
                                (server_versions or [dict(protocol.V10)])]
        self.server_caps = list(server_caps)
        self.registry_revision = registry_revision
        self.dispatcher = messages.ActionDispatcher()
        self.dispatcher.register("echo", {"text": "string"})
        self.rev = messages.RevisionStore()
        self.acked = []          # [(id, revision)] in accept order
        self.last_good = {}      # msg id -> fragment dict (V05 re-pin source)
        self.regen_count = 0
        self.cursor = 0
        self._lock = threading.Lock()
        self._listener = None
        self._conns = []
        self._thread = None
        self._closed = False

    # -- lifecycle --
    def start(self):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._thread = threading.Thread(target=self._accept_loop,
                                        daemon=True)
        self._thread.start()
        return self._listener.getsockname()[1]

    @property
    def port(self):
        return self._listener.getsockname()[1]

    def stop(self):
        self._closed = True
        for s in (self._conns + [self._listener]):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    # -- state readers (tests) --
    def acked_list(self):
        with self._lock:
            return list(self.acked)

    # -- serving --
    def _accept_loop(self):
        while not self._closed:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            self._conns.append(conn)
            threading.Thread(target=self._serve_conn, args=(conn,),
                             daemon=True).start()

    def _serve_conn(self, conn):
        try:
            f = conn.makefile("r", encoding="utf-8")
            while not self._closed:
                line = f.readline()
                if not line:
                    return
                try:
                    env = protocol.decode_frame(line.encode("utf-8"))
                except wire.WireError as e:
                    self._send(conn, protocol.mk_result(
                        "wire", f"protocol-error:{e}", msg_id="err-wire"))
                    continue
                try:
                    reply = self._handle(env)
                except wire.WireError as e:
                    reply = protocol.mk_result(
                        env.get("id", "?"), f"rejected:{e}",
                        msg_id=f"err-{env.get('id', '?')}")
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

    def _handle(self, env):
        mtype = env.get("type")
        if mtype in ("hello", "resume"):
            return self._handle_handshake(env)
        if mtype in ("text", "action"):
            return self._handle_chat(env)
        if mtype == "payload.data":
            return self._handle_payload_data(env)
        # session/result/error/payload.get never initiate from client here
        res = messages.validate_message(env)
        if res["status"] == "fallback":
            return protocol.mk_result(env.get("id", "?"),
                                      f"fallback:{res['reason']}",
                                      msg_id=f"fb-{env.get('id', '?')}")
        raise wire.WireError(f"unexpected-type:{mtype}")

    def _handle_handshake(self, env):
        res = messages.validate_message(env)
        if res["status"] != "ok":
            raise wire.WireError("handshake-needs-bootstrap")
        body = res["body"]
        sess = protocol.negotiate_for_body(body, self.server_versions,
                                           self.server_caps,
                                           self.registry_revision)
        if sess["selected_version"] is not None:
            # V04/V05: never echo null-fragment last_seen entries.
            # Resolve each last_seen id against authoritative last_good and
            # emit a pin only when a compatible approved entry exists.
            last_seen = body.get("last_seen", []) or []
            pins = []
            seen_ids = set()
            for entry in last_seen:
                mid = (entry or {}).get("id")
                if not isinstance(mid, str) or not mid:
                    continue
                seen_ids.add(mid)
                frag = self.last_good.get(mid)
                if frag is None:
                    continue  # unresolvable: no pin, never null
                if not isinstance(frag.get("fragment_id"), str):
                    continue
                if not isinstance(frag.get("fragment_version"), dict):
                    continue
                pins.append({"id": mid, "revision": frag["revision"],
                             "fragment_id": frag["fragment_id"],
                             "fragment_version":
                                 dict(frag["fragment_version"])})
            for mid, frag in self.last_good.items():
                if mid not in seen_ids:
                    if not isinstance(frag.get("fragment_id"), str):
                        continue
                    if not isinstance(frag.get("fragment_version"), dict):
                        continue
                    pins.append({"id": mid, "revision": frag["revision"],
                                 "fragment_id": frag["fragment_id"],
                                 "fragment_version":
                                     dict(frag["fragment_version"])})
            sess["pins"] = pins
            if pins and sess["mode"] == "rich":
                sess["reason"] = "negotiated+re-pinned"
            if not pins and last_seen:
                # Resume history exists but nothing compatible approved:
                # keep the V04 version selection, fall back to static
                # text with the upgrade nudge per V05.
                sess["mode"] = "text"
                sess["reason"] = "upgrade-nudge:re-pin-unavailable"
                sess["upgrade_available"] = True
        return protocol.mk_session(sess, msg_id=f"session-{body['client_id']}")

    def _handle_chat(self, env):
        # Payload not inline: demand it via payload.get (E03), client
        # answers with payload.data on the same connection.
        norm = wire.validate_envelope(env)
        ref = norm["payload_ref"]
        get = protocol.mk_payload_get(
            {"id": ref["id"], "version": ref["version"],
             "sha256": ref["sha256"]},
            request_id=f"get:{norm['id']}:{norm['revision']}")
        return get  # _serve_conn sends this; data arrives next frame

    def _handle_payload_data(self, env):
        res = messages.validate_message(env)
        if res["status"] != "ok":
            raise wire.WireError("payload-data-invalid")
        # request_id = "get:{msg_id}:{revision}"
        req = env["request_id"]
        parts = req.split(":")
        if len(parts) != 3 or parts[0] != "get":
            raise wire.WireError("payload-data-request_id-shape")
        msg_id, revision = parts[1], int(parts[2])
        payload_str = env["data"]
        try:
            body = __import__("json").loads(payload_str)
        except Exception as e:
            raise wire.WireError(f"payload-bad-json: {e}")
        with self._lock:
            return self._accept_payload(msg_id, revision, body)

    def _accept_payload(self, msg_id, revision, body):
        """E02/E05 dedup + E04 action dedup. Returns a result envelope."""
        major = 1
        if isinstance(body, dict) and "action_id" in body:
            # E04: exact replay returns the saved correlated result with
            # no new effect, even though (id,revision,major) is a dup.
            req_id = body.get("request_id", f"get:{msg_id}:{revision}")
            saved = self.dispatcher.results.get(req_id)
            if saved is not None:
                return protocol.mk_result(
                    req_id, saved["text"],
                    msg_id=f"res-{msg_id}-{revision}")
            verdict = self.rev.submit(msg_id, revision, major)
            if verdict in ("stale", "duplicate-inert"):
                return protocol.mk_result(f"get:{msg_id}:{revision}",
                                          f"{verdict}:{msg_id}:{revision}",
                                          msg_id=f"res-{msg_id}-{revision}-dup")
            saved = self.dispatcher.dispatch(body["action_id"],
                                             body.get("values", {}),
                                             body.get("request_id",
                                                      f"get:{msg_id}:{revision}"))
            self.acked.append((msg_id, revision))
            self.cursor += 1
            return protocol.mk_result(
                body.get("request_id", msg_id), saved["text"],
                msg_id=f"res-{msg_id}-{revision}")
        # plain text: generate last-good fragment once, reuse after (V05)
        verdict = self.rev.submit(msg_id, revision, major)
        if verdict in ("stale", "duplicate-inert"):
            return protocol.mk_result(f"get:{msg_id}:{revision}",
                                      f"{verdict}:{msg_id}:{revision}",
                                      msg_id=f"res-{msg_id}-{revision}-dup")
        if msg_id not in self.last_good:
            self.last_good[msg_id] = {
                "fragment_id": msg_id, "revision": revision,
                "fragment_version": {"major": 1, "minor": 0}}
            self.regen_count += 1
        self.acked.append((msg_id, revision))
        self.cursor += 1
        env_extra = f"{msg_id}:{revision}"
        res = protocol.mk_result(f"get:{msg_id}:{revision}",
                                 f"acked:{env_extra}",
                                 msg_id=f"res-{msg_id}-{revision}")
        res["cursor"] = str(self.cursor)
        return res
