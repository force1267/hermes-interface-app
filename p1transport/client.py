"""P1 client: handshake, bubble list, outbox, resume/re-pin (V04/V05).

Bubble dedup key is (id, revision, representation-major) per E02/E05:
a replayed ack never doubles a bubble, a lost one stays in the outbox
until the provider acks it. Per-device request IDs + backend dedup
give E04 exactly-once effects across reconnects.
"""
import json
import socket

from p0contract import messages, wire

from . import protocol


class ConnectionLost(ConnectionError):
    pass


class Client:
    def __init__(self, device_id, supported_versions=None, caps=(),
                 registry_revision=None, budget_revision=None):
        self.device_id = device_id
        self.supported_versions = [dict(v) for v in
                                   (supported_versions
                                    or [dict(protocol.V10)])]
        self.caps = list(caps)
        self.registry_revision = registry_revision
        self.budget_revision = budget_revision
        self.bubbles = []   # [{id, revision, major, text}] in ack order
        self._seen = set()  # (id, revision, major) dedup set
        self.outbox = []    # [(envelope, payload_str)] awaiting ack
        self.session = None
        self.cursor = None
        self._req_seq = 0
        self._sock = None
        self._rfile = None

    # -- connection --
    def connect(self, host, port, resume=False):
        self._sock = socket.create_connection((host, port), timeout=5)
        self._sock.settimeout(5)
        self._rfile = self._sock.makefile("r", encoding="utf-8")
        last_seen = [{"id": b["id"], "revision": b["revision"],
                      "fragment_id": None, "fragment_version": None}
                     for b in self.bubbles]
        if resume:
            env = protocol.mk_resume(
                self.device_id, self.supported_versions, self.caps,
                self.registry_revision, self.budget_revision,
                last_seen=last_seen, cursor=self.cursor)
        else:
            env = protocol.mk_hello(
                self.device_id, self.supported_versions, self.caps,
                self.registry_revision, self.budget_revision)
        sess = self._roundtrip(env, expect="session")
        res = messages.validate_message(sess)
        if res["status"] != "ok":
            raise wire.WireError("session-invalid")
        self.session = res["body"]
        return self.session

    def reconnect(self, host, port):
        """Resume + replay the outbox in order. Returns the session body."""
        self.close()
        sess = self.connect(host, port, resume=True)
        for entry in list(self.outbox):
            if len(entry) == 3:
                env, payload_str, saved_text = entry
            else:
                env, payload_str = entry
                saved_text = ""
            if not saved_text:
                saved_text = self._infer_bubble_text(payload_str)
            try:
                self._send_and_ack(env, payload_str,
                                   bubble_text=saved_text)
            except ConnectionLost:
                break
        return sess

    def close(self):
        for h in (self._rfile, self._sock):
            try:
                if h is not None:
                    h.close()
            except OSError:
                pass
        self._sock = self._rfile = None

    def _infer_bubble_text(self, payload_str, fallback=""):
        try:
            import json as _json
            body = _json.loads(payload_str)
        except Exception:
            return fallback
        if isinstance(body, dict):
            if "action_id" in body:
                try:
                    return "action:%s" % body["action_id"]
                except Exception:
                    return fallback
            t = body.get("text")
            if isinstance(t, str):
                return t
        return fallback
    # -- sending --
    def _next_req(self):
        self._req_seq += 1
        return f"{self.device_id}:{self._req_seq}"

    def send_text(self, text, msg_id=None, revision=0):
        msg_id = msg_id or self._next_req().replace(":", "-")
        payload_str = json.dumps({"text": text}, sort_keys=True)
        env = protocol.mk_text_envelope(
            msg_id, revision, payload_str.encode("utf-8"),
            caps=self.caps, fallback=text[:80] or "text")
        self._send_and_ack(env, payload_str, bubble_text=text)
        return msg_id

    def send_action(self, action_id, values, msg_id=None, revision=0):
        """Returns the provider result text (saved result on replay)."""
        request_id = self._next_req()
        msg_id = msg_id or request_id.replace(":", "-")
        payload_str = json.dumps({"action_id": action_id,
                                  "request_id": request_id,
                                  "context_id": self.device_id,
                                  "values": dict(values)}, sort_keys=True)
        env = protocol.mk_action_envelope(
            msg_id, revision, payload_str.encode("utf-8"), caps=self.caps)
        self._send_and_ack(env, payload_str, bubble_text=f"action:{action_id}")
        # result text of the last ack
        return self._last_result

    def _send_and_ack(self, env, payload_str, bubble_text=""):
        if not bubble_text:
            bubble_text = self._infer_bubble_text(payload_str)
        entry = (env, payload_str, bubble_text)
        if not any(e[0]["id"] == env["id"]
                   and e[0]["revision"] == env["revision"]
                   for e in self.outbox):
            self.outbox.append(entry)
        try:
            reply = self._roundtrip(env, expect="payload.get")
        except (OSError, ValueError):
            raise ConnectionLost("send failed; kept in outbox")
        res = messages.validate_message(reply)
        if res["status"] != "ok":
            raise wire.WireError("payload.get-invalid")
        data = protocol.mk_payload_data(
            res["body"]["ref"], payload_str,
            res["body"]["request_id"], caps=self.caps)
        try:
            final = self._roundtrip(data, expect="result")
        except (OSError, ValueError):
            raise ConnectionLost("payload send failed; kept in outbox")
        res2 = messages.validate_message(final)
        if res2["status"] != "ok":
            raise wire.WireError("result-invalid")
        self._last_result = res2["body"]["text"]
        if final.get("cursor") is not None:
            self.cursor = final["cursor"]
        # acked: drop from outbox, add bubble once (E02/E05 dedup)
        self.outbox = [e for e in self.outbox if e[0]["id"] != env["id"]
                       or e[0]["revision"] != env["revision"]]
        self._add_bubble(env["id"], env["revision"],
                         env["version"]["major"], bubble_text)

    def _add_bubble(self, msg_id, revision, major, text):
        key = (msg_id, revision, major)
        if key in self._seen:
            return False
        self._seen.add(key)
        self.bubbles.append({"id": msg_id, "revision": revision,
                             "major": major, "text": text})
        return True

    def bubble_ids(self):
        return [(b["id"], b["revision"]) for b in self.bubbles]

    # -- wire --
    def _roundtrip(self, env, expect):
        if self._sock is None:
            raise ConnectionLost("not connected")
        try:
            self._sock.sendall(protocol.encode_frame(env))
            line = self._rfile.readline()
        except (OSError, ValueError) as e:
            raise ConnectionLost(str(e))
        if not line:
            raise ConnectionLost("peer closed mid-conversation")
        try:
            reply = protocol.decode_frame(line.encode("utf-8"))
        except wire.WireError as e:
            raise ValueError(f"bad-frame: {e}")
        if reply.get("type") != expect:
            raise ValueError(f"expected {expect}, got {reply.get('type')}")
        return reply
