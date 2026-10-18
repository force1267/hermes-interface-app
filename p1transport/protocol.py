"""P1 transport framing + handshake helpers (V04/V05, E03/E04/E05).

Every wire unit is one UTF-8 JSON envelope per line, validated by
p0contract.wire.parse_wire (duplicate keys, non-JSON numbers rejected).
Handshake (hello/resume/session) and payload transfer (payload.get /
payload.data) use the E03 inline-bootstrap shapes, so no URL fetch and
no out-of-band channel exist. Chat ack is a result envelope.
"""
import hashlib
import json

from p0contract import evolution, messages, wire

V10 = {"major": 1, "minor": 0}

_client_seq = [0]


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _bootstrap_envelope(mtype, body, caps=(), fallback="handshake",
                        msg_id=None, revision=0):
    """Build an E03 bootstrap-string envelope (hello/resume/session/result/error)."""
    raw = json.dumps(body, sort_keys=True).encode("utf-8")
    _client_seq[0] += 1
    env = {"type": mtype, "version": dict(V10), "min-compat": dict(V10),
           "id": msg_id or f"{mtype}-{_client_seq[0]}", "revision": revision,
           "payload-ref": {"id": f"boot:{mtype}:{_client_seq[0]}",
                           "version": dict(V10), "sha256": _sha(raw)},
           "caps": list(caps), "fallback": {"text": fallback},
           "bootstrap": raw.decode("utf-8")}
    # self-check: must validate locally before it ever hits the wire
    messages.validate_message(env)
    return env


def mk_hello(client_id, supported_versions, caps=(), registry_revision=None,
             budget_revision=None):
    body = {"client_id": client_id,
            "supported_versions": [dict(v) for v in supported_versions],
            "caps": list(caps), "registry_revision": registry_revision,
            "budget_revision": budget_revision}
    return _bootstrap_envelope("hello", body, caps=caps,
                               msg_id=f"hello-{client_id}")


def mk_resume(client_id, supported_versions, caps=(), registry_revision=None,
              budget_revision=None, last_seen=(), cursor=None):
    body = {"client_id": client_id,
            "supported_versions": [dict(v) for v in supported_versions],
            "caps": list(caps), "registry_revision": registry_revision,
            "budget_revision": budget_revision,
            "last_seen": [dict(e) for e in last_seen], "cursor": cursor}
    return _bootstrap_envelope("resume", body, caps=caps,
                               msg_id=f"resume-{client_id}")


def mk_session(session_body, caps=(), msg_id=None):
    return _bootstrap_envelope("session", session_body, caps=caps,
                               fallback="session", msg_id=msg_id)


def mk_result(request_id, text, caps=(), msg_id=None):
    return _bootstrap_envelope("result", {"request_id": request_id,
                                          "status": "ok", "text": text},
                               caps=caps, fallback=text[:80] or "result",
                               msg_id=msg_id)


def mk_text_envelope(msg_id, revision, payload_bytes, caps=(), fallback="text"):
    """E02 text envelope; payload travels via payload.get/data, not inline."""
    ref = {"id": f"payload:{msg_id}:{revision}",
           "version": dict(V10), "sha256": _sha(payload_bytes)}
    env = {"type": "text", "version": dict(V10), "min-compat": dict(V10),
           "id": msg_id, "revision": revision, "payload-ref": ref,
           "caps": list(caps), "fallback": {"text": fallback}}
    wire.validate_envelope(env)
    return env


def mk_action_envelope(msg_id, revision, payload_bytes, caps=()):
    env = mk_text_envelope(msg_id, revision, payload_bytes, caps=caps,
                           fallback="action")
    env["type"] = "action"
    wire.validate_envelope(env)
    return env


def mk_payload_get(ref, request_id, caps=()):
    body = {"ref": {"id": ref["id"], "version": dict(ref["version"]),
                    "sha256": ref["sha256"]}, "request_id": request_id}
    raw = json.dumps(body, sort_keys=True).encode("utf-8")
    env = {"type": "payload.get", "version": dict(V10),
           "min-compat": dict(V10), "id": f"pg-{request_id}",
           "revision": 0,
           "payload-ref": {"id": f"boot:payload.get:{request_id}",
                           "version": dict(V10), "sha256": _sha(raw)},
           "caps": list(caps), "fallback": {"text": "payload request"},
           "bootstrap": raw.decode("utf-8")}
    messages.validate_message(env)
    return env


def mk_payload_data(ref, payload_str, request_id, caps=()):
    raw = payload_str.encode("utf-8")
    if _sha(raw) != ref["sha256"]:
        raise wire.WireError("payload-data-hash-mismatch")
    env = {"type": "payload.data", "version": dict(V10),
           "min-compat": dict(V10), "id": f"pd-{request_id}",
           "revision": 0,
           "payload-ref": {"id": ref["id"], "version": dict(ref["version"]),
                           "sha256": ref["sha256"]},
           "caps": list(caps), "fallback": {"text": "payload bytes"},
           "data": payload_str, "request_id": request_id}
    messages.validate_message(env)
    return env


def negotiate_for_body(body, server_versions, server_caps,
                       registry_revision):
    """V04 selection from a hello/resume body. Returns session body dict."""
    hello = {"supported_versions": body.get("supported_versions", []),
             "caps": body.get("caps", []),
             "last_seen": body.get("last_seen", [])}
    sess = evolution.negotiate_session(hello, server_versions, server_caps,
                                       registry_revision)
    # upgrade_available: provider serves a newer minor in the chosen major
    if sess["selected_version"] is not None:
        sel = sess["selected_version"]
        newer = [v for v in server_versions
                 if v["major"] == sel["major"] and v["minor"] > sel["minor"]]
        sess["upgrade_available"] = bool(newer)
    return sess


def encode_frame(env):
    return (json.dumps(env, sort_keys=True) + "\n").encode("utf-8")


def decode_frame(line: bytes):
    return wire.parse_wire(line)
