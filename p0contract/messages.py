"""E03-E05 messages: bootstrap, actions, revisions, dual-major, fallback."""
import hashlib
import json

from .wire import WireError, validate_envelope, verify_payload_ref

MESSAGE_TYPES = {
    "hello", "resume", "session", "text", "fragment", "action",
    "result", "error", "payload.get", "payload.data",
}
BOOTSTRAP_STRING_TYPES = {"hello", "resume", "session", "result", "error"}


def _payload_bytes_of_inline(s):
    if not isinstance(s, str):
        raise WireError("bootstrap-must-be-json-string")
    return s.encode("utf-8")


def validate_message(env, store=None):
    """Full per-type validation. store maps (id,major,minor)->bytes for non-inline."""
    norm = validate_envelope(env)
    mtype = norm["type"]
    if mtype not in MESSAGE_TYPES:
        return {"status": "fallback", "reason": f"unsupported-type: {mtype}",
                "text": norm["fallback"]["text"]}
    store = store or {}
    ref = norm["payload_ref"]
    if mtype in BOOTSTRAP_STRING_TYPES:
        if "bootstrap" not in env:
            raise WireError(f"{mtype}-missing-bootstrap")
        raw = _payload_bytes_of_inline(env["bootstrap"])
        verify_payload_ref(ref, raw)
        # payload.get bootstrap has its own schema; others just need valid JSON
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise WireError(f"{mtype}-bootstrap-bad-json: {e}")
        if not isinstance(body, dict):
            raise WireError(f"{mtype}-bootstrap-must-be-object")
        return {"status": "ok", "body": body, "norm": norm}
    if mtype == "payload.get":
        if "bootstrap" not in env:
            raise WireError("payload.get-missing-bootstrap")
        raw = _payload_bytes_of_inline(env["bootstrap"])
        verify_payload_ref(ref, raw)
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise WireError(f"payload.get-bootstrap-bad-json: {e}")
        if not isinstance(body, dict) or "ref" not in body or "request_id" not in body:
            raise WireError("payload.get-bootstrap-shape")
        if not isinstance(body["request_id"], str) or not body["request_id"]:
            raise WireError("payload.get-request_id-invalid")
        return {"status": "ok", "body": body, "norm": norm}
    if mtype == "payload.data":
        if "data" not in env or "request_id" not in env:
            raise WireError("payload.data-missing-data-or-request_id")
        if not isinstance(env["request_id"], str) or not env["request_id"]:
            raise WireError("payload.data-request_id-invalid")
        raw = _payload_bytes_of_inline(env["data"])
        verify_payload_ref(ref, raw)
        return {"status": "ok", "body": {"data": env["data"]}, "norm": norm}
    # text/fragment/action: resolve from validated local cache or payload.get
    key = (ref["id"], ref["version"]["major"], ref["version"]["minor"])
    if key not in store:
        return {"status": "need-payload", "norm": norm}
    verify_payload_ref(ref, store[key])
    try:
        body = json.loads(store[key].decode("utf-8"))
    except Exception as e:
        raise WireError(f"payload-bad-json: {e}")
    return {"status": "ok", "body": body, "norm": norm}


class ActionDispatcher:
    """Authenticated backend dispatcher owns side effects + request_id dedup."""

    def __init__(self):
        self.schemas = {}  # action_id -> {field: type-name}
        self.results = {}  # request_id -> result
        self.effects = 0

    def register(self, action_id, schema):
        self.schemas[action_id] = dict(schema)

    def dispatch(self, action_id, values, request_id):
        if action_id not in self.schemas:
            raise WireError(f"unknown-action: {action_id}")
        if not isinstance(request_id, str) or not request_id:
            raise WireError("request_id-must-be-nonempty")
        if request_id in self.results:
            return self.results[request_id]
        if not isinstance(values, dict):
            raise WireError("values-must-be-object")
        schema = self.schemas[action_id]
        for k, t in schema.items():
            if k not in values:
                raise WireError(f"action-missing-field: {k}")
            v = values[k]
            if t == "string" and not isinstance(v, str):
                raise WireError(f"action-field-type: {k}")
            elif t == "number" and not (isinstance(v, (int, float)) and not isinstance(v, bool)):
                raise WireError(f"action-field-type: {k}")
            elif t == "boolean" and not isinstance(v, bool):
                raise WireError(f"action-field-type: {k}")
        # inert JSON only: reject nested executable-looking keys
        for k in values.keys():
            kl = k.lower()
            if kl in ("html", "code", "script", "style", "src", "href") or kl.startswith("on"):
                raise WireError(f"action-values-executable-denied: {k}")
        self.effects += 1
        res = {"request_id": request_id, "status": "ok",
               "text": f"did:{action_id}:{request_id}"}
        self.results[request_id] = res
        return res


class RevisionStore:
    """E05 revision + dual-representation dedup. One logical bubble per id."""

    def __init__(self):
        self._state = {}  # id -> {"revision": int, "majors": set}

    def submit(self, msg_id, revision, major):
        cur = self._state.get(msg_id)
        if cur is None:
            self._state[msg_id] = {"revision": revision, "majors": {major}}
            return "accept"
        if revision < cur["revision"]:
            return "stale"
        if revision == cur["revision"] and major in cur["majors"]:
            return "duplicate-inert"
        if revision >= cur["revision"]:
            if revision > cur["revision"]:
                self._state[msg_id] = {"revision": revision, "majors": {major}}
            else:
                cur["majors"].add(major)
            return "accept"
        return "stale"


def fallback_for(text, reason):
    return {"render": "fallback", "text": text, "reason": reason}


def dual_publish(msg_id, revision, reps, supported_majors):
    """Two valid representations sharing id/revision. Choose highest mutual major."""
    ids = {r["id"] for _, r in reps}
    revs = {revision}
    if len(ids) != 1 or list(ids)[0] != msg_id:
        raise WireError("dual-id-mismatch")
    for major, env in reps:
        norm = validate_envelope(env)
        if norm["id"] != msg_id or norm["revision"] != revision:
            raise WireError("dual-id-revision-mismatch")
        if norm["version"]["major"] != major:
            raise WireError("dual-major-mismatch")
    offered = sorted({m for m, _ in reps})
    mutual = [m for m in offered if m in supported_majors]
    if not mutual:
        return {"bubble": msg_id, "selected": None, "status": "incompatible"}
    return {"bubble": msg_id, "selected": max(mutual), "status": "ok"}
