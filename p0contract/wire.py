"""E01/E02 wire + envelope validation. No policy numbers live here."""
import hashlib
import json
import re

SHA_RE = re.compile(r"^[0-9a-f]{64}$")

MESSAGE_TYPES = {
    "hello", "resume", "session", "text", "fragment", "action",
    "result", "error", "payload.get", "payload.data",
}


class WireError(ValueError):
    pass


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def parse_wire(raw: bytes):
    """Parse UTF-8 JSON object, rejecting duplicate keys and non-JSON numbers."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise WireError(f"not-utf8: {e}")
    def _no_const(v):
        raise WireError(f"non-json-number: {v}")
    def _pairs(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise WireError(f"duplicate-key: {k}")
            obj[k] = v
        return obj
    try:
        val = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_const)
    except WireError:
        raise
    except json.JSONDecodeError as e:
        raise WireError(f"bad-json: {e}")
    if not isinstance(val, dict):
        raise WireError("wire-unit-must-be-object")
    return val


def validate_version(v, field="version"):
    if not isinstance(v, dict):
        raise WireError(f"{field}-must-be-object")
    if set(v.keys()) != {"major", "minor"}:
        # allow unknown ordinary fields per E01/V01? version objects are strict:
        # unknown fields inside version are ignored but major/minor required.
        if "major" not in v or "minor" not in v:
            raise WireError(f"{field}-missing-major-minor")
    major, minor = v.get("major"), v.get("minor")
    if not _is_int(major) or major < 1:
        raise WireError(f"{field}.major-must-be-positive-int")
    if not _is_int(minor) or minor < 0:
        raise WireError(f"{field}.minor-must-be-nonneg-int")
    return {"major": major, "minor": minor}


def cmp_version(a, b):
    return (a["major"], a["minor"]).__lt__((b["major"], b["minor"])) and -1 or (
        (a["major"], a["minor"]) == (b["major"], b["minor"]) and 0 or 1)


def check_min_compat(version, min_compat):
    """min-compat must not be greater than version (lexicographic)."""
    if (min_compat["major"], min_compat["minor"]) > (version["major"], version["minor"]):
        raise WireError("min-compat-greater-than-version")


def _nonempty_str(v, field):
    if not isinstance(v, str) or not v:
        raise WireError(f"{field}-must-be-nonempty-string")


def validate_envelope(env):
    """Validate E02 envelope. Unknown ordinary fields ignored. Returns normalized view."""
    if not isinstance(env, dict):
        raise WireError("envelope-must-be-object")
    required = ["type", "version", "min-compat", "id", "revision",
                "payload-ref", "caps", "fallback"]
    for f in required:
        if f not in env:
            raise WireError(f"missing-field: {f}")
    mtype = env["type"]
    _nonempty_str(mtype, "type")
    version = validate_version(env["version"], "version")
    min_compat = validate_version(env["min-compat"], "min-compat")
    check_min_compat(version, min_compat)
    _nonempty_str(env["id"], "id")
    if env["id"].startswith("/") or "\x00" in env["id"]:
        raise WireError("id-must-be-opaque")
    if not _is_int(env["revision"]) or env["revision"] < 0:
        raise WireError("revision-must-be-nonneg-int")
    pref = env["payload-ref"]
    if not isinstance(pref, dict):
        raise WireError("payload-ref-must-be-object")
    for f in ("id", "version", "sha256"):
        if f not in pref:
            raise WireError(f"payload-ref-missing: {f}")
    _nonempty_str(pref["id"], "payload-ref.id")
    pver = validate_version(pref["version"], "payload-ref.version")
    sha = pref["sha256"]
    if not isinstance(sha, str) or not SHA_RE.match(sha):
        raise WireError("payload-ref.sha256-must-be-lowercase-64hex")
    caps = env["caps"]
    if not isinstance(caps, list) or any(not isinstance(c, str) for c in caps):
        raise WireError("caps-must-be-string-array")
    if len(set(caps)) != len(caps):
        raise WireError("caps-must-be-unique")
    fb = env["fallback"]
    if not isinstance(fb, dict) or "text" not in fb:
        raise WireError("fallback-must-have-text")
    if not isinstance(fb["text"], str) or not fb["text"]:
        raise WireError("fallback.text-must-be-nonempty")
    if env["revision"] is None:
        raise WireError("revision-null-forbidden")
    for f in ("type", "id"):
        if env[f] is None:
            raise WireError(f"{f}-null-forbidden")
    return {
        "type": mtype, "version": version, "min-compat": min_compat,
        "id": env["id"], "revision": env["revision"],
        "payload_ref": {"id": pref["id"], "version": pver, "sha256": sha},
        "caps": list(caps), "fallback": {"text": fb["text"]},
    }


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_payload_ref(ref, payload_bytes: bytes):
    """Receiver MUST verify hash and payload version before use."""
    if sha256_hex(payload_bytes) != ref["sha256"]:
        raise WireError("hash-mismatch")
    return True


def resolve_payload(ref, store):
    """Resolve only through provider store. Never a URL.

    store: dict[(id, major, minor)] -> bytes. Rejects refs carrying a url.
    """
    if not isinstance(ref, dict):
        raise WireError("ref-must-be-object")
    for k in ref.keys():
        if k.lower() == "url":
            raise WireError("url-dereference-denied")
    # also reject url-like id values
    rid = ref.get("id", "")
    if isinstance(rid, str) and ("://" in rid or rid.startswith("data:")):
        raise WireError("url-dereference-denied")
    ver = ref.get("version")
    key = (ref.get("id"), ver.get("major"), ver.get("minor")) if isinstance(ver, dict) else None
    if key not in store:
        raise WireError("payload-missing")
    payload_bytes = store[key]
    verify_payload_ref({"sha256": ref.get("sha256", "")}, payload_bytes)
    return payload_bytes
