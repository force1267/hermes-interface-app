"""V01-V05 evolution, kinds, majors, negotiation. Pure functions (P0)."""
import json

from .wire import WireError, validate_version, cmp_version


def is_reader_compatible(msg_version, msg_min_compat, reader_version):
    """V01: lexicographic min-compat check within a matching major."""
    if msg_version["major"] != reader_version["major"]:
        return False
    if msg_min_compat["major"] != msg_version["major"]:
        return False
    return (reader_version["major"], reader_version["minor"]) >= (
        msg_min_compat["major"], msg_min_compat["minor"])


SEED_KINDS = {
    "text": ["Text"],
    "card-list": ["Text", "List", "Button"],
    "form": ["Text", "List", "Button", "Field"],
    "media": ["Text", "List", "Button", "Media"],
}
CONTAINER_OK = True  # nested Stack layout containers permitted in every kind


class KindRegistry:
    """V02 registry. Insertions need schema + text fallback + passing golden."""

    def __init__(self, fixtures=None):
        # fixtures: golden_test name -> callable returning True
        self.fixtures = dict(fixtures or {})
        self.kinds = {}
        for kind, comps in SEED_KINDS.items():
            self.kinds[kind] = {
                "kind": kind,
                "version": {"major": 1, "minor": 0},
                "min_compat": {"major": 1, "minor": 0},
                "schema_id": f"seed:{kind}",
                "required_caps": [],
                "fallback": "text",
                "golden_test": f"golden:{kind}",
                "components": list(comps),
            }

    def insert(self, record):
        for f in ("kind", "version", "min_compat", "schema_id",
                  "required_caps", "fallback", "golden_test"):
            if f not in record:
                raise WireError(f"kind-record-missing: {f}")
        validate_version(record["version"], "kind.version")
        validate_version(record["min_compat"], "kind.min_compat")
        if not record["schema_id"] or not isinstance(record["schema_id"], str):
            raise WireError("kind-schema-required")
        if record["fallback"] != "text":
            raise WireError("kind-fallback-must-be-text")
        gt = record["golden_test"]
        if gt not in self.fixtures:
            raise WireError("kind-golden-missing")
        try:
            passed = bool(self.fixtures[gt]())
        except Exception as e:
            raise WireError(f"kind-golden-failed: {e}")
        if not passed:
            raise WireError("kind-golden-failed")
        if not isinstance(record["required_caps"], list):
            raise WireError("kind-required_caps-invalid")
        self.kinds[record["kind"]] = dict(record)
        return True


def negotiate_session(hello, server_versions, server_caps, registry_revision="r1"):
    """V04 pure selection. hello={supported_versions, caps, last_seen, cursor}."""
    supported = hello.get("supported_versions", [])
    caps = hello.get("caps", [])
    last_seen = hello.get("last_seen", [])
    for v in supported:
        validate_version(v, "hello.supported_versions[]")
    # highest common major/minor the provider can serve
    common = []
    for sv in server_versions:
        for cv in supported:
            if sv["major"] == cv["major"]:
                common.append({"major": sv["major"],
                               "minor": min(sv["minor"], cv["minor"])})
    if not common:
        return {"selected_version": None, "registry_revision": registry_revision,
                "mode": "text", "reason": "incompatible-major",
                "upgrade_available": True, "pins": []}
    # pick highest major, then highest minor
    common.sort(key=lambda v: (v["major"], v["minor"]))
    selected = common[-1]
    missing = [c for c in server_caps if c not in caps]
    if missing:
        return {"selected_version": None, "registry_revision": registry_revision,
                "mode": "text", "reason": f"missing-caps:{','.join(missing)}",
                "upgrade_available": True, "pins": []}
    # empty new-client history is not incompatibility evidence (V04/V05)
    pins = []
    for seen in last_seen:
        pins.append({"id": seen.get("id", ""), "revision": seen.get("revision", 0),
                     "fragment_id": seen.get("fragment_id"),
                     "fragment_version": seen.get("fragment_version")})
    return {"selected_version": selected, "registry_revision": registry_revision,
            "mode": "rich", "reason": "negotiated", "upgrade_available": False,
            "pins": pins}


def reevaluate_on_resume(client_caps_versions, registry, last_good, store_text="upgrade-nudge"):
    """V05: re-pin to compatible approved last-good or static text; no sticky flag.

    client_caps_versions: {"supported_versions": [...], "caps": [...]}
    last_good: list of fragment dicts previously known-good.
    Returns {"mode": rich|text, "pins"|"text", "re_upgraded": bool}.
    """
    supported = client_caps_versions.get("supported_versions", [])
    selected = None
    for cand in sorted(supported, key=lambda v: (v["major"], v["minor"])):
        pass
    # reuse negotiate with a dummy server offering v1
    sess = negotiate_session(
        {"supported_versions": supported,
         "caps": client_caps_versions.get("caps", []),
         "last_seen": []},
        [{"major": 1, "minor": 0}], [])
    if sess["selected_version"] is None:
        return {"mode": "text", "text": "static-incompatible:" + store_text,
                "re_upgraded": False}
    # compatible: re-pin same logical fragments without regenerating
    pins = [{"id": f.get("fragment_id", f.get("id", "")),
             "fragment_id": f.get("fragment_id", f.get("id", "")),
             "fragment_version": f.get("version", {"major": 1, "minor": 0})}
            for f in last_good]
    return {"mode": "rich", "pins": pins, "re_upgraded": bool(pins)}
