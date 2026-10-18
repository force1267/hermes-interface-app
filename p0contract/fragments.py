"""F01/F02 fragment + allowlisted component validation."""
import hashlib
import json

from .wire import WireError, validate_version


class FragmentError(ValueError):
    pass


ALLOWED_COMPONENTS = {
    "Stack": {"props": {"direction": ("vertical", "horizontal")}, "children": "nodes"},
    "Text": {"props": {"text": "string"}, "children": "empty"},
    "List": {"props": {"items": "string[]"}, "children": "empty"},
    "Button": {"props": {"label": "string", "action_id": "string",
                          "intent": ("assigned", "generative")}, "children": "empty"},
    "Field": {"props": {"name": "string", "label": "string",
                         "input": ("text", "number", "boolean"),
                         "value": "matching",
                         "placeholder": "optional-string"}, "children": "empty"},
    "Media": {"props": {"asset_id": "string", "alt": "string",
                         "media_type": ("image", "audio", "video", "file")}, "children": "empty"},
}

# Rejected wherever a known executable field/component is supplied (F02).
FORBIDDEN_EXACT = {"html", "code", "script", "style", "src", "href"}


def _forbidden_key(key: str) -> bool:
    k = key.lower()
    if k in FORBIDDEN_EXACT:
        return True
    if k.startswith("on"):
        return True
    return False


def _check_media_asset(asset_id: str):
    if not isinstance(asset_id, str) or not asset_id:
        raise FragmentError("Media.asset_id-must-be-nonempty")
    low = asset_id.lower()
    if "://" in asset_id or low.startswith("data:") or low.startswith("javascript:"):
        raise FragmentError("Media.external-url-denied")
    if asset_id.startswith("http") or asset_id.startswith("/"):
        # opaque backend asset IDs only; never paths/URLs
        raise FragmentError("Media.external-url-denied")


def clean_node(node):
    """Validate one node; return cleaned node with ONLY allowlisted props.

    Raises FragmentError on unknown component / bad props / forbidden keys.
    Unknown innocuous props are stripped (not passed to renderer).
    """
    if not isinstance(node, dict):
        raise FragmentError("node-must-be-object")
    for f in ("component", "props", "children"):
        if f not in node:
            raise FragmentError(f"node-missing: {f}")
    comp = node["component"]
    if comp not in ALLOWED_COMPONENTS:
        raise FragmentError(f"unknown-component: {comp}")
    props = node["props"]
    if not isinstance(props, dict):
        raise FragmentError("props-must-be-object")
    children = node["children"]
    if not isinstance(children, list):
        raise FragmentError("children-must-be-array")
    spec = ALLOWED_COMPONENTS[comp]
    # executable/code-bearing keys rejected anywhere, even as unknown props
    for k in props.keys():
        if _forbidden_key(k):
            raise FragmentError(f"raw-code-prop-denied: {k}")
    cleaned = {}
    if comp == "Stack":
        if props.get("direction") not in ("vertical", "horizontal"):
            raise FragmentError("Stack.direction-invalid")
        cleaned["direction"] = props["direction"]
        for ch in children:
            clean_node(ch)  # validate recursively
    elif comp == "Text":
        if not isinstance(props.get("text"), str):
            raise FragmentError("Text.text-must-be-string")
        cleaned["text"] = props["text"]
        if children:
            raise FragmentError("Text-children-must-be-empty")
    elif comp == "List":
        items = props.get("items")
        if not isinstance(items, list) or any(not isinstance(i, str) for i in items):
            raise FragmentError("List.items-must-be-string-array")
        cleaned["items"] = list(items)
        if children:
            raise FragmentError("List-children-must-be-empty")
    elif comp == "Button":
        if not isinstance(props.get("label"), str):
            raise FragmentError("Button.label-must-be-string")
        if not isinstance(props.get("action_id"), str) or not props["action_id"]:
            raise FragmentError("Button.action_id-must-be-nonempty")
        if props.get("intent") not in ("assigned", "generative"):
            raise FragmentError("Button.intent-invalid")
        cleaned.update({k: props[k] for k in ("label", "action_id", "intent")})
        if children:
            raise FragmentError("Button-children-must-be-empty")
    elif comp == "Field":
        for k in ("name", "label"):
            if not isinstance(props.get(k), str) or not props[k]:
                raise FragmentError(f"Field.{k}-must-be-nonempty")
        if props.get("input") not in ("text", "number", "boolean"):
            raise FragmentError("Field.input-invalid")
        val = props.get("value", None)
        if "value" not in props:
            raise FragmentError("Field.value-required")
        want = props["input"]
        ok = (isinstance(val, str) if want == "text"
              else (isinstance(val, (int, float)) and not isinstance(val, bool)) if want == "number"
              else isinstance(val, bool))
        if not ok:
            raise FragmentError("Field.value-type-mismatch")
        cleaned.update({k: props[k] for k in ("name", "label", "input", "value")})
        if "placeholder" in props:
            if not isinstance(props["placeholder"], str):
                raise FragmentError("Field.placeholder-must-be-string")
            cleaned["placeholder"] = props["placeholder"]
        if children:
            raise FragmentError("Field-children-must-be-empty")
    elif comp == "Media":
        if not isinstance(props.get("alt"), str):
            raise FragmentError("Media.alt-must-be-string")
        if props.get("media_type") not in ("image", "audio", "video", "file"):
            raise FragmentError("Media.media_type-invalid")
        _check_media_asset(props.get("asset_id"))
        cleaned.update({k: props[k] for k in ("asset_id", "alt", "media_type")})
        if children:
            raise FragmentError("Media-children-must-be-empty")
    # unknown innocuous fields are ignored (stripped): cleaned holds only allowlist.
    return {"component": comp, "props": cleaned, "children": [
        clean_node(c) for c in children] if comp == "Stack" else []}


def fragment_identity_hash(frag: dict) -> str:
    canon = json.dumps({
        "fragment_id": frag["fragment_id"],
        "version": frag["version"],
        "kind": frag["kind"],
        "mode": frag["mode"],
        "origin": frag["origin"],
        "tree": frag["tree"],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def validate_fragment(frag, envelope_fallback_text=None):
    if not isinstance(frag, dict):
        raise FragmentError("fragment-must-be-object")
    for f in ("fragment_id", "version", "kind", "mode", "origin",
              "fallback_text", "tree"):
        if f not in frag:
            raise FragmentError(f"fragment-missing: {f}")
    if not isinstance(frag["fragment_id"], str) or not frag["fragment_id"]:
        raise FragmentError("fragment_id-must-be-nonempty")
    validate_version(frag["version"], "fragment.version")
    if frag["mode"] not in ("standard", "expanded"):
        raise FragmentError("mode-invalid")
    if frag["origin"] not in ("generated", "cached", "builtin"):
        raise FragmentError("origin-invalid")
    if not isinstance(frag["fallback_text"], str) or not frag["fallback_text"]:
        raise FragmentError("fallback_text-must-be-nonempty")
    if envelope_fallback_text is not None and envelope_fallback_text != frag["fallback_text"]:
        raise FragmentError("envelope-fallback-must-equal-fallback_text")
    clean_node(frag["tree"])
    return True


class FragmentStore:
    """Enforces immutable identity (fragment_id, version, hash)."""

    def __init__(self):
        self._hash = {}  # (fragment_id, major, minor) -> hash

    def submit(self, frag):
        validate_fragment(frag)
        key = (frag["fragment_id"], frag["version"]["major"], frag["version"]["minor"])
        h = fragment_identity_hash(frag)
        if key in self._hash and self._hash[key] != h:
            raise FragmentError("changed-bytes-require-new-version")
        self._hash[key] = h
        return h
