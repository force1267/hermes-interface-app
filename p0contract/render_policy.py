"""F03/F04/F05 render budget, effective mode, sandbox bridge."""
from .wire import WireError

ALLOWED_BRIDGE_OPS = {"render", "action", "resize", "ready"}


def validate_budget(b):
    """Runtime render_budget supplied by managing agent. No coded defaults.

    Returns dict or raises WireError. Caller treats missing/invalid as preview.
    """
    if not isinstance(b, dict):
        raise WireError("budget-must-be-object")
    for f in ("revision", "max_inline_height_px", "max_inline_width_px",
              "max_inline_actions", "allow_inline_focus_capture"):
        if f not in b:
            raise WireError(f"budget-missing: {f}")
    if not isinstance(b["revision"], str) or not b["revision"]:
        raise WireError("budget.revision-invalid")
    for f in ("max_inline_height_px", "max_inline_width_px"):
        v = b[f]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
            raise WireError(f"budget.{f}-must-be-positive")
    a = b["max_inline_actions"]
    if not isinstance(a, int) or isinstance(a, bool) or a < 0:
        raise WireError("budget.max_inline_actions-must-be-nonneg-int")
    if not isinstance(b["allow_inline_focus_capture"], bool):
        raise WireError("budget.allow_inline_focus_capture-must-be-bool")
    return dict(b)


def enforce_budget(measured, budget):
    """Trusted client measurement vs policy. Overflow -> expanded.

    measured={height_px, width_px, actions, focus_capture: bool}.
    Returns (mode, reason).
    """
    try:
        b = validate_budget(budget)
    except WireError as e:
        return ("preview", f"missing-invalid-budget:{e}")
    if measured.get("height_px", 0) > b["max_inline_height_px"]:
        return ("expanded", "height-overflow")
    if measured.get("width_px", 0) > b["max_inline_width_px"]:
        return ("expanded", "width-overflow")
    if measured.get("actions", 0) > b["max_inline_actions"]:
        return ("expanded", "actions-overflow")
    if measured.get("focus_capture") and not b["allow_inline_focus_capture"]:
        return ("expanded", "focus-capture-denied")
    return ("standard", "within-budget")


def effective_mode(provider_mode, overflow=False, user_expand=False, user_collapse=False):
    """F04 truth table. Explicit user expand wins; collapse returns to preview.

    Returns (mode, chrome) where chrome lists required controls.
    """
    if user_expand:
        return ("expanded", ["Close", "Collapse"])
    if user_collapse:
        return ("standard", ["Expand"])
    if provider_mode == "expanded" or overflow:
        return ("expanded", ["Close", "Collapse"])
    return ("standard", ["Expand"])


def collapse_preserve(form_values, request_ids, focus_target):
    """Collapse preserves unsent values/request IDs and restores focus target."""
    return {"form_values": dict(form_values), "request_ids": list(request_ids),
            "focus_target": focus_target}


def validate_bridge(event, channel_token, current_context, registered_actions=()):
    """F05 postMessage bridge validation. Deny on any failure."""
    if not event.get("source_ok"):
        return (False, "bridge-source-denied")
    if event.get("token") != channel_token:
        return (False, "bridge-token-denied")
    op = event.get("op")
    if op not in ALLOWED_BRIDGE_OPS:
        return (False, f"bridge-op-denied:{op}")
    if event.get("context") != current_context:
        return (False, "bridge-context-denied")
    payload = event.get("payload", {})
    if not isinstance(payload, dict):
        return (False, "bridge-shape-denied")
    if op == "action":
        aid = payload.get("action_id")
        if aid not in registered_actions:
            return (False, f"bridge-action-denied:{aid}")
    if op == "resize":
        dims = payload.get("dims")
        budget = event.get("budget")
        if not isinstance(dims, dict) or budget is not None:
            if budget is not None:
                try:
                    b = validate_budget(budget)
                except WireError:
                    return (False, "bridge-resize-budget-invalid")
                if dims.get("height_px", 0) > b["max_inline_height_px"] or \
                   dims.get("width_px", 0) > b["max_inline_width_px"]:
                    return (False, "bridge-resize-clamped")
        if not isinstance(dims, dict):
            return (False, "bridge-shape-denied")
    return (True, "ok")


def sandbox_config():
    return {
        "sandbox": "allow-scripts",
        "csp": {"default-src": "'none'", "connect-src": "'none'",
                "form-action": "'none'", "object-src": "'none'",
                "base-uri": "'none'", "frame-src": "'none'"},
    }


def check_sandbox(config):
    """Deny direct egress: exactly allow-scripts, no other tokens; strict CSP."""
    if config.get("sandbox") != "allow-scripts":
        return (False, "sandbox-permissions-denied")
    csp = config.get("csp", {})
    for k, v in {"default-src": "'none'", "connect-src": "'none'",
                 "form-action": "'none'", "object-src": "'none'",
                 "base-uri": "'none'", "frame-src": "'none'"}.items():
        if csp.get(k) != v:
            return (False, f"csp-denied:{k}")
    return (True, "ok")
