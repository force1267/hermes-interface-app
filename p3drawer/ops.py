"""P3 drawer operation boundary (named ops shared with the shell).

Every shell action routes through handle_op(): the page calls it with an
op dict and renders only what the returned backend result confirms. The
JS layer in p2rich/sandbox.py implements the same op names against its
durable client store, so browser behavior and backend behavior stay in
lockstep. Nothing here claims success before the Drawer confirms it:
delete/repair without confirm return confirm-required and mutate nothing.
"""
from .drawer import DrawerError


DRAWER_OPS = ("add", "rename", "pin", "unpin", "delete",
              "repair", "repair_offer", "resolve", "list")


def handle_op(drawer, op):
    """Route one shell action to the Drawer; return its actual result.

    op is a dict with an "op" name. Raises DrawerError on unknown ops or
    unknown pages; otherwise returns the Drawer result verbatim so the
    adapter/endpoint layer propagates real backend outcomes (ok,
    confirm-required, chat-text-retry, unavailable, rejected) instead of
    inventing success text.
    """
    name = (op or {}).get("op")
    if name == "add":
        return drawer.create_page(
            (op.get("name") or "Untitled"),
            op.get("tree"), kind=op.get("kind", "text") or "text",
            fallback_text=op.get("fallback_text"))
    if name == "rename":
        return drawer.rename(op["page_id"], op.get("new_name", ""))
    if name == "pin":
        return drawer.pin(op["page_id"])
    if name == "unpin":
        return drawer.unpin(op["page_id"])
    if name == "delete":
        return drawer.delete(op["page_id"],
                             confirm=bool(op.get("confirm", False)))
    if name == "repair":
        return drawer.repair(op["page_id"], new_tree=op.get("new_tree"),
                             confirm=bool(op.get("confirm", False)))
    if name == "repair_offer":
        return drawer.repair_offer(op["page_id"])
    if name == "resolve":
        return drawer.resolve_page(op["page_id"])
    if name == "list":
        return drawer.list_drawer()
    raise DrawerError(f"unknown-op: {name}")
