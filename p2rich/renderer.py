"""Deterministic trusted renderer: fragment tree -> HTML through the allowlist.

Only allowlisted components/props reach the DOM. Unknown innocuous props
are stripped by clean_node; forbidden keys (html/code/script/style/src/href/
on*) and unknown components raise FragmentError and the caller degrades per
R04. No per-kind styling: every kind shares the same classes; the wrapper
carries data-kind/data-origin for truthfulness only.

Bounded previews (F03): render_preview_html truncates runaway content and
carries an inline physical size bound so a missing/invalid budget or an
overflow collapse can never emit the full huge body.
"""

import html as _html

from p0contract.fragments import clean_node, FragmentError

# V02 per-kind component subsets (Stack nesting allowed in every kind).
KIND_COMPONENTS = {
    "text": {"Stack", "Text"},
    "card-list": {"Stack", "Text", "List", "Button"},
    "form": {"Stack", "Text", "List", "Button", "Field"},
    "media": {"Stack", "Text", "List", "Button", "Field", "Media"},
}

# F03 preview bounds: physical DOM clamp + content truncation. A preview
# must stay small no matter how huge the fragment body is.
PREVIEW_MAX_TEXT_CHARS = 200
PREVIEW_MAX_LIST_ITEMS = 3
PREVIEW_MAX_STACK_CHILDREN = 8
PREVIEW_STYLE = "max-height:160px;max-width:360px;overflow:hidden"


def esc(s):
    return _html.escape(s, quote=True)


def check_kind(tree, kind):
    """Reject trees using components outside the kind's V02 subset."""
    allowed = KIND_COMPONENTS.get(kind)
    if allowed is None:
        raise FragmentError(f"unknown-kind: {kind}")
    stack = [tree]
    while stack:
        n = stack.pop()
        if n["component"] not in allowed:
            raise FragmentError(
                f"kind-component-denied: {kind}:{n['component']}")
        stack.extend(n.get("children", []))


def apply_form_values(tree, form_values):
    """Return a copy of the tree with unsent form values applied to Fields.

    Fields render the caller's live values (typed but not yet submitted),
    not just the fragment's original value prop. Unknown names ignored.
    """
    if not form_values:
        return tree

    def fix(node):
        comp = node["component"]
        props = dict(node.get("props", {}))
        children = [fix(c) for c in node.get("children", [])]
        if comp == "Field" and props.get("name") in form_values:
            v = form_values[props["name"]]
            want = props.get("input")
            if want == "text" and isinstance(v, str):
                props["value"] = v
            elif want == "number" and isinstance(v, (int, float)) \
                    and not isinstance(v, bool):
                props["value"] = v
            elif want == "boolean" and isinstance(v, bool):
                props["value"] = v
        return {"component": comp, "props": props, "children": children}

    return fix(tree)


def truncate_tree(tree):
    """Return a bounded copy of the tree for static previews."""
    def trunc(node):
        comp = node["component"]
        props = dict(node.get("props", {}))
        children = node.get("children", [])
        if comp == "Text" and isinstance(props.get("text"), str):
            t = props["text"]
            if len(t) > PREVIEW_MAX_TEXT_CHARS:
                props["text"] = t[:PREVIEW_MAX_TEXT_CHARS] + "\u2026"
        elif comp == "List" and isinstance(props.get("items"), list):
            items = props["items"][:PREVIEW_MAX_LIST_ITEMS]
            if len(props["items"]) > len(items):
                items = items + ["\u2026"]
            props["items"] = items
        if children:
            children = [trunc(c)
                        for c in children[:PREVIEW_MAX_STACK_CHILDREN]]
        return {"component": comp, "props": props, "children": children}

    return trunc(tree)


def render_node(node):
    comp = node["component"]
    props = node["props"]
    children = node.get("children", [])
    if comp == "Text":
        return f'<p class="t">{esc(props["text"])}</p>'
    if comp == "List":
        items = "".join(f"<li>{esc(i)}</li>" for i in props["items"])
        return f'<ul class="l">{items}</ul>'
    if comp == "Button":
        gen = " g" if props.get("intent") == "generative" else ""
        return (f'<button class="b{gen}" data-action="{esc(props["action_id"])}"'
                f' data-intent="{esc(props["intent"])}">{esc(props["label"])}</button>')
    if comp == "Field":
        inp = props["input"]
        name = esc(props["name"])
        label = esc(props["label"])
        ph = (f' placeholder="{esc(props["placeholder"])}"'
              if "placeholder" in props else "")
        if inp == "boolean":
            checked = " checked" if props["value"] else ""
            ctl = (f'<input class="f-in" type="checkbox" name="{name}"{checked}>')
        else:
            t = "number" if inp == "number" else "text"
            ctl = (f'<input class="f-in" type="{t}" name="{name}"'
                   f' value="{esc(str(props["value"]))}"{ph}>')
        return f'<label class="f"><span>{label}</span>{ctl}</label>'
    if comp == "Media":
        return (f'<figure class="m" data-asset="{esc(props["asset_id"])}"'
                f' data-mediatype="{esc(props["media_type"])}">'
                f"<figcaption>{esc(props['alt'])}</figcaption></figure>")
    if comp == "Stack":
        d = "v" if props.get("direction") == "vertical" else "h"
        inner = "".join(render_node(c) for c in children)
        return f'<div class="s {d}">{inner}</div>'
    raise FragmentError(f"unknown-component: {comp}")


def render_tree(tree, kind, form_values=None):
    """Validate through the allowlist, enforce kind subset, render HTML."""
    cleaned = clean_node(tree)
    check_kind(cleaned, kind)
    return render_node(apply_form_values(cleaned, form_values))


def _chrome(mode):
    if mode == "expanded":
        return ('<div class="takeover">'
                '<button class="x" data-op="collapse">Collapse</button>'
                '<button class="x" data-op="close">Close</button></div>')
    return '<button class="x" data-op="expand">Expand</button>'


def _badge(origin):
    if origin == "generated":
        return '<span class="gen-badge">Generated</span>'
    if origin == "cached":
        return '<span class="org">Cached</span>'
    return '<span class="org">Built-in</span>'


def render_bubble_html(frag, mode="standard", form_values=None):
    """Full bubble HTML: shared wrapper + generative treatment + chrome.

    mode is 'standard' or 'expanded'. Same classes for every kind.
    form_values overrides Field values so unsent typed input is visible.
    With form_values=None the output is exactly the historical bytes.
    """
    tree_html = render_tree(frag["tree"], frag["kind"],
                            form_values=form_values)
    origin = frag["origin"]
    gen_cls = " gen" if origin == "generated" else ""
    mode_cls = "exp" if mode == "expanded" else "std"
    return (f'<article class="bubble{gen_cls} {mode_cls}"'
            f' data-fragment="{esc(frag["fragment_id"])}"'
            f' data-kind="{esc(frag["kind"])}"'
            f' data-origin="{esc(origin)}" data-mode="{mode}">'
            f"{_badge(origin)}{tree_html}{_chrome(mode)}</article>")


def render_preview_html(frag, form_values=None):
    """Bounded static preview: truncated body + physical size clamp + Expand.

    Used whenever there is no usable budget (missing/invalid/unmeasured) or
    the user collapsed an overflowed bubble: the huge body must never be
    emitted in full. Same shared classes; data-preview marks the truncation.
    """
    bounded = truncate_tree(apply_form_values(frag["tree"],
                                              form_values or None))
    tree_html = render_node(check_preview_clean(bounded, frag["kind"]))
    origin = frag["origin"]
    gen_cls = " gen" if origin == "generated" else ""
    return (f'<article class="bubble{gen_cls} std preview"'
            f' data-fragment="{esc(frag["fragment_id"])}"'
            f' data-kind="{esc(frag["kind"])}"'
            f' data-origin="{esc(origin)}" data-mode="standard"'
            f' data-preview="truncated" style="{PREVIEW_STYLE}">'
            f"{_badge(origin)}{tree_html}"
            f'<button class="x" data-op="expand">Expand</button></article>')


def check_preview_clean(bounded_tree, kind):
    """Validate the truncated/pre-filled tree before rendering a preview."""
    cleaned = clean_node(bounded_tree)
    check_kind(cleaned, kind)
    return cleaned


def fallback_bubble_html(text, reason):
    return (f'<article class="bubble std" data-mode="standard">'
            f'<p class="t">{esc(text)}</p>'
            f'<span class="fb" data-reason="{esc(reason)}"></span></article>')
