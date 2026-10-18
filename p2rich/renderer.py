"""Deterministic trusted renderer: fragment tree -> HTML through the allowlist.

Only allowlisted components/props reach the DOM. Unknown innocuous props
are stripped by clean_node; forbidden keys (html/code/script/style/src/href/
on*) and unknown components raise FragmentError and the caller degrades per
R04. No per-kind styling: every kind shares the same classes; the wrapper
carries data-kind/data-origin for truthfulness only.
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


def render_tree(tree, kind):
    """Validate through the allowlist, enforce kind subset, render HTML."""
    cleaned = clean_node(tree)
    check_kind(cleaned, kind)
    return render_node(cleaned)


def render_bubble_html(frag, mode="standard"):
    """Full bubble HTML: shared wrapper + generative treatment + chrome.

    mode is 'standard' or 'expanded'. Same classes for every kind.
    """
    tree_html = render_tree(frag["tree"], frag["kind"])
    origin = frag["origin"]
    gen_cls = " gen" if origin == "generated" else ""
    mode_cls = "exp" if mode == "expanded" else "std"
    if origin == "generated":
        badge = '<span class="gen-badge">Generated</span>'
    elif origin == "cached":
        badge = '<span class="org">Cached</span>'
    else:
        badge = '<span class="org">Built-in</span>'
    if mode == "expanded":
        chrome = ('<div class="takeover">'
                  '<button class="x" data-op="collapse">Collapse</button>'
                  '<button class="x" data-op="close">Close</button></div>')
    else:
        chrome = '<button class="x" data-op="expand">Expand</button>'
    return (f'<article class="bubble{gen_cls} {mode_cls}"'
            f' data-fragment="{esc(frag["fragment_id"])}"'
            f' data-kind="{esc(frag["kind"])}"'
            f' data-origin="{esc(origin)}" data-mode="{mode}">'
            f"{badge}{tree_html}{chrome}</article>")


def fallback_bubble_html(text, reason):
    return (f'<article class="bubble std" data-mode="standard">'
            f'<p class="t">{esc(text)}</p>'
            f'<span class="fb" data-reason="{esc(reason)}"></span></article>')
