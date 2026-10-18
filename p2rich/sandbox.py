"""F05 sandbox page: one reusable iframe + strict CSP + validating bridge.

Outer page owns the backend connection; the frame only renders data.
Bridge ops allowed: render, action, resize, ready. Frame srcdoc is
opaque-origin; auth is the per-instance channel token, not the origin.

CSP composition (defect 3): a srcdoc frame inherits the OUTER page's CSP
in addition to enforcing its own meta policy, so the outer policy must
carry the frame bundle's script hash too (hash-pinned, no
'unsafe-inline', sandbox still exactly allow-scripts).

Frame bundle contains zero navigation primitives (no location/window.open
references, no links, no forms with actions); anchors are click-trapped,
a beforeunload stay-guard is installed, and navigate-to 'none' is set
for browsers that enforce it. Fragment content can never become script
(allowlist + hash CSP + escaping), so scripted navigation cannot
originate from rendered data.

Outer page wires real UI: registered actions post validated action ops,
bubble Expand renders the full tree through the frame bridge, Collapse
restores the server-rendered bounded preview and focus, typed form
values round-trip through frame state sync, and Tab is trapped inside
an expanded takeover.
"""
import html as _html
import base64
import hashlib
import json

from p0contract.fragments import validate_fragment, FragmentError
from p0contract.render_policy import (
    ALLOWED_BRIDGE_OPS, validate_bridge, sandbox_config, check_sandbox,
)
from .renderer import render_preview_html, fallback_bubble_html
from .renderer import PREVIEW_STYLE

# Physical preview clamp as a hash-pinned stylesheet rule: the page CSP has
# no style-src allowance for inline styles (they fall back to default-src
# 'none'), so the bound lives here, pinned by hash like the scripts.
PREVIEW_CSS = "article.preview{" + PREVIEW_STYLE + "}"

SANDBOX_ATTR = "allow-scripts"
FRAME_ID = "frag-frame"

CSP_BASE = ("default-src 'none'; connect-src 'none'; form-action 'none'; "
            "object-src 'none'; base-uri 'none'; frame-src 'none'")
CSP_NAV = "navigate-to 'none'"
# Back-compat alias: the six required directives (tests assert on these).
CSP_META = CSP_BASE + "; script-src 'self'; style-src 'self'"

# Trusted renderer inside the frame: mirrors the python allowlist in JS and
# refuses raw-code components/props. Fragments are data; no code path exists.
FRAME_JS = r"""
(function(){
  var TOKEN = "__TOKEN__";
  var CONTEXT = "__CONTEXT__";
  var REGISTERED = __ACTIONS__;
  var KIND_COMPONENTS = {text:["Stack","Text"],
    "card-list":["Stack","Text","List","Button"],
    form:["Stack","Text","List","Button","Field"],
    media:["Stack","Text","List","Button","Field","Media"]};
  var PREVIEW_TEXT = 200, PREVIEW_ITEMS = 3, PREVIEW_CHILDREN = 8;
  function esc(s){ return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function badKey(k){ var l = String(k).toLowerCase();
    return l==="html"||l==="code"||l==="script"||l==="style"||l==="src"||
      l==="href"||l.slice(0,2)==="on"; }
  function mediaAsset(a){
    if(typeof a!=="string"||!a) throw new Error("Media.asset_id-must-be-nonempty");
    var l = a.toLowerCase();
    if(a.indexOf("://")>=0||l.indexOf("data:")===0||l.indexOf("javascript:")===0)
      throw new Error("Media.external-url-denied");
    if(a.indexOf("http")===0||a.charAt(0)==="/")
      throw new Error("Media.external-url-denied");
  }
  function cleanNode(n){
    if(!n||typeof n!=="object"||typeof n.component!=="string"||
       typeof n.props!=="object"||!n.props||!Array.isArray(n.children))
      throw new Error("node-shape-invalid");
    var comp = n.component, props = n.props, children = n.children;
    if(!(comp==="Stack"||comp==="Text"||comp==="List"||comp==="Button"||
         comp==="Field"||comp==="Media"))
      throw new Error("unknown-component:"+comp);
    for(var k in props){ if(badKey(k)) throw new Error("raw-code-prop-denied:"+k); }
    var c = {}, kids = [];
    if(comp==="Stack"){
      if(props.direction!=="vertical"&&props.direction!=="horizontal")
        throw new Error("Stack.direction-invalid");
      c.direction = props.direction;
      kids = children.map(cleanNode);
    } else if(comp==="Text"){
      if(typeof props.text!=="string") throw new Error("Text.text-must-be-string");
      c.text = props.text;
      if(children.length) throw new Error("Text-children-must-be-empty");
    } else if(comp==="List"){
      if(!Array.isArray(props.items)||!props.items.every(function(i){return typeof i==="string";}))
        throw new Error("List.items-must-be-string-array");
      c.items = props.items.slice();
      if(children.length) throw new Error("List-children-must-be-empty");
    } else if(comp==="Button"){
      if(typeof props.label!=="string") throw new Error("Button.label-must-be-string");
      if(typeof props.action_id!=="string"||!props.action_id)
        throw new Error("Button.action_id-must-be-nonempty");
      if(props.intent!=="assigned"&&props.intent!=="generative")
        throw new Error("Button.intent-invalid");
      c.label = props.label; c.action_id = props.action_id; c.intent = props.intent;
      if(children.length) throw new Error("Button-children-must-be-empty");
    } else if(comp==="Field"){
      if(typeof props.name!=="string"||!props.name)
        throw new Error("Field.name-must-be-nonempty");
      if(typeof props.label!=="string"||!props.label)
        throw new Error("Field.label-must-be-nonempty");
      if(props.input!=="text"&&props.input!=="number"&&props.input!=="boolean")
        throw new Error("Field.input-invalid");
      if(!("value" in props)) throw new Error("Field.value-required");
      var v = props.value, w = props.input;
      var ok = (w==="text") ? (typeof v==="string") :
        (w==="number") ? (typeof v==="number") : (typeof v==="boolean");
      if(!ok) throw new Error("Field.value-type-mismatch");
      c.name = props.name; c.label = props.label; c.input = w; c.value = v;
      if("placeholder" in props){
        if(typeof props.placeholder!=="string")
          throw new Error("Field.placeholder-must-be-string");
        c.placeholder = props.placeholder;
      }
      if(children.length) throw new Error("Field-children-must-be-empty");
    } else if(comp==="Media"){
      if(typeof props.alt!=="string") throw new Error("Media.alt-must-be-string");
      if(["image","audio","video","file"].indexOf(props.media_type)<0)
        throw new Error("Media.media_type-invalid");
      mediaAsset(props.asset_id);
      c.asset_id = props.asset_id; c.alt = props.alt; c.media_type = props.media_type;
      if(children.length) throw new Error("Media-children-must-be-empty");
    }
    return {component:comp, props:c, children:kids};
  }
  function checkKind(tree, kind){
    if(kind===undefined||kind===null) return;
    var allowed = KIND_COMPONENTS[kind];
    if(!allowed) throw new Error("unknown-kind:"+kind);
    var stack = [tree];
    while(stack.length){
      var n = stack.pop();
      if(allowed.indexOf(n.component)<0)
        throw new Error("kind-component-denied:"+kind+":"+n.component);
      for(var i=0;i<n.children.length;i++) stack.push(n.children[i]);
    }
  }
  function truncate(node){
    var props = {}, k;
    for(k in node.props) props[k] = node.props[k];
    var kids = node.children;
    if(node.component==="Text"&&typeof props.text==="string"&&props.text.length>PREVIEW_TEXT)
      props.text = props.text.slice(0,PREVIEW_TEXT)+"\u2026";
    if(node.component==="List"&&Array.isArray(props.items)){
      props.items = props.items.slice(0,PREVIEW_ITEMS);
      if(node.props.items.length>PREVIEW_ITEMS) props.items.push("\u2026");
    }
    if(kids.length) kids = kids.slice(0,PREVIEW_CHILDREN).map(truncate);
    return {component:node.component, props:props, children:kids};
  }
  function fieldValue(name, props, formValues){
    if(formValues&&typeof formValues==="object"&&
       Object.prototype.hasOwnProperty.call(formValues,name)){
      var v = formValues[name];
      if(props.input==="text"&&typeof v==="string") return v;
      if(props.input==="number"&&typeof v==="number") return v;
      if(props.input==="boolean"&&typeof v==="boolean") return v;
    }
    return props.value;
  }
  function renderNode(n, formValues){
    var p = n.props;
    if(n.component==="Text") return '<p class="t">'+esc(p.text)+"</p>";
    if(n.component==="List") return '<ul class="l">'+p.items.map(function(i){
      return "<li>"+esc(i)+"</li>"; }).join("")+"</ul>";
    if(n.component==="Button"){ var g=p.intent==="generative"?" g":"";
      return '<button class="b'+g+'" data-action="'+esc(p.action_id)+
        '" data-intent="'+esc(p.intent)+'">'+esc(p.label)+"</button>"; }
    if(n.component==="Field"){
      var val = fieldValue(p.name, p, formValues);
      if(p.input==="boolean"){
        var checked = val?" checked":"";
        return '<label class="f"><span>'+esc(p.label)+'</span>'+
          '<input class="f-in" type="checkbox" name="'+esc(p.name)+'"'+checked+"></label>";
      }
      var t = p.input==="number"?"number":"text";
      var ph = ("placeholder" in p)?' placeholder="'+esc(p.placeholder)+'"':"";
      return '<label class="f"><span>'+esc(p.label)+'</span>'+
        '<input class="f-in" type="'+t+'" name="'+esc(p.name)+
        '" value="'+esc(String(val))+'"'+ph+"></label>";
    }
    if(n.component==="Media") return '<figure class="m" data-asset="'+esc(p.asset_id)+
      '" data-mediatype="'+esc(p.media_type)+'"><figcaption>'+esc(p.alt)+"</figcaption></figure>";
    if(n.component==="Stack"){ var d=p.direction==="vertical"?"v":"h";
      return '<div class="s '+d+'">'+n.children.map(function(c){return renderNode(c,formValues);}).join("")+"</div>"; }
    throw new Error("unknown-component");
  }
  var FORMS = {};
  var CURRENT = null;
  document.addEventListener("input", function(ev){
    var t = ev.target;
    if(!t||!t.name||!CURRENT) return;
    var vals = FORMS[CURRENT]||(FORMS[CURRENT]={});
    vals[t.name] = (t.type==="checkbox") ? !!t.checked : t.value;
    try{ window.parent.postMessage({op:"form-state", fragment_id:CURRENT, values:vals}, "*"); }catch(e){}
  });
  function reply(status){
    try{ window.parent.postMessage({op:"ready", status:status}, "*"); }catch(e){}
  }
  window.addEventListener("beforeunload", function(e){
    e.preventDefault(); e.returnValue = "";
  });
  document.addEventListener("click", function(e){
    var t = e.target;
    while(t&&t!==document){
      if(t.tagName==="A"){ e.preventDefault(); return; }
      t = t.parentNode;
    }
  }, true);
  window.__renderTree = function(tree, kind, formValues, preview){
    var cleaned = cleanNode(tree);
    checkKind(cleaned, kind);
    var fv = (formValues&&typeof formValues==="object")?formValues:{};
    if(preview) cleaned = truncate(cleaned);
    return renderNode(cleaned, fv);
  };
  window.addEventListener("message", function(ev){
    if(ev.source!==window.parent){ reply("denied"); return; }
    var d = ev.data||{};
    var ok = d.token===TOKEN && d.context===CONTEXT &&
      (d.op==="render"||d.op==="action"||d.op==="resize"||d.op==="ready");
    if(!ok){ reply("denied"); return; }
    if(d.op==="action"){
      var aid = (d.payload||{}).action_id;
      if(REGISTERED.indexOf(aid)<0){ reply("denied-action"); return; }
      reply("action-ok:"+aid); return;
    }
    if(d.op==="render"){
      try{
        var p = d.payload||{};
        var cleaned = cleanNode(p.tree);
        checkKind(cleaned, p.kind);
        CURRENT = p.fragment_id||null;
        var fv = {};
        if(p.form_values&&typeof p.form_values==="object") fv = p.form_values;
        if(CURRENT&&FORMS[CURRENT]){
          var merged = {};
          for(var k in fv) merged[k] = fv[k];
          for(var k2 in FORMS[CURRENT]) merged[k2] = FORMS[CURRENT][k2];
          fv = merged;
        }
        if(p.preview) cleaned = truncate(cleaned);
        document.getElementById("r").innerHTML = renderNode(cleaned, fv);
        reply("rendered");
      }catch(e){ reply("refused:"+e.message); }
      return;
    }
    reply("ok");
  });
  reply("loaded");
})();
"""


def _frame_js(channel_token, context, registered_actions=()):
    return (FRAME_JS.replace("__TOKEN__", channel_token)
            .replace("__CONTEXT__", context)
            .replace("__ACTIONS__", json.dumps(list(registered_actions))))


def _sha256_b64(text):
    return base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


def frame_srcdoc(channel_token, context, registered_actions=()):
    js = _frame_js(channel_token, context, registered_actions)
    # Bundled renderer runs only under its build-supplied hash (F05).
    digest_b64 = _sha256_b64(js)
    csp = (CSP_BASE + "; " + CSP_NAV +
           f"; script-src 'sha256-{digest_b64}'")
    doc = ("""<!doctype html><html><head><meta http-equiv="Content-Security-Policy" """
           f"""content="{csp}"></head>"""
           f"""<body><div id="r"></div><script>{js}</script></body></html>""")
    return doc


def _bubble_articles(bubbles):
    """Server-render bounded previews + collect bridge data for bubbles.

    Accepts RichBubble instances or dicts {fragment, form_values?,
    focus_target?}. Invalid fragments degrade to fallback text (never a
    silent drop, never raw bytes).
    """
    articles = []
    data = []
    for i, b in enumerate(bubbles or ()):
        if hasattr(b, "fragment"):
            frag = b.fragment
            fvals = dict(getattr(b, "form_values", {}) or {})
            ftarget = getattr(b, "focus_target", None)
        else:
            frag = b.get("fragment")
            fvals = dict(b.get("form_values", {}) or {})
            ftarget = b.get("focus_target")
        try:
            validate_fragment(frag)
            fid = frag.get("fragment_id") or f"bubble-{i}"
            html = render_preview_html(frag, fvals)
            html = html.replace(
                '<button class="x" data-op="expand">Expand</button>',
                f'<button id="x-{_html.escape(fid, quote=True)}"'
                ' class="x" data-op="expand">Expand</button>', 1)
            articles.append(html)
            data.append({"id": fid, "tree": frag["tree"], "kind": frag["kind"],
                         "form_values": fvals, "focus_target": ftarget})
        except (FragmentError, KeyError, TypeError, AttributeError):
            try:
                fb = (frag.get("fallback_text", "")
                      if isinstance(frag, dict) else "") or "Content unavailable."
            except Exception:
                fb = "Content unavailable."
            articles.append(fallback_bubble_html(fb, "invalid-bubble-skipped"))
    return "\n".join(articles), data


def _action_buttons(registered_actions):
    return "\n".join(
        f'<button id="act-{_html.escape(a, quote=True)}"'
        f' class="a" data-op="action"'
        f' data-action="{_html.escape(a, quote=True)}">'
        f"{_html.escape(a, quote=True)}</button>"
        for a in (registered_actions or ()))


def _js_data(obj):
    # Embed JSON in a <script> block: escape `<` so no `</script>` can form.
    return (json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
            .replace("<", "\\u003c"))


OUTER_JS_TEMPLATE = """window.P2_TOKEN = __TOKEN_JSON__;
window.P2_CONTEXT = __CONTEXT_JSON__;
window.P2_ACTIONS = __ACTIONS_JSON__;
window.P2_BUBBLES = __BUBBLES_JSON__;
(function(){
  var frame = document.getElementById("__FRAME_ID__");
  var bubbles = document.getElementById("bubbles");
  var PREV = {};
  var EXPANDED = {};
  var STORED = {};
  var FOCUS_TARGET = {};
  Array.prototype.forEach.call(
    bubbles.querySelectorAll("article[data-fragment]"), function(a){
      PREV[a.getAttribute("data-fragment")] = a.outerHTML;
    });
  window.P2_BUBBLES.forEach(function(b){
    STORED[b.id] = b.form_values || {};
    FOCUS_TARGET[b.id] = b.focus_target || null;
  });
  function post(op, payload){
    frame.contentWindow.postMessage(
      {token: window.P2_TOKEN, context: window.P2_CONTEXT,
       op: op, payload: payload}, "*");
  }
  window.addEventListener("message", function(ev){
    if(ev.source !== frame.contentWindow) return;
    var d = ev.data || {};
    if(d.op === "form-state" && d.fragment_id){
      STORED[d.fragment_id] = d.values || {};
    }
  });
  function findBubble(id){
    for(var i=0;i<window.P2_BUBBLES.length;i++)
      if(window.P2_BUBBLES[i].id===id) return window.P2_BUBBLES[i];
    return null;
  }
  function article(id){
    var safe = String(id).replace(/"/g, '\\"');
    return bubbles.querySelector('article[data-fragment="'+safe+'"]');
  }
  function setChromeExpanded(id){
    var art = article(id);
    if(!art) return;
    var btn = art.querySelector("button.x[data-op=expand]");
    if(btn){
      var wrap = document.createElement("div");
      wrap.className = "takeover";
      var c1 = document.createElement("button");
      c1.className = "x"; c1.setAttribute("data-op","collapse");
      c1.textContent = "Collapse";
      var c2 = document.createElement("button");
      c2.className = "x"; c2.setAttribute("data-op","close");
      c2.textContent = "Close";
      wrap.appendChild(c1); wrap.appendChild(c2);
      btn.parentNode.replaceChild(wrap, btn);
    }
    art.setAttribute("data-state","expanded");
  }
  function restoreChrome(id){
    var art = article(id);
    if(art && PREV[id]){
      var tmp = document.createElement("div");
      tmp.innerHTML = PREV[id];
      var fresh = tmp.firstChild;
      art.parentNode.replaceChild(fresh, art);
    }
  }
  function expand(id, invoker){
    var b = findBubble(id);
    if(!b) return;
    post("render", {tree: b.tree, kind: b.kind, fragment_id: id,
                    form_values: STORED[id] || {}});
    setChromeExpanded(id);
    EXPANDED[id] = true;
    if(invoker && invoker.id) INVOKER_IDS[id] = invoker.id;
    try{ frame.focus(); }catch(e){}
  }
  var INVOKER_IDS = {};
  function collapse(id){
    var b = findBubble(id);
    if(b)
      post("render", {tree: b.tree, kind: b.kind, fragment_id: id,
                      form_values: STORED[id] || {}, preview: true});
    delete EXPANDED[id];
    restoreChrome(id);
    var target = null;
    var ft = FOCUS_TARGET[id];
    if(ft) target = document.getElementById(ft);
    if(!target && INVOKER_IDS[id])
      target = document.getElementById(INVOKER_IDS[id]);
    if(target && target.focus){ try{ target.focus(); }catch(e){} }
  }
  document.addEventListener("click", function(e){
    var t = e.target;
    while(t && t !== document){
      if(t.getAttribute && t.getAttribute("data-op")){
        var op = t.getAttribute("data-op");
        var art = null, id = null;
        if(t.hasAttribute && t.hasAttribute("data-fragment-id"))
          id = t.getAttribute("data-fragment-id");
        else {
          var n = t;
          while(n && n !== document){
            if(n.getAttribute && n.getAttribute("data-fragment")){
              id = n.getAttribute("data-fragment"); break;
            }
            n = n.parentNode;
          }
        }
        if(op === "expand" && id) expand(id, t);
        else if((op === "collapse" || op === "close") && id) collapse(id);
        else if(op === "action" && t.getAttribute("data-action"))
          post("action", {action_id: t.getAttribute("data-action")});
        e.preventDefault();
        return;
      }
      if(t.getAttribute && t.getAttribute("data-action")){
        // In-content buttons (server-rendered preview chrome) act live.
        post("action", {action_id: t.getAttribute("data-action")});
        e.preventDefault();
        return;
      }
      t = t.parentNode;
    }
  });
  document.addEventListener("keydown", function(e){
    var ids = Object.keys(EXPANDED).filter(function(k){ return EXPANDED[k]; });
    if(!ids.length || e.key !== "Tab") return;
    var art = article(ids[0]);
    var f = [];
    if(art) f = Array.prototype.slice.call(art.querySelectorAll("button"));
    f.push(frame);
    if(!f.length) return;
    var first = f[0], last = f[f.length-1];
    if(e.shiftKey && document.activeElement === first){
      e.preventDefault(); last.focus();
    } else if(!e.shiftKey && document.activeElement === last){
      e.preventDefault(); first.focus();
    }
  });
})();
"""


def build_page(channel_token="tok-p2", context="ctx-1", registered_actions=(),
               bubbles=()):
    """Outer client page with exactly one reusable sandboxed frame."""
    registered_actions = tuple(registered_actions or ())
    srcdoc = frame_srcdoc(channel_token, context, registered_actions)
    srcdoc_attr = _html.escape(srcdoc, quote=True)
    articles, bubble_data = _bubble_articles(bubbles)
    inline = (OUTER_JS_TEMPLATE
              .replace("__FRAME_ID__", FRAME_ID)
              .replace("__TOKEN_JSON__", _js_data(channel_token))
              .replace("__CONTEXT_JSON__", _js_data(context))
              .replace("__ACTIONS_JSON__",
                       _js_data(list(registered_actions or ())))
              .replace("__BUBBLES_JSON__", _js_data(bubble_data)))
    outer_digest = _sha256_b64("\n" + inline + "\n")
    frame_digest = _sha256_b64(_frame_js(channel_token, context,
                                         registered_actions or ()))
    css_digest = _sha256_b64(PREVIEW_CSS)
    # The srcdoc frame inherits this outer policy AND enforces its own
    # frame policy: both hashes are pinned so the frame bundle runs.
    csp = (CSP_BASE + "; " + CSP_NAV +
           f"; script-src 'sha256-{outer_digest}' 'sha256-{frame_digest}'"
           f"; style-src 'sha256-{css_digest}'")
    page = f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<title>P2 sandbox harness</title><style>{PREVIEW_CSS}</style></head>
<body>
<div id="bubbles">{articles}</div>
<div id="actions">{_action_buttons(registered_actions)}</div>
<iframe id="{FRAME_ID}" sandbox="{SANDBOX_ATTR}" srcdoc="{srcdoc_attr}"></iframe>
<script>
{inline}
</script>
</body></html>"""
    return page


def frame_count_in_page(page_html):
    return page_html.lower().count("<iframe")
