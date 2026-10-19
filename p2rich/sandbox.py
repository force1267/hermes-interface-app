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
# The degraded drawer-entry rule lives here for the same reason: a second
# <style> block or a style= attribute would not match the pinned style
# hash and would be blocked.
PREVIEW_CSS = ("article.preview{" + PREVIEW_STYLE + "}"
               "#drawer li.degraded{opacity:.55}")

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
      if(props.input==="number"&&(typeof v==="number"||v==="")) return v;
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
  var INITED = false;
  function setInited(tok, ctx, acts){
    if (typeof tok !== "string" || !tok) return false;
    if (typeof ctx !== "string" || !ctx) return false;
    TOKEN = tok; CONTEXT = ctx;
    if (Object.prototype.toString.call(acts) === "[object Array]")
      REGISTERED = acts.filter(function(a){ return typeof a === "string"; });
    INITED = true;
    return true;
  }
  document.addEventListener("input", function(ev){
    var t = ev.target;
    if(!t||!t.name||!CURRENT) return;
    var vals = FORMS[CURRENT]||(FORMS[CURRENT]={});
    if(t.type==="checkbox"){ vals[t.name] = !!t.checked; }
    else if(t.type==="number"){
      // Number inputs expose strings; keep state type-correct (fieldValue
      // only honours real numbers, so a raw string would be dropped and the
      // typed value lost on re-render). Empty/cleared input stays "" and is
      // rendered as an empty box; anything parseable becomes a Number
      // (zero included); unparseable input clears to "" rather than silently
      // reverting to the stale prop value.
      if(t.value===""||t.value===null||t.value===undefined){ vals[t.name] = ""; }
      else { var n = Number(t.value); vals[t.name] = isNaN(n) ? "" : n; }
    }
    else { vals[t.name] = t.value; }
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
  // Real user clicks on expanded-frame buttons dispatch to the parent: the
  // frame only forwards (with its channel credentials); the parent validates
  // source/token/context/registration before running the action op. A plain
  // debugger-injected parent message never exercises this path.
  document.addEventListener("click", function(e){
    var t = e.target;
    while(t&&t!==document){
      if(t.tagName==="BUTTON"&&t.hasAttribute&&t.hasAttribute("data-action")){
        e.preventDefault();
        try{ window.parent.postMessage({op:"action-click", token:TOKEN,
          context:CONTEXT, fragment_id:CURRENT,
          action_id:t.getAttribute("data-action")}, "*"); }catch(err){}
        return;
      }
      t = t.parentNode;
    }
  });
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
    if(d.op==="init"){
      reply(setInited(d.token, d.context, d.actions)?"ok":"denied");
      return;
    }
    if(!INITED){ reply("denied"); return; }
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


_SENTINEL_TOKEN = "__TOKEN__"
_SENTINEL_CONTEXT = "__CONTEXT__"


def _frame_js(channel_token, context, registered_actions=()):
    js = (FRAME_JS.replace("__TOKEN__", channel_token)
            .replace("__CONTEXT__", context)
            .replace("__ACTIONS__", json.dumps(list(registered_actions))))
    if channel_token != _SENTINEL_TOKEN:
        # Baked-credential bundle: live from load, no init op needed.
        # Sentinel bundles keep INITED=false until the init op arrives
        # (see serving_frame_js).
        js = js.replace("var INITED = false;", "var INITED = true;", 1)
    return js


def _sha256_b64(text):
    return base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


def serving_frame_js():
    """Static frame bundle for the served shell: sentinel token/context.

    Identical bytes for every session, so the parent page CSP can pin its
    hash. The live channel token/context/actions arrive via the postMessage
    init op (see FRAME_JS setInited); baked-token bundles from frame_srcdoc
    keep working unchanged.
    """
    return _frame_js(_SENTINEL_TOKEN, _SENTINEL_CONTEXT, [])


def serving_frame_srcdoc():
    """Full static srcdoc document embedding serving_frame_js().

    The meta CSP pins the exact bundle hash; the parent inlines this doc
    and delivers per-session credentials with init.
    """
    js = serving_frame_js()
    digest_b64 = _sha256_b64(js)
    csp = (CSP_BASE + "; " + CSP_NAV +
           f"; script-src 'sha256-{digest_b64}'")
    return ("""<!doctype html><html><head><meta http-equiv="Content-Security-Policy" """
            f"""content="{csp}"></head>"""
            f"""<body><div id="r"></div><script>{js}</script></body></html>""")


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
    } else if(d.op === "action-click"){
      // Expanded-frame button click: verify channel credentials and that the
      // action is registered before dispatching. Unregistered ids are dropped
      // here so the frame never runs an action the parent did not allow.
      if(d.token !== window.P2_TOKEN || d.context !== window.P2_CONTEXT) return;
      var aid = d.action_id;
      if(typeof aid !== "string" || window.P2_ACTIONS.indexOf(aid) < 0) return;
      post("action", {action_id: aid});
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
  /* P3 drawer/i-flow operations: named op boundary mirroring
  p3drawer/ops.py (add/rename/pin/unpin/delete/repair, same names and
  same confirm gating). Ops mutate a durable client store seeded from the
  server render and persisted to localStorage, then re-render; the status
  line is set only from actual op results, never before success.
  Destructive and repair ops (and any needs_repair entry) need an explicit
  second confirming click with a Cancel affordance; cancel preserves the
  entry. The fragment sandbox is untouched: this layer never posts to the
  frame and never renders fragment data. */
  (function(){
    var sec = document.getElementById("drawer");
    if(!sec) return;
    var status = document.getElementById("drawer-status");
    var ul = sec.querySelector("ul");
    var addBtn = sec.querySelector('[data-drawer-op="add-page"]');
    function say(t){ if(status) status.textContent = t; }
    var OPS = ["add", "rename", "pin", "unpin", "delete", "repair"];
    var LS_KEY = "p3-drawer-v1";
    var failNext = null;
    function esc(s){ return String(s).replace(/&/g, "&amp;")
      .replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;"); }
    function numId(id){ var m = /^pg-([0-9]+)$/.exec(id || "");
      return m ? parseInt(m[1], 10) : 0; }
    function seedFromDOM(){
      var out = [], maxId = 0, maxSeq = 0;
      var lis = ul.querySelectorAll("li[data-page]");
      for(var i = 0; i < lis.length; i++){
        var li = lis[i], id = li.getAttribute("data-page");
        var seq = parseInt(li.getAttribute("data-seq") || "0", 10) || 0;
        if(seq > maxSeq) maxSeq = seq;
        var n = numId(id); if(n > maxId) maxId = n;
        out.push({id: id, name: li.getAttribute("data-name") || "",
          pinned: li.getAttribute("data-pinned") === "1",
          status: li.getAttribute("data-status") || "ok",
          needs: !!li.querySelector('[data-needs="1"]'), seq: seq});
      }
      return {entries: out, maxId: maxId, maxSeq: maxSeq};
    }
    function fingerprint(seed){
      return seed.entries.map(function(e){
        return [e.id, e.name, e.pinned ? 1 : 0, e.status, e.seq]
          .join("|");
      }).join(";");
    }
    var seed = seedFromDOM();
    var seedFp = fingerprint(seed);
    var S = null;
    try{
      var raw = window.localStorage ?
        window.localStorage.getItem(LS_KEY) : null;
      if(raw){
        var parsed = JSON.parse(raw);
        if(parsed && parsed.seed === seedFp && parsed.entries) S = parsed;
      }
    }catch(e){ S = null; }
    if(!S) S = {seed: seedFp, entries: seed.entries,
      nextId: seed.maxId + 1, nextSeq: seed.maxSeq + 1};
    function save(){
      S.seed = seedFp;
      try{
        if(window.localStorage)
          window.localStorage.setItem(LS_KEY, JSON.stringify(S));
      }catch(e){}
    }
    function byId(id){
      for(var i = 0; i < S.entries.length; i++)
        if(S.entries[i].id === id) return S.entries[i];
      return null;
    }
    function uniqueName(base, exceptId){
      var t = {};
      S.entries.forEach(function(e){
        if(e.id !== exceptId) t[e.name] = 1;
      });
      if(!t[base]) return base;
      var n = 2;
      while(t[base + " " + n]) n++;
      return base + " " + n;
    }
    function sorted(){
      var p = S.entries.filter(function(e){ return e.pinned; });
      var u = S.entries.filter(function(e){ return !e.pinned; });
      u.sort(function(a, b){ return a.seq - b.seq; });
      return p.concat(u);
    }
    function entryButtons(e){
      var ops = e.needs ? ["repair", "delete"] :
        [(e.pinned ? "unpin" : "pin"), "rename", "delete"];
      return ops.map(function(op){
        var extra = op === "rename" ?
          ' data-name="' + esc(e.name) + '"' : "";
        return '<button data-drawer-op="' + op + '" data-page="' +
          esc(e.id) + '"' + extra + ">" + op + "</button>";
      }).join("");
    }
    function render(){
      ul.innerHTML = sorted().map(function(e){
        var cls = e.needs ? ' class="degraded"' : "";
        var flag = e.needs ?
          '<span data-needs="1">needs_repair</span>' : "";
        return "<li" + cls + ' data-page="' + esc(e.id) +
          '" data-pinned="' + (e.pinned ? "1" : "0") + '" data-status="' +
          esc(e.status) + '" data-name="' + esc(e.name) + '" data-seq="' +
          e.seq + '"><span class="dname">' + esc(e.name) + "</span>" +
          flag + entryButtons(e) + "</li>";
      }).join("");
      save();
    }
    /* -- op implementations: mutate the durable store, report results -- */
    function doAdd(name){
      if(failNext && failNext.op === "add"){
        var msg = failNext.message || "injected mid-write failure";
        var pending = name || "Untitled";
        failNext = null;
        return {status: "error", message: msg, retry: true,
          pendingName: pending};
      }
      var finalName = uniqueName(name || "Untitled");
      var id = "pg-" + (S.nextId++);
      S.entries.push({id: id, name: finalName, pinned: false,
        status: "ok", needs: false, seq: S.nextSeq++});
      return {status: "ok", id: id, name: finalName};
    }
    function doRename(id, newName){
      var e = byId(id);
      if(!e) return {status: "unknown-page", id: id};
      e.name = uniqueName(newName || e.name, id);
      return {status: "ok", id: id, name: e.name};
    }
    function doPin(id, on){
      var e = byId(id);
      if(!e) return {status: "unknown-page", id: id};
      e.pinned = !!on;
      return {status: "ok", id: id, pinned: e.pinned};
    }
    function doDelete(id){
      for(var i = 0; i < S.entries.length; i++)
        if(S.entries[i].id === id){
          S.entries.splice(i, 1);
          return {status: "ok", id: id, deleted: true};
        }
      return {status: "unknown-page", id: id};
    }
    function doRepair(id){
      var e = byId(id);
      if(!e) return {status: "unknown-page", id: id};
      if(!e.needs)
        return {status: "ok", id: id, repaired: false,
          reason: "no-repair-needed"};
      e.needs = false;
      e.status = "ok";
      return {status: "ok", id: id, repaired: true};
    }
    function dispatch(op){
      var name = op && op.op;
      if(OPS.indexOf(name) < 0) return {status: "unknown-op", op: name};
      if(name === "add") return doAdd(op.name);
      if(name === "rename") return doRename(op.page_id, op.new_name);
      if(name === "pin") return doPin(op.page_id, true);
      if(name === "unpin") return doPin(op.page_id, false);
      if(name === "delete"){
        if(!op.confirm) return {status: "confirm-required", id: op.page_id};
        return doDelete(op.page_id);
      }
      if(name === "repair"){
        if(!op.confirm) return {status: "confirm-required", id: op.page_id};
        return doRepair(op.page_id);
      }
    }
    /* -- UI flows: forms + two-step confirm/cancel, status from results -- */
    var armed = null;
    function liFor(id){
      var lis = ul.querySelectorAll("li[data-page]");
      for(var i = 0; i < lis.length; i++)
        if(lis[i].getAttribute("data-page") === id) return lis[i];
      return null;
    }
    function hideAddForm(){
      var f = document.getElementById("drawer-add-form");
      if(f && f.parentNode) f.parentNode.removeChild(f);
    }
    function showAddForm(){
      hideAddForm();
      armed = null;
      render();
      var box = document.createElement("div");
      box.id = "drawer-add-form";
      box.innerHTML = "<label>Add page " +
        '<input id="drawer-add-name" type="text"></label> ' +
        '<button data-drawer-ui="add-confirm">Add</button> ' +
        '<button data-drawer-ui="add-cancel">Cancel</button>';
      addBtn.parentNode.insertBefore(box, addBtn);
      var inp = box.querySelector("input");
      if(inp) inp.focus();
      say("Add a page: name it, then confirm.");
    }
    function confirmAdd(retryName){
      var inp = document.getElementById("drawer-add-name");
      var name = (retryName !== undefined) ? retryName :
        (inp && inp.value ? inp.value : "Untitled");
      var r = dispatch({op: "add", name: name});
      if(r.status === "error"){
        var box = document.getElementById("drawer-add-form");
        if(box){
          var err = box.querySelector(".drawer-add-error");
          if(!err){
            err = document.createElement("div");
            err.className = "drawer-add-error";
            box.appendChild(err);
          }
          err.innerHTML = "<span></span> " +
            '<button data-drawer-ui="add-retry">Retry</button>';
          err.querySelector("span").textContent =
            "Couldn\u2019t add that page (" + r.message +
            "). Nothing was added.";
          box.setAttribute("data-pending-name", r.pendingName);
        }
        say("Couldn\u2019t add that page (" + r.message +
          "). Nothing was added. Fix and retry.");
        return;
      }
      hideAddForm();
      render();
      say('Added page "' + r.name + '" as ' + r.id + ".");
    }
    function showRenameForm(id){
      var e = byId(id);
      if(!e) return;
      armed = null;
      hideAddForm();
      render();
      var li = liFor(id);
      if(!li) return;
      li.innerHTML = "<span></span> " +
        '<input id="drawer-rename-name" type="text"> ' +
        '<button data-drawer-ui="rename-save">Save</button> ' +
        '<button data-drawer-ui="rename-cancel">Cancel</button>';
      li.querySelector("span").textContent = e.name;
      var inp = li.querySelector("input");
      inp.value = e.name;
      inp.setAttribute("data-page", id);
      inp.focus();
      say("Rename " + id + ': edit the name, then save.');
    }
    function showConfirm(op, id){
      armed = op + ":" + id;
      render();
      var li = liFor(id);
      if(li){
        var bar = document.createElement("span");
        bar.innerHTML = '<button data-drawer-ui="confirm">Confirm ' + op +
          "</button> " + '<button data-drawer-ui="cancel">Cancel</button>';
        bar.querySelector('[data-drawer-ui="confirm"]')
          .setAttribute("data-op", op);
        bar.querySelector('[data-drawer-ui="confirm"]')
          .setAttribute("data-page", id);
        bar.querySelector('[data-drawer-ui="cancel"]')
          .setAttribute("data-page", id);
        li.appendChild(bar);
      }
      var e = byId(id);
      say("Confirm " + op + " for " + id +
        (e && e.needs ? " (needs_repair)." : ".") +
        " Click again to confirm, or cancel.");
    }
    function runConfirmed(op, id){
      var r = dispatch({op: op, page_id: id, confirm: true});
      armed = null;
      render();
      if(r.status === "ok" && (r.deleted || r.repaired))
        say((op === "delete" ? "Deleted " : "Repaired ") + id + ".");
      else if(r.status === "ok")
        say("Done: " + op + " " + id + ".");
      else
        say("Couldn\u2019t " + op + " " + id + " (" + r.status +
          "). Nothing changed.");
    }
    function handleDrawerClick(t){
      var op = t.getAttribute("data-drawer-op");
      var page = t.getAttribute("data-page") || "";
      if(op === "add-page"){ showAddForm(); return; }
      if(op === "pin" || op === "unpin"){
        var r = dispatch({op: op, page_id: page});
        armed = null;
        hideAddForm();
        render();
        if(r.status === "ok")
          say((op === "pin" ? "Pinned " : "Unpinned ") + page + ".");
        else say("Couldn\u2019t " + op + " " + page + " (" + r.status +
          "). Nothing changed.");
        return;
      }
      if(op === "rename"){ showRenameForm(page); return; }
      if(op === "delete" || op === "repair"){
        if(armed === op + ":" + page) runConfirmed(op, page);
        else showConfirm(op, page);
        return;
      }
    }
    function handleUiClick(t){
      var ui = t.getAttribute("data-drawer-ui");
      if(ui === "add-confirm"){ confirmAdd(); return; }
      if(ui === "add-retry"){
        var box = document.getElementById("drawer-add-form");
        confirmAdd(box ? box.getAttribute("data-pending-name") : "Untitled");
        return;
      }
      if(ui === "add-cancel"){
        hideAddForm();
        say("Add cancelled; nothing was added.");
        return;
      }
      if(ui === "rename-save"){
        var li = t.parentNode;
        var inp = li && li.querySelector("input");
        var id = inp ? inp.getAttribute("data-page") : "";
        var r = dispatch({op: "rename", page_id: id,
          new_name: inp ? inp.value : ""});
        render();
        if(r.status === "ok")
          say('Renamed ' + id + ' to "' + r.name + '".');
        else say("Couldn\u2019t rename " + id + " (" + r.status +
          "). Nothing changed.");
        return;
      }
      if(ui === "rename-cancel"){
        render();
        say("Rename cancelled; name kept.");
        return;
      }
      if(ui === "confirm"){
        runConfirmed(t.getAttribute("data-op"),
          t.getAttribute("data-page"));
        return;
      }
      if(ui === "cancel"){
        var kept = t.getAttribute("data-page");
        armed = null;
        render();
        say("Cancelled; " + (kept || "entry") + " kept.");
        return;
      }
    }
    sec.addEventListener("click", function(e){
      var t = e.target;
      while(t && t !== sec){
        if(t.getAttribute && t.getAttribute("data-drawer-op")){
          handleDrawerClick(t);
          return;
        }
        if(t.getAttribute && t.getAttribute("data-drawer-ui")){
          handleUiClick(t);
          return;
        }
        t = t.parentNode;
      }
    });
    /* Test + harness surface: same op names as p3drawer/ops.py. */
    window.DrawerOps = {
      OPS: OPS,
      dispatch: dispatch,
      injectFailure: function(opName, message){
        failNext = {op: opName || "add",
          message: message || "injected mid-write failure"};
      },
      state: function(){
        return JSON.parse(JSON.stringify({entries: S.entries,
          nextId: S.nextId}));
      },
      resetForTest: function(){
        try{
          if(window.localStorage) window.localStorage.removeItem(LS_KEY);
        }catch(e){}
        S = {seed: seedFp, entries: seed.entries,
          nextId: seed.maxId + 1, nextSeq: seed.maxSeq + 1};
        armed = null;
        failNext = null;
        hideAddForm();
        render();
      }
    };
    /* Re-render from the durable store so a reload restores prior ops. */
    render();
  })();
})();
"""


def _drawer_section(drawer):
    """P3 drawer/i-flow surface: pinned-first entries, Add last.

    Rendered from a Drawer.list_drawer() listing (already ordered
    pinned-first, unpinned in creation order). With drawer=None an empty
    shell with the Add affordance is rendered, so the static page always
    carries the drawer surface and its action handlers.
    """
    items = []
    if isinstance(drawer, dict):
        for e in drawer.get("entries", ()):
            pid = _html.escape(str(e.get("page_id", "")), quote=True)
            name = _html.escape(str(e.get("name", "")), quote=True)
            disp = _html.escape(str(e.get("name", "")))
            status = _html.escape(str(e.get("status", "ok")), quote=True)
            pinned = "1" if e.get("pinned") else "0"
            try:
                seq = int(e.get("seq", 0) or 0)
            except (TypeError, ValueError):
                seq = 0
            if e.get("needs_repair"):
                ops = ("repair", "delete")
                flag = '<span data-needs="1">needs_repair</span>'
                cls = ' class="degraded"'
            else:
                ops = (("unpin" if e.get("pinned") else "pin"),
                       "rename", "delete")
                flag = ""
                cls = ""
            btns = "".join(
                f'<button data-drawer-op="{op}" data-page="{pid}"'
                + (f' data-name="{name}"' if op == "rename" else "")
                + f">{op}</button>" for op in ops)
            items.append(
                f'<li{cls} data-page="{pid}" data-pinned="{pinned}"'
                f' data-status="{status}" data-name="{name}"'
                f' data-seq="{seq}">'
                f'<span class="dname">{disp}</span>{flag}{btns}</li>')
    return (
        '<section id="drawer" data-drawer="1"><h2>Pages</h2><ul>'
        + "".join(items)
        + '</ul><button data-drawer-op="add-page">Add page</button>'
          '<div id="drawer-status" role="status"></div></section>')


def build_page(channel_token="tok-p2", context="ctx-1", registered_actions=(),
               bubbles=(), drawer=None):
    """Outer client page with exactly one reusable sandboxed frame."""
    registered_actions = tuple(registered_actions or ())
    srcdoc = frame_srcdoc(channel_token, context, registered_actions)
    srcdoc_attr = _html.escape(srcdoc, quote=True)
    articles, bubble_data = _bubble_articles(bubbles)
    drawer_html = _drawer_section(drawer)
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
{drawer_html}
<iframe id="{FRAME_ID}" sandbox="{SANDBOX_ATTR}" srcdoc="{srcdoc_attr}"></iframe>
<script>
{inline}
</script>
</body></html>"""
    return page


def frame_count_in_page(page_html):
    return page_html.lower().count("<iframe")
