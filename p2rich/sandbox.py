"""F05 sandbox page: one reusable iframe + strict CSP + validating bridge.

Outer page owns the backend connection; the frame only renders data.
Bridge ops allowed: render, action, resize, ready. Frame srcdoc is
opaque-origin; auth is the per-instance channel token, not the origin.
"""
import html as _html
import base64
import hashlib
import json

from p0contract.render_policy import (
    ALLOWED_BRIDGE_OPS, validate_bridge, sandbox_config, check_sandbox,
)

SANDBOX_ATTR = "allow-scripts"
FRAME_ID = "frag-frame"

CSP_BASE = ("default-src 'none'; connect-src 'none'; form-action 'none'; "
            "object-src 'none'; base-uri 'none'; frame-src 'none'")
# Back-compat alias: the six required directives (tests assert on these).
CSP_META = CSP_BASE + "; script-src 'self'; style-src 'self'"

# Trusted renderer inside the frame: mirrors the python allowlist in JS and
# refuses raw-code components/props. Fragments are data; no code path exists.
FRAME_JS = r"""
(function(){
  var TOKEN = "__TOKEN__";
  var CONTEXT = "__CONTEXT__";
  var REGISTERED = __ACTIONS__;
  var ALLOW = {Stack:1, Text:1, List:1, Button:1, Field:1, Media:1};
  function esc(s){ return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function badKey(k){ var l = String(k).toLowerCase();
    return l==="html"||l==="code"||l==="script"||l==="style"||l==="src"||
      l==="href"||l.slice(0,2)==="on"; }
  function renderNode(n){
    if(!n || !ALLOW[n.component]) throw new Error("unknown-component:"+(n&&n.component));
    var p = n.props||{};
    for(var k in p){ if(badKey(k)) throw new Error("raw-code-prop-denied:"+k); }
    if(n.component==="Text") return '<p class="t">'+esc(p.text)+"</p>";
    if(n.component==="List") return '<ul class="l">'+p.items.map(function(i){
      return "<li>"+esc(i)+"</li>"; }).join("")+"</ul>";
    if(n.component==="Button"){ var g=p.intent==="generative"?" g":"";
      return '<button class="b'+g+'" data-action="'+esc(p.action_id)+'">'+esc(p.label)+"</button>"; }
    if(n.component==="Field") return '<label class="f"><span>'+esc(p.label)+
      "</span><input name=\""+esc(p.name)+"\"></label>";
    if(n.component==="Media") return '<figure class="m" data-asset="'+esc(p.asset_id)+
      '"><figcaption>'+esc(p.alt)+"</figcaption></figure>";
    if(n.component==="Stack") return '<div class="s">'+(n.children||[]).map(renderNode).join("")+"</div>";
    throw new Error("unknown-component");
  }
  window.__renderTree = renderNode;
  window.addEventListener("message", function(ev){
    var d = ev.data||{};
    var ok = d.token===TOKEN && d.context===CONTEXT &&
      (d.op==="render"||d.op==="action"||d.op==="resize"||d.op==="ready");
    if(!ok){ parent.postMessage({op:"ready",status:"denied"}, "*"); return; }
    if(d.op==="action" && REGISTERED.indexOf((d.payload||{}).action_id)<0){
      parent.postMessage({op:"ready",status:"denied-action"}, "*"); return; }
    if(d.op==="render"){
      try{ var h=renderNode(d.payload.tree);
        document.getElementById("r").innerHTML=h;
        parent.postMessage({op:"ready",status:"rendered"}, "*");
      }catch(e){ parent.postMessage({op:"ready",status:"refused:"+e.message}, "*"); }
    }
  });
  parent.postMessage({op:"ready",status:"loaded"}, "*");
})();
"""


def frame_srcdoc(channel_token, context, registered_actions=()):
    js = (FRAME_JS.replace("__TOKEN__", channel_token)
          .replace("__CONTEXT__", context)
          .replace("__ACTIONS__", json.dumps(list(registered_actions))))
    # Bundled renderer runs only under its build-supplied hash (F05).
    digest = base64.b64encode(hashlib.sha256(js.encode()).digest()).decode()
    csp = CSP_BASE + f"; script-src 'sha256-{digest}'"
    doc = ("""<!doctype html><html><head><meta http-equiv="Content-Security-Policy" """
           f"""content="{csp}"></head>"""
           f"""<body><div id="r"></div><script>{js}</script></body></html>""")
    return doc


def build_page(channel_token="tok-p2", context="ctx-1", registered_actions=()):
    """Outer client page with exactly one reusable sandboxed frame."""
    srcdoc = frame_srcdoc(channel_token, context, registered_actions)
    srcdoc_attr = _html.escape(srcdoc, quote=True)
    inline = (f"window.P2_TOKEN = {json.dumps(channel_token)};\n"
              f"window.P2_CONTEXT = {json.dumps(context)};")
    digest = base64.b64encode(
        hashlib.sha256(("\n" + inline + "\n").encode()).digest()).decode()
    csp = CSP_BASE + f"; script-src 'sha256-{digest}'"
    page = f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<title>P2 sandbox harness</title></head>
<body>
<div id="bubbles"></div>
<iframe id="{FRAME_ID}" sandbox="{SANDBOX_ATTR}" srcdoc="{srcdoc_attr}"></iframe>
<script>
{inline}
</script>
</body></html>"""
    return page


def frame_count_in_page(page_html):
    return page_html.lower().count("<iframe")
