/* Thin transport shim. No rendering policy, no page data channel.
   One socket only: the /app/ws transport. All operational thresholds
   (draft bound, reconnect backoff, frame clamp) arrive in the welcome
   client_policy; this file owns no numeric policy of its own. Drafts stay
   in sessionStorage (account+conversation scoped, never credentials). */
(function () {
  "use strict";
  var RELEASE_ID = (document.querySelector('meta[name="release-id"]') || {}).content || "dev";
  var statusEl = document.getElementById("connection-status");
  var bubblesEl = document.getElementById("bubbles");
  var drawerEl = document.getElementById("drawer-items");
  var addEl = document.getElementById("add-content");
  var composer = document.getElementById("composer");
  var input = document.getElementById("composer-input");
  var sendBtn = document.getElementById("composer-send");
  var frame = document.getElementById("frag-frame");
  var frameDoc = null;
  try {
    var fdEl = document.getElementById("frame-doc");
    frameDoc = fdEl ? JSON.parse(fdEl.textContent) : null;
  } catch (e) { frameDoc = null; }
  var state = { ws: null, csrf: null, clientId: null, generation: 0,
    seq: 0, conversationId: null, pendingText: null, attempt: 0,
    openTime: 0, policy: null, frameToken: null, frameContext: null,
    frameActions: [], frameReady: false, forms: {}, lastSeq: 0,
    pendingRenders: [], awaiting: {} };

  function setStatus(s, detail) {
    statusEl.textContent = s + (detail ? ": " + detail : "");
    statusEl.dataset.state = (s === "ready") ? "up" : "down";
    sendBtn.disabled = (s !== "ready");
  }
  function draftKey() {
    return "draft:" + state.conversationId;
  }
  function draftBound() {
    var b = state.policy && state.policy.draft_bytes;
    return (typeof b === "number" && b > 0) ? b : null;
  }
  function saveDraft() {
    try {
      if (state.conversationId && input.value) {
        var bound = draftBound();
        var v = (bound === null) ? input.value : input.value.slice(0, bound);
        sessionStorage.setItem(draftKey(), v);
      }
    } catch (e) { /* storage may be unavailable; draft is best-effort */ }
  }
  function loadDraft() {
    try {
      var d = state.conversationId ?
        sessionStorage.getItem(draftKey()) : null;
      if (d) input.value = d;
    } catch (e) { /* ignore */ }
  }
  function nextReq() { state.seq += 1; return "web-" + Date.now() + "-" + state.seq; }
  function send(op, body, csrf) {
    if (!state.ws || state.ws.readyState !== 1) return;
    var id = nextReq();
    state.ws.send(JSON.stringify({ v: 1, kind: "command",
      request_id: id, client_id: state.clientId,
      generation: state.generation, csrf: (csrf === undefined ? state.csrf : csrf),
      op: op, body: body || {} }));
    state.awaiting[id] = op;
    var cap = (state.policy && state.policy.outbound_messages) || 0;
    if (cap > 0) {
      var keys = Object.keys(state.awaiting);
      while (keys.length > cap) {
        delete state.awaiting[keys.shift()];
      }
    }
  }
  function bubbleMode(id) {
    var a = bubblesEl.querySelector('[data-bubble-id="' + CSS.escape(id) + '"]');
    return (a && a.dataset.mode) || "standard";
  }
  function bubbleNode(b) {
    var a = document.createElement("article");
    a.dataset.bubbleId = b.id;
    a.dataset.mode = b.mode || "standard";
    var who = document.createElement("strong");
    who.textContent = (b.role === "assistant") ? "hermes" : "you";
    var p = document.createElement("p");
    p.textContent = b.text || "";
    a.appendChild(who); a.appendChild(p);
    if (b.preview_html) {
      var div = document.createElement("div");
      div.textContent = b.preview_html;
      a.appendChild(div);
    }
    if (b.role === "assistant") {
      var btn = document.createElement("button");
      var expanded = a.dataset.mode === "expanded";
      btn.textContent = expanded ? "Collapse" : "Expand";
      btn.dataset.op = "toggle-mode";
      btn.addEventListener("click", function () {
        send("view.set", { bubble_id: b.id,
          mode: expanded ? "standard" : "expanded" });
      });
      a.appendChild(btn);
    }
    return a;
  }
  function postFrame(msg) {
    if (!state.frameReady) return;
    try {
      frame.contentWindow.postMessage(Object.assign(
        { token: state.frameToken, context: state.frameContext }, msg), "*");
    } catch (e) { /* frame not ready; next ready re-syncs */ }
  }
  function forceInit() {
    // Post init without the frameReady gate: after a same-value srcdoc
    // re-mount the frame may not reload (no second "loaded"), so the
    // welcome credentials must also go out on this path. A mid-reload
    // frame drops it harmlessly; its "loaded" triggers the gated init.
    try {
      frame.contentWindow.postMessage({ op: "init",
        token: state.frameToken, context: state.frameContext,
        actions: state.frameActions }, "*");
    } catch (e) { /* next loaded retries */ }
  }
  function renderToFrame(b) {
    var fp = b && b.frame_payload;
    if (!fp || !fp.tree) return;
    if (!state.frameReady) {
      state.pendingRenders.push(b);
      var cap = (state.policy && state.policy.outbound_messages) || 0;
      while (state.pendingRenders.length > cap) state.pendingRenders.shift();
      return;
    }
    postFrame({ op: "render", payload: {
      tree: fp.tree, kind: fp.kind || "text",
      fragment_id: fp.fragment_id || b.id,
      form_values: state.forms[fp.fragment_id || b.id] || {},
      preview: (fp.preview !== false) && bubbleMode(b.id) !== "expanded"
    }});
  }
  function mountFrame() {
    if (!frameDoc || frame.getAttribute("srcdoc") === frameDoc) return;
    state.frameReady = false;
    frame.setAttribute("srcdoc", frameDoc);
  }
  function resetFrame() {
    try { frame.removeAttribute("srcdoc"); } catch (e) {}
    state.frameReady = false;
    state.forms = {};
    state.pendingRenders = [];
    mountFrame();
  }
  function onEvent(ev) {
    var msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    if (typeof msg.event_seq === "number") state.lastSeq = msg.event_seq;
    if (msg.op === "welcome") {
      state.csrf = msg.body.csrf;
      state.clientId = msg.client_id;
      state.generation = msg.generation;
      if (msg.body.client_policy) state.policy = msg.body.client_policy;
      state.frameToken = msg.body.frame_token || null;
      state.frameContext = msg.body.frame_context || null;
      state.frameActions = msg.body.registered_actions || [];
      resetFrame();
      forceInit();
      setStatus("resuming", "");
      send("snapshot", {});
    } else if (msg.op === "snapshot") {
      state.conversationId = msg.body.conversation_id;
      bubblesEl.replaceChildren();
      (msg.body.bubbles || []).forEach(function (b) {
        bubblesEl.appendChild(bubbleNode(b));
        renderToFrame(b);
      });
      drawerEl.replaceChildren();
      ((msg.body.drawer && msg.body.drawer.items) || []).forEach(function (it) {
        var li = document.createElement("li");
        li.textContent = (it.pinned ? "[pinned] " : "") + (it.label || it.id || "item");
        li.dataset.pageId = it.id || "";
        drawerEl.appendChild(li);
      });
      var add = msg.body.drawer && msg.body.drawer.add;
      addEl.hidden = !add;
      addEl.replaceChildren();
      if (add) {
        var p = document.createElement("p");
        p.textContent = add.enabled ? "Add is available." : "Add is not enabled yet.";
        addEl.appendChild(p);
      }
      setStatus("ready", "");
      loadDraft();
      var pend = msg.body.pending || [];
      pend.forEach(function () { /* outcome-unknown: surfaced, never resent */ });
      send("receipt", { event_seq: state.lastSeq }, null);
    } else if (msg.op === "patch" && msg.body.region === "bubbles") {
      (msg.body.items || []).forEach(function (b) {
        var old = bubblesEl.querySelector(
          '[data-bubble-id="' + CSS.escape(b.id) + '"]');
        var node = bubbleNode(b);
        if (old) old.replaceWith(node); else bubblesEl.appendChild(node);
        renderToFrame(b);
      });
      send("receipt", { event_seq: state.lastSeq }, null);
    } else if (msg.op === "patch" && (msg.body.region === "drawer-items" || msg.body.region === "add-content")) {
      send("snapshot", {});
    } else if (msg.op === "outcome") {
      // Only the send that caused an outcome drives the composer.
      // Anything else (receipt acks, broadcast completions for a
      // previous generation) must not clobber the banner: a receipt
      // outcome arriving after backend-unavailable once flipped the
      // shell back to ready.
      var why = msg.request_id ? state.awaiting[msg.request_id] : null;
      if (msg.request_id && state.awaiting[msg.request_id]) {
        delete state.awaiting[msg.request_id];
      }
      var st = msg.body.status;
      if (why !== "chat.send") {
        if ((st === "completed" || st === "outcome-unknown") && !why) {
          // Broadcast for a command this generation never sent
          // (reload mid-send): resync to pick up the durable result.
          send("snapshot", {});
        } else if (why === "view.set" && st === "completed") {
          send("snapshot", {});
        } else if (why && (st === "rejected" || st === "failed")) {
          setStatus("ready", msg.body.code || st);
        }
        return;
      }
      if (st === "accepted") { setStatus("waiting", ""); }
      else if (st === "completed") {
        setStatus("ready", "");
        try { sessionStorage.removeItem(draftKey()); } catch (e) {}
        input.value = "";
      } else if (st === "outcome-unknown") {
        setStatus("uncertain", "not resent; check history");
      } else if (st === "rejected" || st === "failed") {
        setStatus("ready", msg.body.code || st);
      }
    } else if (msg.op === "status") {
      setStatus(msg.body.state === "ready" ? "ready" : "down",
        msg.body.detail || msg.body.state);
      if (msg.body.state === "backend-unavailable") {
        bubblesEl.dataset.stale = "true";
      }
      if (msg.body.state === "reload-required") location.reload();
    }
  }
  function backoffMs() {
    var P = state.policy;
    if (!P) return 0;
    var base = P.reconnect_base_seconds * 1000;
    var cap = P.reconnect_cap_seconds * 1000;
    var attempt = state.attempt++;
    return Math.random() * Math.min(cap, base * Math.pow(P.reconnect_factor, attempt));
  }
  function livedLongEnough() {
    var P = state.policy;
    if (!P || typeof P.reconnect_stable_seconds !== "number") return false;
    return (Date.now() - state.openTime) >= P.reconnect_stable_seconds * 1000;
  }
  function connect() {
    var url = (location.protocol === "https:" ? "wss://" : "ws://") +
      location.host + "/app/ws";
    var ws;
    try { ws = new WebSocket(url, "hermes.web.v1"); } catch (e) {
      setStatus("down", "no socket support"); return;
    }
    state.ws = ws;
    try { window.__chatWs = ws; } catch (e) {}
    ws.addEventListener("open", function () {
      state.openTime = Date.now();
      var tab = null;
      try {
        tab = sessionStorage.getItem("tab_id");
        if (!tab) {
          tab = "tab-" + Math.random().toString(36).slice(2);
          sessionStorage.setItem("tab_id", tab);
        }
      } catch (e) { tab = "tab-ephemeral"; }
      send("attach", { tab_id: tab, release_id: RELEASE_ID,
        cursor_hint: null }, null);
    });
    ws.addEventListener("message", onEvent);
    ws.addEventListener("close", function (ce) {
      try {
        var log = JSON.parse(
          sessionStorage.getItem("chat-close-log") || "[]");
        log.push([Date.now(),
                  String((ce && ce.code) || 0) + "/" +
                  String((ce && ce.reason) || ""),
                  state.generation]);
        while (log.length > 8) log.shift();
        sessionStorage.setItem("chat-close-log", JSON.stringify(log));
        sessionStorage.setItem("chat-last-close",
          String((ce && ce.code) || 0) + "/" +
          String((ce && ce.reason) || ""));
      } catch (e) { /* storage may be unavailable */ }
      if (livedLongEnough()) state.attempt = 0;
      setStatus("down", "reconnecting");
      setTimeout(connect, backoffMs());
    });
    ws.addEventListener("error", function () { ws.close(); });
  }
  composer.addEventListener("submit", function (e) {
    e.preventDefault();
    var text = input.value;
    if (!text.trim() || !state.conversationId) return;
    saveDraft();
    state.pendingText = text;
    send("chat.send", { conversation_id: state.conversationId,
      text: text });
  });
  input.addEventListener("input", saveDraft);
  // Single sandboxed frame host: source-checked bridge, no auth in frame.
  // Frame channel credentials rotate per socket generation; tokenless or
  // stale-context frame events are ignored, never forwarded.
  window.addEventListener("message", function (e) {
    if (e.source !== frame.contentWindow) return;
    var d = e.data;
    if (!d || typeof d.op !== "string") return;
    if (d.op === "ready" || d.op === "loaded" || d.op === "rendered" ||
        d.op === "ok" || d.op === "denied" || d.op === "refused") {
      if (!state.frameReady) {
        state.frameReady = true;
        postFrame({ op: "init", context: state.frameContext,
          token: state.frameToken, actions: state.frameActions });
        var queued = state.pendingRenders;
        state.pendingRenders = [];
        queued.forEach(function (b) { renderToFrame(b); });
      }
      return;
    }
    if (d.op === "resize" && typeof d.height === "number" &&
        isFinite(d.height)) {
      var P = state.policy || {};
      var lo = (typeof P.frame_min_height === "number") ? P.frame_min_height : 0;
      var hi = (typeof P.frame_max_height === "number") ? P.frame_max_height : Number.POSITIVE_INFINITY;
      var h = Math.max(lo, Math.min(hi, d.height));
      frame.style.height = h + "px";
      return;
    }
    if (d.op === "form-state") {
      if (typeof d.fragment_id === "string" && d.values &&
          typeof d.values === "object") {
        state.forms[d.fragment_id] = d.values;
      }
      return;
    }
    if (d.op !== "action-click") return;
    /* effect-bearing actions are forwarded through the validated WS
       path, never executed here. */
    if (d.token !== state.frameToken || d.context !== state.frameContext) return;
    if (!state.conversationId || typeof d.action_id !== "string") return;
    send("action.invoke", { conversation_id: state.conversationId,
      action_id: String(d.action_id), values: {}, context_id: state.clientId,
      expected_revision: 0, confirm: false, frame_token: state.frameToken });
  });
  mountFrame();
  setStatus("down", "connecting");
  connect();
})();
