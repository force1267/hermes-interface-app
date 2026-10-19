/* Thin transport shim. No rendering policy, no page data channel.
   One socket only: the /app/ws transport. Drafts stay
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
  var state = { ws: null, csrf: null, clientId: null, generation: 0,
    seq: 0, conversationId: null, pendingText: null, attempt: 0 };

  function setStatus(s, detail) {
    statusEl.textContent = s + (detail ? ": " + detail : "");
    statusEl.dataset.state = (s === "ready") ? "up" : "down";
    sendBtn.disabled = (s !== "ready");
  }
  function draftKey() {
    return "draft:" + state.conversationId;
  }
  function saveDraft() {
    try {
      if (state.conversationId && input.value)
        sessionStorage.setItem(draftKey(), input.value.slice(0, 65536));
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
    state.ws.send(JSON.stringify({ v: 1, kind: "command",
      request_id: nextReq(), client_id: state.clientId,
      generation: state.generation, csrf: (csrf === undefined ? state.csrf : csrf),
      op: op, body: body || {} }));
  }
  function bubbleNode(b) {
    var a = document.createElement("article");
    a.dataset.bubbleId = b.id;
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
    return a;
  }
  function onEvent(ev) {
    var msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    if (msg.op === "welcome") {
      state.csrf = msg.body.csrf;
      state.clientId = msg.client_id;
      state.generation = msg.generation;
      setStatus("resuming", "");
      send("snapshot", {});
    } else if (msg.op === "snapshot") {
      state.conversationId = msg.body.conversation_id;
      bubblesEl.replaceChildren();
      (msg.body.bubbles || []).forEach(function (b) {
        bubblesEl.appendChild(bubbleNode(b));
      });
      drawerEl.replaceChildren();
      (msg.body.drawer && msg.body.drawer.items || []).forEach(function (it) {
        var li = document.createElement("li");
        li.textContent = it.label || it.id || "item";
        drawerEl.appendChild(li);
      });
      setStatus("ready", "");
      loadDraft();
      var pend = msg.body.pending || [];
      pend.forEach(function () { /* outcome-unknown: surfaced, never resent */ });
    } else if (msg.op === "patch" && msg.body.region === "bubbles") {
      (msg.body.items || []).forEach(function (b) {
        var old = bubblesEl.querySelector(
          '[data-bubble-id="' + CSS.escape(b.id) + '"]');
        var node = bubbleNode(b);
        if (old) old.replaceWith(node); else bubblesEl.appendChild(node);
      });
    } else if (msg.op === "outcome") {
      var st = msg.body.status;
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
  function backoff() {
    var base = 1000, cap = 30000, attempt = state.attempt++;
    return Math.min(cap, base * Math.pow(2, attempt)) * (0.5 + Math.random() * 0.5);
  }
  function connect() {
    var url = (location.protocol === "https:" ? "wss://" : "ws://") +
      location.host + "/app/ws";
    var ws;
    try { ws = new WebSocket(url, "hermes.web.v1"); } catch (e) {
      setStatus("down", "no socket support"); return;
    }
    state.ws = ws;
    ws.addEventListener("open", function () {
      state.attempt = 0;
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
    ws.addEventListener("close", function () {
      setStatus("down", "reconnecting");
      setTimeout(connect, backoff());
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
  window.addEventListener("message", function (e) {
    if (e.source !== frame.contentWindow) return;
    var d = e.data;
    if (!d || typeof d.op !== "string") return;
    if (["render", "action", "resize", "ready", "form-state"].indexOf(d.op) < 0) return;
    /* frame events are typed bridge events; effect-bearing actions are
       forwarded through the validated WS path, never executed here. */
    if (d.op === "action" && d.action_id && state.conversationId) {
      send("action.invoke", { conversation_id: state.conversationId,
        action_id: String(d.action_id), values: d.values || {},
        context_id: state.clientId, expected_revision: d.revision || 0,
        confirm: !!d.confirm });
    } else if (d.op === "resize" && typeof d.height === "number" &&
        isFinite(d.height)) {
      var h = Math.max(80, Math.min(800, d.height));
      frame.style.height = h + "px";
    }
  });
  setStatus("down", "connecting");
  connect();
})();
