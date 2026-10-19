/* Thin transport shim. No rendering policy, no page data channel.
   One socket only: the /app/ws transport. All operational thresholds
   (draft bound, reconnect backoff, frame clamp, close-log retention,
   frame ready timeout) arrive in the welcome client_policy; this file
   owns no numeric policy of its own. Drafts stay in
   sessionStorage (account+conversation scoped, never credentials). */
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
    seq: 0, conversationId: null, attempt: 0,
    openTime: 0, policy: null, frameToken: null, frameContext: null,
    frameActions: [], frameReady: false, forms: {}, lastSeq: 0,
    pendingRenders: [], pending: {}, knownFragments: {},
    wasDown: false, frameTimer: null, fenceIgnored: 0 };

  function setStatus(s, detail) {
    statusEl.textContent = s + (detail ? ": " + detail : "");
    statusEl.dataset.state = (s === "ready") ? "up" : "down";
    sendBtn.disabled = (s !== "ready");
  }
  function draftKey() {
    return "draft:" + state.conversationId;
  }
  function doneKey() {
    // Single-use marker for the exact text that already completed, so a
    // completion that lands before its snapshot resync cannot resurrect
    // the sent prompt as a draft. Consumed by the next loadDraft.
    return "draftDone:" + state.conversationId;
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
      var done = state.conversationId ?
        sessionStorage.getItem(doneKey()) : null;
      if (done !== null) {
        // Consume the marker: it covers exactly one snapshot race.
        // A genuinely retyped identical draft is saved fresh by input
        // events afterwards and must load normally next time.
        sessionStorage.removeItem(doneKey());
        var cur = state.conversationId ?
          sessionStorage.getItem(draftKey()) : null;
        if (cur === done) {
          try { sessionStorage.removeItem(draftKey()); } catch (e2) {}
          return;
        }
        if (cur) input.value = cur;
        return;
      }
      var d = state.conversationId ?
        sessionStorage.getItem(draftKey()) : null;
      if (d) input.value = d;
    } catch (e) { /* ignore */ }
  }
  // The sent text that completed: clear the composer and the stored
  // draft only when they still hold exactly that text. Anything newer
  // the user typed is an unsent draft and is preserved.
  function noteCompletedText(done) {
    if (typeof done !== "string" || !done) return;
    try {
      if (state.conversationId) {
        if (sessionStorage.getItem(draftKey()) === done) {
          sessionStorage.removeItem(draftKey());
        }
        sessionStorage.setItem(doneKey(), done);
      }
    } catch (e) { /* ignore */ }
    if (input.value === done) input.value = "";
  }
  function nextReq() { state.seq += 1; return "web-" + Date.now() + "-" + state.seq; }
  function send(op, body, csrf) {
    if (!state.ws || state.ws.readyState !== 1) return;
    var id = nextReq();
    state.ws.send(JSON.stringify({ v: 1, kind: "command",
      request_id: id, client_id: state.clientId,
      generation: state.generation, csrf: (csrf === undefined ? state.csrf : csrf),
      op: op, body: body || {} }));
    state.pending[id] = { op: op };
    var cap = (state.policy && state.policy.outbound_messages) || 0;
    if (cap > 0) {
      var keys = Object.keys(state.pending);
      while (keys.length > cap) {
        delete state.pending[keys.shift()];
      }
    }
  }
  function fenceFail() {
    // Ignored frame event (wrong channel or unknown surface). Counted
    // for the confinement gate; never forwarded, never rendered.
    state.fenceIgnored += 1;
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
  function trackFragment(b) {
    var fp = b && b.frame_payload;
    if (fp && typeof fp.fragment_id === "string" && fp.fragment_id) {
      state.knownFragments[fp.fragment_id] = 1;
    }
  }
  function postFrame(msg) {
    if (!state.frameReady) return;
    try {
      frame.contentWindow.postMessage(Object.assign(
        { token: state.frameToken, context: state.frameContext }, msg), "*");
    } catch (e) { /* frame not ready; next ready re-syncs */ }
  }
  function forceInit() {
    // Post init without the frameReady gate: after an in-place welcome
    // (same srcdoc, no reload) there is no second "loaded", so the
    // rotated credentials must also go out on this path. A mid-reload
    // frame drops it harmlessly; its "loaded" triggers the gated init.
    // Null credentials pre-welcome are ignored by the frame; the real
    // welcome re-inits.
    try {
      frame.contentWindow.postMessage({ op: "init",
        token: state.frameToken, context: state.frameContext,
        actions: state.frameActions }, "*");
    } catch (e) { /* next loaded retries */ }
  }
  function renderJob(b) {
    var fp = b.frame_payload;
    postFrame({ op: "render", payload: {
      tree: fp.tree, kind: fp.kind || "text",
      fragment_id: fp.fragment_id || b.id,
      form_values: state.forms[fp.fragment_id || b.id] || {},
      preview: (fp.preview !== false) && bubbleMode(b.id) !== "expanded"
    }});
  }
  function renderToFrame(b) {
    var fp = b && b.frame_payload;
    if (!fp || !fp.tree) return;
    trackFragment(b);
    if (!state.frameReady) {
      state.pendingRenders.push(b);
      var cap = (state.policy && state.policy.outbound_messages) || 0;
      while (state.pendingRenders.length > cap) state.pendingRenders.shift();
      return;
    }
    renderJob(b);
  }
  function armFrameTimer() {
    if (state.frameTimer) {
      try { clearTimeout(state.frameTimer); } catch (e) {}
      state.frameTimer = null;
    }
    var P = state.policy;
    var t = (P && typeof P.frame_ready_timeout_seconds === "number") ?
      P.frame_ready_timeout_seconds : 0;
    if (!(t > 0)) return;
    state.frameTimer = setTimeout(function () {
      state.frameTimer = null;
      if (!state.frameReady) {
        // A fresh frame document never signalled: retry the init once
        // and mark the mount degraded. Parent text already shows the
        // answers; the next "loaded" clears the mark and re-syncs.
        forceInit();
        try { frame.dataset.degraded = "no-frame-ready"; } catch (e2) {}
      }
    }, t * 1000);
  }
  function mountFrame() {
    if (!frameDoc || frame.getAttribute("srcdoc") === frameDoc) return;
    state.frameReady = false;
    frame.setAttribute("srcdoc", frameDoc);
  }
  function resetFrame() {
    // Stable mount: the srcdoc bytes are identical across welcomes, so
    // rewriting them would only risk a second navigation racing the
    // frame's load signal. Only a changed bundle remounts; credential
    // rotation re-inits in place via forceInit.
    if (!frameDoc || frame.getAttribute("srcdoc") !== frameDoc) {
      try { frame.removeAttribute("srcdoc"); } catch (e) {}
      state.frameReady = false;
      mountFrame();
    }
    state.forms = {};
    state.pendingRenders = [];
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
      armFrameTimer();
      forceInit();
      setStatus("resuming", "");
      send("snapshot", {});
    } else if (msg.op === "snapshot") {
      state.conversationId = msg.body.conversation_id;
      bubblesEl.replaceChildren();
      state.knownFragments = {};
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
      // Atomic honesty: the snapshot carries the backend bit, so a
      // reload while dead never flashes ready before the status event.
      var alive = (msg.body.backend_alive !== false);
      if (alive) {
        state.wasDown = false;
        setStatus("ready", "");
        try { bubblesEl.dataset.stale = ""; } catch (e) {}
      } else {
        state.wasDown = true;
        setStatus("backend-unavailable", "cached history; backend unreachable");
        try { bubblesEl.dataset.stale = "true"; } catch (e2) {}
      }
      loadDraft();
      var pend = msg.body.pending || [];
      pend.forEach(function () { /* outcome-unknown: surfaced, never resent */ });
      send("receipt", { event_seq: state.lastSeq }, null);
    } else if (msg.op === "patch" && msg.body.region === "bubbles") {
      (msg.body.items || []).forEach(function (b) {
        trackFragment(b);
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
      // Correlation survives accepted: only a terminal outcome for the
      // exact request we sent drives the composer. Anything else is a
      // broadcast (reload mid-send) that resyncs, never replays.
      var why = msg.request_id ? state.pending[msg.request_id] : null;
      if (why) {
        delete state.pending[msg.request_id];
      }
      var st = msg.body.status;
      if (msg.body && typeof msg.body.sent_text === "string") {
        noteCompletedText(msg.body.sent_text);
      }
      if (!why || why.op !== "chat.send") {
        if (!why && (st === "completed" || st === "outcome-unknown")) {
          // Broadcast for a command this generation never sent
          // (reload mid-send): resync to pick up the durable result.
          send("snapshot", {});
        } else if (why && why.op === "view.set" && st === "completed") {
          send("snapshot", {});
        } else if (why && (st === "rejected" || st === "failed")) {
          setStatus("ready", msg.body.code || st);
        }
        // Receipt and other non-send outcomes never touch the banner:
        // a receipt ack landing after backend-unavailable once flipped
        // the shell back to ready.
        return;
      }
      if (st === "accepted") { setStatus("waiting", ""); }
      else if (st === "completed") { setStatus("ready", ""); }
      else if (st === "outcome-unknown") {
        setStatus("uncertain", "not resent; check history");
      } else if (st === "rejected" || st === "failed") {
        setStatus("ready", msg.body.code || st);
      }
    } else if (msg.op === "status") {
      if (msg.body.state === "reload-required") { location.reload(); return; }
      if (msg.body.state === "ready") {
        var recovered = state.wasDown;
        state.wasDown = false;
        setStatus("ready", "");
        try { bubblesEl.dataset.stale = ""; } catch (e) {}
        // Death pushed while idle; recovery pushes ready. Resync
        // without reload and without regenerating answers.
        if (recovered) send("snapshot", {});
        return;
      }
      if (msg.body.state === "backend-unavailable") {
        state.wasDown = true;
        setStatus("backend-unavailable", msg.body.detail || msg.body.state);
        try { bubblesEl.dataset.stale = "true"; } catch (e2) {}
        return;
      }
      setStatus("down", msg.body.detail || msg.body.state);
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
        var P = state.policy;
        var cap = (P && typeof P.close_log_entries === "number" &&
          P.close_log_entries > 0) ? P.close_log_entries : 32;
        var log = JSON.parse(
          sessionStorage.getItem("chat-close-log") || "[]");
        log.push([Date.now(),
                  String((ce && ce.code) || 0) + "/" +
                  String((ce && ce.reason) || ""),
                  state.generation]);
        while (log.length > cap) log.shift();
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
    send("chat.send", { conversation_id: state.conversationId,
      text: text });
  });
  input.addEventListener("input", saveDraft);
  // Single sandboxed frame host: source-checked bridge, no auth in frame.
  // Frame channel credentials rotate per socket generation; tokenless,
  // context-stale, or unknown-surface frame events are ignored, never
  // forwarded. Server-consumed actions forward with their fragment id
  // for domain validation there; parent-consumed ops (resize,
  // form-state) are fenced here.
  window.__chatFenceIgnored = function () { return state.fenceIgnored; };
  window.addEventListener("message", function (e) {
    if (e.source !== frame.contentWindow) return;
    var d = e.data;
    if (!d || typeof d.op !== "string") return;
    if (d.op === "ready") {
      var rst = d.status;
      if (rst === "loaded") {
        // Fresh frame document: credential it, then deliver everything
        // queued while it loaded. Every load re-inits; a stale ready
        // flag can never strand the channel again.
        state.frameReady = true;
        if (state.frameTimer) {
          try { clearTimeout(state.frameTimer); } catch (e2) {}
          state.frameTimer = null;
        }
        try { frame.removeAttribute("data-degraded"); } catch (e3) {}
        postFrame({ op: "init", context: state.frameContext,
          token: state.frameToken, actions: state.frameActions });
        var queued = state.pendingRenders;
        state.pendingRenders = [];
        queued.forEach(function (b) { renderToFrame(b); });
        return;
      }
      if (!state.frameReady) {
        state.frameReady = true;
        postFrame({ op: "init", context: state.frameContext,
          token: state.frameToken, actions: state.frameActions });
        var q2 = state.pendingRenders;
        state.pendingRenders = [];
        q2.forEach(function (b) { renderToFrame(b); });
        return;
      }
      if (state.frameToken && typeof rst === "string" &&
          (rst === "denied" || rst.indexOf("denied") === 0 ||
           rst === "refused" || rst.indexOf("refused") === 0)) {
        // A render was refused after ready (rotated channel, raced
        // mount): re-init once; the init reply itself never re-triggers.
        postFrame({ op: "init", context: state.frameContext,
          token: state.frameToken, actions: state.frameActions });
      }
      return;
    }
    if (d.op === "resize" && typeof d.height === "number" &&
        isFinite(d.height)) {
      if (d.token !== state.frameToken || d.context !== state.frameContext) {
        fenceFail();
        return;
      }
      var P = state.policy || {};
      var lo = (typeof P.frame_min_height === "number") ? P.frame_min_height : 0;
      var hi = (typeof P.frame_max_height === "number") ? P.frame_max_height : Number.POSITIVE_INFINITY;
      var h = Math.max(lo, Math.min(hi, d.height));
      frame.style.height = h + "px";
      return;
    }
    if (d.op === "form-state") {
      if (d.token !== state.frameToken || d.context !== state.frameContext ||
          typeof d.fragment_id !== "string" ||
          !state.knownFragments[d.fragment_id] || !d.values ||
          typeof d.values !== "object") {
        fenceFail();
        return;
      }
      state.forms[d.fragment_id] = d.values;
      return;
    }
    if (d.op !== "action-click") return;
    /* effect-bearing actions are forwarded through the validated WS
       path, never executed here. */
    if (d.token !== state.frameToken || d.context !== state.frameContext) {
      fenceFail();
      return;
    }
    if (!state.conversationId || typeof d.action_id !== "string") return;
    send("action.invoke", { conversation_id: state.conversationId,
      action_id: String(d.action_id), values: {},
      fragment_id: (typeof d.fragment_id === "string") ? d.fragment_id : null,
      context_id: state.clientId,
      expected_revision: 0, confirm: false, frame_token: state.frameToken });
  });
  mountFrame();
  setStatus("down", "connecting");
  connect();
})();
