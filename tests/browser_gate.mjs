// Committed P2 browser gate: re-runnable, zero dependencies (raw CDP only).
//
// Usage:
//   node tests/browser_gate.mjs <page.html> <chrome-bin> <user-data-dir> [port|0]
// Port 0 (or omitted) allocates an isolated ephemeral debug port owned by
// this run; a nonzero port is used as-is after a fail-fast occupancy check.
//
// The page is built by tests/test_browser_gate.py via p2rich.sandbox
// build_page() with a form bubble (focus_target=act-a.submit) and a long
// text bubble (focus_target=nope-missing). This script drives it through
// CDP exactly like the independent harness (site isolation disabled only
// to expose the opaque frame context; sandbox + CSP stay active) and
// asserts: legitimate render/bridge positive controls, wrong
// token/context/op/action negatives, JS schema negatives (URL asset,
// unknown component, on* prop, kind mismatch), fetch/websocket/form/top-nav
// denials with no destination request, live expand/collapse with focus
// restoration, typed-value round-trip, preview bounds, and parent
// containment after an own-frame navigation attempt.
//
// Exit 0 = all gates pass. Any FAIL prints and exits 1.
import { spawn } from 'node:child_process';

const [pagePath, chromeBin, userDir, portArg] = process.argv.slice(2);
// Port 0 (or omitted) = ephemeral: chrome picks a free debug port and this
// script learns it from OUR child's stderr, so parallel/repeated runs can
// never share (or steal) a stale browser. A nonzero port keeps the old
// behaviour but fails fast if something already listens on it.
let port = Number(portArg || 0);
if (!pagePath || !chromeBin || !userDir) {
  console.log('usage: node browser_gate.mjs <page.html> <chrome-bin> <user-data-dir> [port|0]');
  process.exit(2);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const failures = [];
function gate(name, cond, extra) {
  if (cond) console.log('PASS ' + name);
  else { console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + extra : '')); failures.push(name); }
}

function spawnChrome(debugPort) {
  const c = spawn(chromeBin, ['--headless', '--no-sandbox',
    '--disable-site-isolation-trials',
    '--disable-features=IsolateOrigins,site-per-process',
    '--remote-debugging-port=' + debugPort, '--remote-allow-origins=*',
    '--user-data-dir=' + userDir, 'about:blank'],
    { stdio: ['ignore', 'ignore', 'pipe'] });
  c.on('error', () => {});
  c.stderr.on('data', (d) => process.stderr.write(d));
  return c;
}
// Ephemeral-port discovery: the "DevTools listening on ws://...:PORT/..."
// line comes from our own child's stderr, so the port is provably ours.
function waitForDevToolsPort(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const done = (fn, v) => { clearTimeout(t); child.stderr.off('data', onData); fn(v); };
    const t = setTimeout(() => done(reject,
      Error('devtools-port-timeout :: ' + buf.slice(-300))), timeoutMs);
    const onData = (d) => {
      buf += String(d);
      const m = buf.match(/DevTools listening on ws:\/\/[^\s:]+:(\d+)\//);
      if (m) done(resolve, Number(m[1]));
    };
    child.stderr.on('data', onData);
    child.on('error', (e) => done(reject, e));
    child.on('exit', (code) => done(reject,
      Error('chrome-exited-early:' + code + ' :: ' + buf.slice(-300))));
  });
}
async function assertPortFree(p) {
  try {
    const r = await fetch('http://127.0.0.1:' + p + '/json/version');
    if (r.ok) throw Error('debug port ' + p + ' already owned by another browser; refusing to attach');
  } catch (e) {
    if (String(e && e.message || e).includes('already owned')) throw e;
    // connection refused = free, as required
  }
}
let chrome = null;
async function cleanup() {
  try { if (ws && ws.readyState === 1) ws.close(); } catch {}
  await sleep(200);
  if (chrome && chrome.exitCode === null) {
    chrome.kill('SIGTERM');
    await new Promise((r) => {
      const t = setTimeout(r, 5000);
      chrome.once('exit', () => { clearTimeout(t); r(); });
    });
    if (chrome.exitCode === null) {
      try { chrome.kill('SIGKILL'); } catch {}
      await new Promise((r) => {
        const t = setTimeout(r, 5000);
        chrome.once('exit', () => { clearTimeout(t); r(); });
      });
    }
  }
}
let ws = null;
let exitCode = 1;
try {
  if (!port) {
    chrome = spawnChrome(0);
    port = await waitForDevToolsPort(chrome, 20000);
    console.log('PASS isolated debug port ' + port);
  } else {
    await assertPortFree(port);
    chrome = spawnChrome(port);
  }
  let tabs;
  for (let i = 0; i < 100; i++) {
    try { tabs = await (await fetch('http://127.0.0.1:' + port + '/json')).json(); break; }
    catch { await sleep(100); }
  }
  if (!tabs) throw Error('no debuggable tabs');
  ws = new WebSocket(tabs.find((t) => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    const t = setTimeout(() => rej(Error('ws-open-timeout')), 15000);
    ws.onopen = () => { clearTimeout(t); res(); };
    ws.onerror = (e) => { clearTimeout(t); rej(e); };
  });
  let id = 0; const pending = new Map();
  const netReqs = [];
  ws.onmessage = (e) => {
    let m; try { m = JSON.parse(e.data); } catch { return; }
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    if (m.method === 'Network.requestWillBeSent') netReqs.push(m.params.request.url);
    if (m.method === 'Runtime.executionContextCreated') contexts.push(m.params.context);
  };
  // Every CDP round-trip carries a deadline so a wedged browser fails loudly
  // instead of hanging the gate (and the unittest runner) forever.
  const call = (method, params = {}, timeoutMs = 15000) => new Promise((resolve, reject) => {
    const n = ++id;
    const t = setTimeout(() => {
      if (pending.has(n)) { pending.delete(n); reject(Error('cdp-timeout:' + method)); }
    }, timeoutMs);
    pending.set(n, (x) => {
      clearTimeout(t);
      x.error ? reject(Error(JSON.stringify(x.error))) : resolve(x.result);
    });
    try { ws.send(JSON.stringify({ id: n, method, params })); }
    catch (e) { clearTimeout(t); pending.delete(n); reject(e); }
  });
  const contexts = [];
  await call('Page.enable'); await call('Runtime.enable'); await call('Network.enable');
  await call('Page.bringToFront');
  await call('Page.navigate', { url: 'file://' + pagePath });
  await sleep(900);

  const tree0 = await call('Page.getFrameTree');
  const topId = tree0.frameTree.frame.id;
  const kids0 = tree0.frameTree.childFrames || [];
  gate('single reusable frame', kids0.length === 1, JSON.stringify(kids0.length));
  gate('driving owned browser (top url is our page)',
    tree0.frameTree.frame.url === 'file://' + pagePath,
    tree0.frameTree.frame.url);
  const fid = kids0[0].frame.id;
  const fctx = contexts.findLast((c) => c.auxData?.frameId === fid && c.auxData?.isDefault)?.id;
  const pctx = contexts.findLast((c) => c.auxData?.frameId === topId && c.auxData?.isDefault)?.id;
  gate('frame + parent contexts visible', !!(fctx && pctx));
  const ev = async (expr, ctx = pctx) => {
    const r = await call('Runtime.evaluate',
      { expression: expr, contextId: ctx, awaitPromise: true, returnByValue: true });
    return r.result?.value ?? r.exceptionDetails?.exception?.description ?? r.exceptionDetails;
  };
  const frameUrl = async () =>
    ((await call('Page.getFrameTree')).frameTree.childFrames || [])[0]?.frame.url;

  // --- sandbox + CSP composition ---
  gate('sandbox exactly allow-scripts',
    (await ev("document.querySelector('iframe').getAttribute('sandbox')")) === 'allow-scripts');
  const outerCsp = await ev(
    "document.querySelector('meta[http-equiv=\"Content-Security-Policy\"]').content");
  for (const d of ["default-src 'none'", "connect-src 'none'", "form-action 'none'",
    "object-src 'none'", "base-uri 'none'", "frame-src 'none'", "navigate-to 'none'"])
    gate('outer csp has ' + d, String(outerCsp).includes(d), outerCsp);
  gate('outer csp pins two script hashes + style hash',
    (String(outerCsp).match(/sha256-/g) || []).length === 3, outerCsp);
  const frameCsp = await ev(
    "document.querySelector('meta[http-equiv=\"Content-Security-Policy\"]').content", fctx);
  gate('frame csp pins one script hash',
    (String(frameCsp).match(/sha256-/g) || []).length === 1, frameCsp);
  gate('frame renderer runs (csp composition ok)',
    (await ev("typeof window.__renderTree", fctx)) === 'function');

  // --- bridge: install listener, positive controls ---
  await ev("window.responses=[];addEventListener('message',e=>{if(e.data&&e.data.op==='ready')responses.push(e.data)})");
  const tok = await ev('window.P2_TOKEN');
  const ctxName = await ev('window.P2_CONTEXT');
  const post = async (msg) => {
    await ev(`document.querySelector('iframe').contentWindow.postMessage(${msg},'*')`);
    await sleep(250);
  };
  const lastStatus = async () => {
    const r = await ev('responses[responses.length-1]&&responses[responses.length-1].status');
    await ev('responses=[]');
    return r;
  };
  const M = (o) => JSON.stringify(o).replace(/</g, '\\u003c');
  await post(M({ token: tok, context: ctxName, op: 'render',
    payload: { tree: { component: 'Text', props: { text: 'hello-bridge' }, children: [] },
               kind: 'text', fragment_id: 't1' } }));
  gate('legit render -> rendered', (await lastStatus()) === 'rendered');
  gate('rendered content lands in frame',
    String(await ev("document.getElementById('r').textContent", fctx)).includes('hello-bridge'));
  await ev(`document.querySelector('button[data-action="a.submit"]').click()`);
  await sleep(250);
  gate('legit action -> action-ok',
    String(await ev('responses[responses.length-1]&&responses[responses.length-1].status')).startsWith('action-ok'));
  await ev('responses=[]');

  // --- bridge negatives ---
  await post(M({ token: 'wrong', context: ctxName, op: 'render',
    payload: { tree: { component: 'Text', props: { text: 'x' }, children: [] }, kind: 'text' } }));
  gate('wrong token denied', (await lastStatus()) === 'denied');
  await post(M({ token: tok, context: 'other', op: 'render',
    payload: { tree: { component: 'Text', props: { text: 'x' }, children: [] }, kind: 'text' } }));
  gate('wrong context denied', (await lastStatus()) === 'denied');
  await post(M({ token: tok, context: ctxName, op: 'eval', payload: {} }));
  gate('bad op denied', (await lastStatus()) === 'denied');
  await post(M({ token: tok, context: ctxName, op: 'action', payload: { action_id: 'a.evil' } }));
  gate('unregistered action denied-action', (await lastStatus()) === 'denied-action');

  // --- JS schema negatives (authoritative mirror of clean_node) ---
  const badRender = async (tree, kind) => {
    await post(M({ token: tok, context: ctxName, op: 'render',
      payload: { tree, kind: kind || 'media', fragment_id: 'neg' } }));
    return lastStatus();
  };
  gate('js rejects url asset',
    String(await badRender({ component: 'Media',
      props: { asset_id: 'https://example.com/evil', alt: 'x', media_type: 'image' },
      children: [] })).startsWith('refused:Media.external-url-denied'));
  gate('js rejects unknown component',
    String(await badRender({ component: 'Script', props: {}, children: [] }, 'text'))
      .startsWith('refused:unknown-component'));
  gate('js rejects on* prop',
    String(await badRender({ component: 'Text', props: { text: 'x', onclick: 'evil()' },
      children: [] }, 'text')).startsWith('refused:raw-code-prop-denied'));
  gate('js enforces kind subset',
    String(await badRender({ component: 'Button',
      props: { label: 'x', action_id: 'a', intent: 'assigned' }, children: [] }, 'text'))
      .startsWith('refused:kind-component-denied'));
  gate('direct __renderTree rejects url asset',
    String(await ev("__renderTree({component:'Media',props:{asset_id:'https://example.com/evil',alt:'x',media_type:'image'},children:[]})", fctx))
      .includes('Media.external-url-denied'));
  gate('direct __renderTree renders valid text',
    String(await ev("__renderTree({component:'Text',props:{text:'ok'},children:[]},'text')", fctx))
      .includes('<p class="t">ok</p>'));

  // --- egress denials, no destination request so far ---
  gate('fetch denied',
    String(await ev("fetch('https://example.com/probe').then(()=> 'ALLOWED').catch(e=>'DENIED '+e.message)", fctx))
      .startsWith('DENIED'));
  gate('websocket denied',
    String(await ev("new Promise(r=>{try{let w=new WebSocket('wss://example.com/probe');w.onopen=()=>r('ALLOWED');w.onerror=()=>r('DENIED onerror');setTimeout(()=>r('TIMEOUT'),2000)}catch(e){r('DENIED '+e.message)}})", fctx))
      .startsWith('DENIED'));
  const urlBeforeForm = await frameUrl();
  await ev("(()=>{let f=document.createElement('form');f.action='https://example.com/form';document.body.append(f);f.submit();return 'submit attempted'})()", fctx);
  await sleep(400);
  gate('form submit stays about:srcdoc', (await frameUrl()) === urlBeforeForm);
  gate('no destination request yet',
    !netReqs.some((u) => String(u).includes('example.com')), JSON.stringify(netReqs));

  // --- top navigation blocked by sandbox ---
  const topUrlBefore = tree0.frameTree.frame.url;
  const topNav = await ev(
    "(()=>{try{top.location.href='https://example.com/evil-top';return 'attempted'}catch(e){return 'THREW '+e.name}})()", fctx);
  await sleep(400);
  gate('top navigation throws', String(topNav).startsWith('THREW'),
    String(topNav));
  gate('top url unchanged',
    (await call('Page.getFrameTree')).frameTree.frame.url === topUrlBefore);

  // --- live expand / form / focus / bounds ---
  const bubbles = await ev('window.P2_BUBBLES.map(b=>b.id)');
  gate('bubbles wired', Array.isArray(bubbles) && bubbles.length === 2, JSON.stringify(bubbles));
  gate('parent shows preview articles',
    (await ev("document.querySelectorAll('#bubbles article').length")) === 2);
  const longId = bubbles.find((b) => b !== 'f-form');
  const prevRect = await ev(
    `document.querySelector('article[data-fragment="${longId}"]').getBoundingClientRect().toJSON()`);
  gate('preview physically bounded',
    prevRect && prevRect.width <= 361 && prevRect.height <= 161, JSON.stringify(prevRect));
  const prevHtml = await ev(
    `document.querySelector('article[data-fragment="${longId}"]').innerHTML`);
  gate('preview truncated with explicit expand',
    String(prevHtml).includes('\u2026') &&
    String(prevHtml).includes('data-op="expand"') &&
    String(prevHtml).length < 2000, String(prevHtml).length);
  await ev(`document.getElementById('x-${longId}').click()`);
  await sleep(400);
  gate('expand marks takeover',
    (await ev(`document.querySelector('article[data-fragment="${longId}"]').getAttribute('data-state')`)) === 'expanded');
  gate('expand focuses frame (takeover)',
    (await ev('document.activeElement===document.querySelector("iframe")')) === true);
  gate('expand renders full body in frame',
    String(await ev("document.getElementById('r').textContent", fctx)).length > 10000);

  // form bubble: expand, type, collapse, focus restored, value persists
  await ev("document.getElementById('x-f-form').click()");
  await sleep(400);
  gate('form renders inputs in frame',
    (await ev("!!document.querySelector('input[name=email]')", fctx)) === true);
  await ev(`document.getElementById('act-a.submit').focus()`);
  await ev("(()=>{let i=document.querySelector('input[name=email]');i.value='typed@x.y';i.dispatchEvent(new Event('input',{bubbles:true}));return i.value})()", fctx);
  await sleep(300);
  await ev(`document.querySelector('article[data-fragment="f-form"] button[data-op="collapse"]').click()`);
  await sleep(400);
  gate('collapse restores focus target',
    (await ev('document.activeElement&&document.activeElement.id')) === 'act-a.submit');
  gate('collapse restores preview chrome',
    String(await ev('document.querySelector(\'article[data-fragment="f-form"]\').innerHTML')).includes('data-op="expand"'));
  gate('typed value persists in frame',
    (await ev("document.querySelector('input[name=email]').value", fctx)) === 'typed@x.y');
  await ev("document.getElementById('x-f-form').click()");
  await sleep(400);
  gate('re-expand re-applies typed value',
    String(await ev("document.getElementById('r').innerHTML", fctx)).includes('typed@x.y'));
  // fallback focus path first: collapse the long bubble (its focus_target
  // is missing) so only f-form stays expanded for the trap test below.
  await ev(`(document.querySelector('article[data-fragment="${longId}"] button[data-op="collapse"]')||document.querySelector('article[data-fragment="${longId}"] button[data-op="close"]')).click()`);
  await sleep(400);
  gate('collapse falls back to invoker button',
    (await ev('document.activeElement&&document.activeElement.id')) === ('x-' + longId));
  // focus isolation: Tab on last element wraps to first
  const wrapResult = await ev(`(()=>{
    let art=document.querySelector('article[data-fragment="f-form"]');
    let btns=Array.prototype.slice.call(art.querySelectorAll('button'));
    let frame=document.querySelector('iframe');
    frame.focus();
    let lastOk = document.activeElement===frame;
    document.dispatchEvent(new KeyboardEvent('keydown',{key:'Tab',bubbles:true}));
    return {lastOk, nowFirst: document.activeElement===btns[0]};
  })()`);
  gate('tab trapped inside takeover',
    wrapResult && wrapResult.lastOk && wrapResult.nowFirst, JSON.stringify(wrapResult));

  // --- real expanded-frame action dispatch: a genuine user click INSIDE the
  // frame (not a debugger-injected parent message) must run one registered
  // action; an unregistered id must stay silent.
  await post(M({ token: tok, context: ctxName, op: 'render',
    payload: { tree: { component: 'Button', props: { label: 'submit',
      action_id: 'a.submit', intent: 'assigned' }, children: [] },
      kind: 'form', fragment_id: 'gate-btn' } }));
  await lastStatus();
  await ev('responses=[]');
  await ev('document.querySelector("#r button").click()', fctx);
  await sleep(400);
  gate('frame button click dispatches action-ok',
    String(await ev('responses[responses.length-1]&&responses[responses.length-1].status'))
      .startsWith('action-ok'));
  await ev('responses=[]');
  await post(M({ token: tok, context: ctxName, op: 'render',
    payload: { tree: { component: 'Button', props: { label: 'evil',
      action_id: 'a.evil', intent: 'assigned' }, children: [] },
      kind: 'form', fragment_id: 'gate-btn' } }));
  await lastStatus();
  await ev('responses=[]');
  await ev('document.querySelector("#r button").click()', fctx);
  await sleep(400);
  const evilStatus = await ev('responses[responses.length-1]&&responses[responses.length-1].status');
  gate('frame button unregistered click stays silent (no action-ok)',
    !String(evilStatus).startsWith('action-ok'), String(evilStatus));
  await ev('responses=[]');

  // --- typed state round-trips: number (incl. zero + cleared), text, boolean
  const fieldRender = (name, label, input, value, fid2) => post(M({ token: tok,
    context: ctxName, op: 'render', payload: { tree: { component: 'Field',
      props: Object.assign({ name, label, input, value }, {}), children: [] },
      kind: 'form', fragment_id: fid2 } }));
  const frameInput = () => ev("document.querySelector('#r input').value", fctx);
  await fieldRender('age', 'Age', 'number', 1, 'gate-num');
  await lastStatus();
  await ev("(()=>{let i=document.querySelector('#r input');i.value='42';i.dispatchEvent(new Event('input',{bubbles:true}))})()", fctx);
  await sleep(300);
  await fieldRender('age', 'Age', 'number', 1, 'gate-num');
  await lastStatus();
  gate('numeric typed value survives re-render', (await frameInput()) === '42');
  await ev("(()=>{let i=document.querySelector('#r input');i.value='0';i.dispatchEvent(new Event('input',{bubbles:true}))})()", fctx);
  await sleep(300);
  await fieldRender('age', 'Age', 'number', 1, 'gate-num');
  await lastStatus();
  gate('numeric zero survives re-render', (await frameInput()) === '0');
  await ev("(()=>{let i=document.querySelector('#r input');i.value='';i.dispatchEvent(new Event('input',{bubbles:true}))})()", fctx);
  await sleep(300);
  await fieldRender('age', 'Age', 'number', 1, 'gate-num');
  await lastStatus();
  gate('numeric cleared input stays empty (no stale revert)', (await frameInput()) === '');
  await fieldRender('nick', 'Nick', 'text', 'x', 'gate-text');
  await lastStatus();
  await ev("(()=>{let i=document.querySelector('#r input');i.value='hello';i.dispatchEvent(new Event('input',{bubbles:true}))})()", fctx);
  await sleep(300);
  await fieldRender('nick', 'Nick', 'text', 'x', 'gate-text');
  await lastStatus();
  gate('text typed value survives re-render', (await frameInput()) === 'hello');
  await fieldRender('flag', 'Flag', 'boolean', false, 'gate-bool');
  await lastStatus();
  await ev("document.querySelector('#r input').click()", fctx);
  await sleep(300);
  await fieldRender('flag', 'Flag', 'boolean', false, 'gate-bool');
  await lastStatus();
  gate('boolean toggled checkbox survives re-render',
    (await ev("document.querySelector('#r input').checked", fctx)) === true);

  // --- containment: own-frame navigation attempt must not escape the frame ---
  const bubblesBefore = await ev("document.getElementById('bubbles').innerHTML.length");
  const buttonsBefore = await ev("document.querySelectorAll('button').length");
  await ev("(()=>{location.href='https://example.com/navigation';return 'attempted'})()", fctx);
  await sleep(1500);
  gate('parent bubbles intact after nav attempt',
    (await ev("document.getElementById('bubbles').innerHTML.length")) === bubblesBefore);
  gate('parent buttons intact after nav attempt',
    (await ev("document.querySelectorAll('button').length")) === buttonsBefore);
  gate('top url unchanged after nav attempt',
    (await call('Page.getFrameTree')).frameTree.frame.url === topUrlBefore);

  console.log(failures.length ? `GATE FAIL ${failures.length}` : 'GATE OK');
  exitCode = failures.length ? 1 : 0;
} catch (e) {
  console.log('ERROR ' + String(e && e.stack || e).slice(0, 500));
  exitCode = 1;
}
// Guaranteed cleanup on every path (success/error/timeout): the browser this
// run owns is closed and reaped BEFORE exit, so no gate Chrome ever lingers
// on the debug port. process.exit runs only after cleanup is awaited.
await cleanup();
process.exit(exitCode);
