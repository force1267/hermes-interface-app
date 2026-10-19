// P5 real-browser gate: drives the served shell through real Chrome over
// CDP with zero dependencies (raw CDP only, like tests/browser_gate.mjs).
//
// Usage:
//   node tests/p5_browser_gate.mjs <baseUrl> <chromeBin> <userDir> <mode> <nonce> <outJson> [password]
// mode full: login, send nonce chat, DOM bubble, frame bridge, net capture.
// mode deadbackend: shell paints, send disabled, banner, draft retained.
//
// Exit 0 = gate ran (report JSON carries pass/fail details); exit 1 = harness error.
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const [baseUrl, chromeBin, userDir, mode, nonce, outPath, password] = process.argv.slice(2);
const report = { mode, baseUrl, checks: {}, netUrls: [], errors: [] };
function check(name, cond, extra) {
  report.checks[name] = cond ? 'pass' : 'fail' + (extra !== undefined ? ' :: ' + extra : '');
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function spawnChrome(debugPort) {
  const c = spawn(chromeBin, ['--headless', '--no-sandbox',
    '--remote-debugging-port=' + debugPort, '--remote-allow-origins=*',
    '--user-data-dir=' + userDir, 'about:blank'],
    { stdio: ['ignore', 'ignore', 'pipe'] });
  c.on('error', () => {});
  c.stderr.on('data', (d) => process.stderr.write(d));
  return c;
}
function waitForDevToolsPort(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const done = (fn, v) => { clearTimeout(t); child.stderr.off('data', onData); fn(v); };
    const t = setTimeout(() => done(reject, Error('devtools-port-timeout :: ' + buf.slice(-300))), timeoutMs);
    const onData = (d) => {
      buf += String(d);
      const m = buf.match(/DevTools listening on ws:\/\/[^\s:]+:(\d+)\//);
      if (m) done(resolve, Number(m[1]));
    };
    child.stderr.on('data', onData);
    child.on('error', (e) => done(reject, e));
    child.on('exit', (code) => done(reject, Error('chrome-exited-early:' + code)));
  });
}

let chrome = null, ws = null;
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
    }
  }
}

try {
  chrome = spawnChrome(0);
  const port = await waitForDevToolsPort(chrome, 20000);
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
  let id = 0; const pending = new Map(); const contexts = [];
  const netReqs = []; const docHeaders = {}; const wsUrls = []; const wsFrames = [];
  const debugPort = port;
  ws.onmessage = (e) => {
    let m; try { m = JSON.parse(e.data); } catch { return; }
    try {
      const key = (m.sessionId || '') + ':' + m.id;
      if (m.id !== undefined && pending.has(key)) { pending.get(key)(m); pending.delete(key); return; }
    } catch { return; }
    if (m.method === 'Network.requestWillBeSent') netReqs.push(m.params.request.url);
    if (m.method === 'Network.webSocketCreated') wsUrls.push(m.params.url);
    if (m.method === 'Network.webSocketFrameReceived' && m.params.response && typeof m.params.response.payloadData === 'string') wsFrames.push(m.params.response.payloadData);
    if (m.method === 'Network.responseReceived' && m.params.type === 'Document') {
      docHeaders[m.params.response.url] = m.params.response.headers;
    }
    if (m.method === 'Runtime.executionContextCreated') contexts.push(m.params.context);
  };
  const call = (method, params = {}, timeoutMs = 15000) => new Promise((resolve, reject) => {
    const n = ++id;
    const t = setTimeout(() => { if (pending.has(':' + n)) { pending.delete(':' + n); reject(Error('cdp-timeout:' + method)); } }, timeoutMs);
    pending.set(':' + n, (x) => { clearTimeout(t); x.error ? reject(Error(JSON.stringify(x.error))) : resolve(x.result); });
    try { ws.send(JSON.stringify({ id: n, method, params })); }
    catch (e) { clearTimeout(t); pending.delete(':' + n); reject(e); }
  });
  const callSess = (sessionId, method, params = {}, timeoutMs = 15000) => new Promise((resolve, reject) => {
    const n = ++id;
    const key = sessionId + ':' + n;
    const t = setTimeout(() => { if (pending.has(key)) { pending.delete(key); reject(Error('cdp-timeout:' + method)); } }, timeoutMs);
    pending.set(key, (x) => { clearTimeout(t); x.error ? reject(Error(JSON.stringify(x.error))) : resolve(x.result); });
    try { ws.send(JSON.stringify({ id: n, sessionId, method, params })); }
    catch (e) { clearTimeout(t); pending.delete(key); reject(e); }
  });
  // Evaluate inside the sandboxed OOPIF via its own CDP target session.
  // The opaque-origin srcdoc frame runs out-of-process, so the page
  // target cannot evaluate in it directly.
  const evFrame = async (expr) => {
    let lastErr = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const tabs = await (await fetch('http://127.0.0.1:' + debugPort + '/json')).json();
        const cands = tabs.filter((t) => t.type === 'iframe' && (t.url || '').indexOf('about:srcdoc') === 0);
        if (!cands.length) throw Error('no-iframe-target');
        for (let ci = cands.length - 1; ci >= 0; ci--) {
          const a = await call('Target.attachToTarget', { targetId: cands[ci].id, flatten: true });
          const sid = a.sessionId;
          try {
            const r = await callSess(sid, 'Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
            if (r && r.exceptionDetails) { lastErr = Error('frame-exc'); continue; }
            return (r && r.result && ('value' in r.result)) ? r.result.value : null;
          } catch (e) { lastErr = e; }
          finally {
            try { await call('Target.detachFromTarget', { sessionId: sid }); } catch {}
          }
        }
        throw lastErr || Error('no-live-iframe-target');
      } catch (e) {
        lastErr = e;
        await sleep(1000);
      }
    }
    throw lastErr;
  };
  // Persistent frame session for polls: attach once, evaluate many times,
  // re-attach when the frame navigates. Returns {read} and {post}.
  const frameLink = async () => {
    const tabs = await (await fetch('http://127.0.0.1:' + debugPort + '/json')).json();
    const cands = tabs.filter((t) => t.type === 'iframe' && (t.url || '').indexOf('about:srcdoc') === 0);
    if (!cands.length) throw Error('no-iframe-target');
    const a = await call('Target.attachToTarget', { targetId: cands[cands.length - 1].id, flatten: true });
    const sid = a.sessionId;
    let alive = true;
    const run = async (expr) => {
      const r = await callSess(sid, 'Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
      if (r && r.exceptionDetails) throw Error('frame-exc');
      return (r && r.result && ('value' in r.result)) ? r.result.value : null;
    };
    return {
      read: run,
      close: async () => { if (alive) { alive = false; try { await call('Target.detachFromTarget', { sessionId: sid }); } catch {} } },
    };
  };
  await call('Page.enable'); await call('Runtime.enable'); await call('Network.enable');
  const jsErrors = [];
  ws.addEventListener('message', (e) => {
    let m; try { m = JSON.parse(e.data); } catch { return; }
    if (m.method === 'Runtime.exceptionThrown') jsErrors.push(JSON.stringify(m.params.exceptionDetails).slice(0, 300));
    if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error') jsErrors.push(m.params.entry.text.slice(0, 300));
  });
  await call('Log.enable').catch(() => {});
  const ev = async (expr, ctx) => {
    const p = { expression: expr, awaitPromise: true, returnByValue: true };
    if (ctx) p.contextId = ctx;
    const r = await call('Runtime.evaluate', p);
    return r.result?.value ?? r.exceptionDetails?.exception?.description ?? r.exceptionDetails;
  };
  const navLoad = async (url) => {
    const fired = new Promise((res) => {
      const h = (e) => {
        let m; try { m = JSON.parse(e.data); } catch { return; }
        if (m.method === 'Page.loadEventFired') { ws.removeEventListener('message', h); res(); }
      };
      ws.addEventListener('message', h);
      setTimeout(() => { try { ws.removeEventListener('message', h); } catch {} res(); }, 15000);
    });
    await call('Page.navigate', { url });
    await fired;
    await sleep(700);
  };
  const frameTree = async () => (await call('Page.getFrameTree')).frameTree;
  const frameCtx = async (frameId) => {
    for (let i = 0; i < 20; i++) {
      const c = contexts.findLast((c) => c.auxData?.frameId === frameId && c.auxData?.isDefault);
      if (c) return c.id;
      await sleep(200);
    }
    return null;
  };

  // --- login via native form POST (no fetch/XHR; same path as curl) ---
  await navLoad(baseUrl + '/app/ws');
  const loginHtml = await ev('document.documentElement.outerHTML');
  const csrfM = String(loginHtml).match(/name="csrf" value="([^"]+)"/);
  check('login page carries challenge', !!csrfM);
  if (!csrfM) throw Error('no login challenge');
  await ev(`(function(){
    var f = document.createElement('form');
    f.method = 'POST'; f.action = '/app/ws';
    var fields = {op:'login', username:'mj', password:${JSON.stringify(password || 'correct-horse')}, csrf:${JSON.stringify(csrfM[1])}};
    for (var k in fields) { var i = document.createElement('input'); i.name = k; i.value = fields[k]; f.appendChild(i); }
    document.body.appendChild(f); f.submit();
  })()`);
  await sleep(1500);
  try {
    const jar = await call('Storage.getCookies', { urls: [baseUrl + '/'] });
    report.cookies = (jar.cookies || []).map((c) => c.name + '|secure=' + c.secure + '|httpOnly=' + c.httpOnly);
  } catch (e) { report.cookies = ['cookie-read-error:' + e.message]; }
  // --- shell ---
  await navLoad(baseUrl + '/');
  const hasIds = await ev(`["app-shell","composer","connection-status","bubbles","drawer-items","add-content","frag-frame"].map((x) => !!document.getElementById(x)).join(',')`);
  const shellPaints = hasIds === 'true,true,true,true,true,true,true';
  check('shell paints with all mount IDs', shellPaints, hasIds);
  report.resources = await ev(`performance.getEntriesByType('resource').map((r) => r.name + ':' + r.responseStatus).join(' | ')`);
  report.jsErrors = jsErrors;
  report.csp = docHeaders[baseUrl + '/'] || docHeaders[baseUrl] || null;
  if (mode === 'deadbackend') {
    const waitReadyish = async () => {
      for (let i = 0; i < 60; i++) {
        const s = String(await ev(`document.getElementById('connection-status').textContent`));
        if (/unavailable/i.test(s)) return s;
        await sleep(1000);
      }
      return String(await ev(`document.getElementById('connection-status').textContent`));
    };
    const status = await waitReadyish();
    check('dead backend banner, no fabricated chat', /down|unavailable/i.test(status), status);
    const disabled = await ev(`document.getElementById('composer-send').disabled`);
    check('send disabled while backend down', disabled === true, String(disabled));
    const bubbleCount = await ev(`document.querySelectorAll('#bubbles article').length`);
    check('no chat bubbles on dead backend', bubbleCount === 0, String(bubbleCount));
    await ev(`document.getElementById('composer-input').value = 'DRAFT-KEEP-DEAD'; document.getElementById('composer-input').dispatchEvent(new Event('input', {bubbles:true}));`);
    await navLoad(baseUrl + '/');
    for (let i = 0; i < 60; i++) {
      const s = String(await ev(`document.getElementById('connection-status').textContent`));
      if (/unavailable/i.test(s)) break;
      await sleep(1000);
    }
    const draft = await ev(`document.getElementById('composer-input').value`);
    check('draft retained across reload on dead backend', draft === 'DRAFT-KEEP-DEAD', String(draft).slice(0, 40));
  } else if (mode === 'restart') {
    // Backend death honesty + draft lifecycle + recovery without
    // reload. The python driver watches outPath+'.control': this mode
    // writes 'stop' / 'start' there and waits for the driver to unlink.
    const { existsSync: fExists } = await import('node:fs');
    const control = outPath + '.control';
    const command = async (op) => {
      writeFileSync(control, op);
      for (let i = 0; i < 300 && fExists(control); i++) await sleep(100);
    };
    const statusNow = async () =>
      String(await ev(`document.getElementById('connection-status').textContent`));
    const waitReadyR = async () => {
      for (let i = 0; i < 90; i++) {
        const s = await statusNow();
        if (s.indexOf('ready') === 0) return s;
        await sleep(1000);
      }
      return statusNow();
    };
    const status0 = await waitReadyR();
    check('initial ready', status0.indexOf('ready') === 0, status0);
    await ev(`document.getElementById('composer-input').value = 'Reply with exactly: ${nonce}'; document.getElementById('composer-send').click();`);
    for (let i = 0; i < 120; i++) {
      const arts = await ev(`Array.from(document.querySelectorAll('#bubbles article')).map((a) => a.querySelector('p') ? a.querySelector('p').textContent : '').join('|')`);
      if (String(arts).indexOf(nonce) >= 0) break;
      await sleep(1000);
    }
    await sleep(2000);
    const history = await ev(`Array.from(document.querySelectorAll('#bubbles article')).map((a) => ({id: a.dataset.bubbleId, role: a.querySelector('strong') ? a.querySelector('strong').textContent : '', text: a.querySelector('p') ? a.querySelector('p').textContent : ''}))`);
    report.historyBefore = history;
    report.draftAfterCompleted = await ev(`document.getElementById('composer-input').value`);
    check('completed send clears draft', report.draftAfterCompleted === '');
    await ev(`document.getElementById('composer-input').value = 'INDEPENDENT-UNSENT-DRAFT'; document.getElementById('composer-input').dispatchEvent(new Event('input', {bubbles:true}));`);
    await command('stop');
    let dead = '', deadDis = false;
    for (let i = 0; i < 40; i++) {
      dead = await statusNow();
      deadDis = await ev(`document.getElementById('composer-send').disabled`);
      if (/unavailable/i.test(dead) && deadDis === true) break;
      await sleep(1000);
    }
    report.deadStatus = dead;
    report.deadDisabled = deadDis;
    check('running backend death detected', /unavailable/i.test(dead) && deadDis === true, dead);
    report.deadHistory = await ev(`Array.from(document.querySelectorAll('#bubbles article')).map((a) => ({id: a.dataset.bubbleId, role: a.querySelector('strong') ? a.querySelector('strong').textContent : '', text: a.querySelector('p') ? a.querySelector('p').textContent : ''}))`);
    check('death does not fabricate or lose last good content', JSON.stringify(report.deadHistory) === JSON.stringify(history));
    await navLoad(baseUrl + '/');
    await sleep(2000);
    report.deadReloadStatus = await statusNow();
    check('reload while dead shows unavailable', /unavailable/i.test(report.deadReloadStatus), report.deadReloadStatus);
    await command('start');
    let back = '';
    for (let i = 0; i < 60; i++) {
      back = await statusNow();
      if (back.indexOf('ready') === 0) break;
      await sleep(1000);
    }
    check('restart returns ready without page reload', back.indexOf('ready') === 0, back);
    await navLoad(baseUrl + '/');
    await waitReadyR();
    report.historyAfter = await ev(`Array.from(document.querySelectorAll('#bubbles article')).map((a) => ({id: a.dataset.bubbleId, role: a.querySelector('strong') ? a.querySelector('strong').textContent : '', text: a.querySelector('p') ? a.querySelector('p').textContent : ''}))`);
    check('history IDs and content survive backend restart/reload', JSON.stringify(history) === JSON.stringify(report.historyAfter));
    check('unsent draft survives restart/reload', (await ev(`document.getElementById('composer-input').value`)) === 'INDEPENDENT-UNSENT-DRAFT');
    try {
      const frameProbe = await evFrame(`Promise.all([fetch('https://example.com/').then(() => 'ALLOWED', () => 'DENIED'), Promise.resolve(document.querySelector('meta[http-equiv="Content-Security-Policy"]') ? document.querySelector('meta[http-equiv="Content-Security-Policy"]').content : 'no-meta')])`);
      report.frameNetworkProbe = frameProbe;
      check('frame fetch denied', frameProbe && frameProbe[0] === 'DENIED');
    } catch (e) {
      check('frame fetch denied', false, String(e).slice(0, 120));
    }
  } else if (mode === 'expiry') {
    const waitReadyX = async () => {
      for (let i = 0; i < 90; i++) {
        const s = String(await ev(`document.getElementById('connection-status').textContent`));
        if (s.indexOf('ready') === 0) return s;
        await sleep(1000);
      }
      return String(await ev(`document.getElementById('connection-status').textContent`));
    };
    const status = await waitReadyX();
    check('login works, socket ready (expiry run)', status.indexOf('ready') === 0, status);
    if (status.indexOf('ready') !== 0) throw Error('never ready: ' + status);
    let end = status, dis = false;
    for (let i = 0; i < 45; i++) {
      end = String(await ev(`document.getElementById('connection-status').textContent`));
      dis = await ev(`document.getElementById('composer-send').disabled`);
      if (/down|reconnecting/.test(end) && dis === true) break;
      await sleep(1000);
    }
    check('expired session drops the socket, send disabled', /down|reconnecting/.test(end) && dis === true, end + ' disabled=' + dis);
    await navLoad(baseUrl + '/app/ws');
    const loginHtml2 = await ev('document.documentElement.outerHTML');
    check('expired session returns to sign-in', /sign in/.test(loginHtml2), String(loginHtml2).slice(0, 120));
  } else {
    const waitReady = async () => {
      for (let i = 0; i < 90; i++) {
        const s = String(await ev(`document.getElementById('connection-status').textContent`));
        if (s.indexOf('ready') === 0) return s;
        await sleep(1000);
      }
      return String(await ev(`document.getElementById('connection-status').textContent`));
    };
    const status = await waitReady();
    check('login works, socket ready (Secure cookie held)', status.indexOf('ready') === 0, status);
    if (status.indexOf('ready') !== 0) throw Error('never ready: ' + status);
    // composer node marker for incremental-update check
    await ev(`document.getElementById('composer').dataset.mark='m1'; document.getElementById('composer-input').focus();`);
    await ev(`document.getElementById('composer-input').value = 'Reply with only this exact line and nothing else: ACK ${nonce}'; document.getElementById('composer-send').click();`);
    let bubbleText = '';
    for (let i = 0; i < 150; i++) {
      const arts = await ev(`Array.from(document.querySelectorAll('#bubbles article')).map((a) => a.innerText).join('\\n---\\n')`);
      if (String(arts).indexOf(nonce) >= 0) { bubbleText = String(arts); break; }
      await sleep(1000);
    }
    report.bubbleText = bubbleText.slice(0, 2000);
    check('assistant DOM bubble renders nonce answer', bubbleText.indexOf(nonce) >= 0, bubbleText.slice(0, 200));
    const mark = await ev(`document.getElementById('composer').dataset.mark`);
    check('composer node stable across patch', mark === 'm1', String(mark));
    const focus = await ev(`document.activeElement && document.activeElement.id`);
    check('focus preserved after patch', focus === 'composer-input', String(focus));
    // draft retention across reload
    await ev(`document.getElementById('composer-input').value = 'DRAFT-KEEP-1'; document.getElementById('composer-input').dispatchEvent(new Event('input', {bubbles:true}));`);
    await sleep(300);
    await navLoad(baseUrl + '/');
    await waitReady();
    const draft = await ev(`document.getElementById('composer-input').value`);
    check('draft retained across reload', draft === 'DRAFT-KEEP-1', String(draft).slice(0, 40));
    // frame host: single reusable iframe, srcdoc mounted, real render
    // (opaque-origin srcdoc frames run JS but stay out of the CDP frame
    // tree, so the frame is located via DOM + its execution context)
    const frameCount = await ev(`document.querySelectorAll('iframe').length`);
    const getFrameId = async () => {
      try {
        const doc = await call('DOM.getDocument', { depth: 0 });
        const q = await call('DOM.querySelector', { nodeId: doc.root.nodeId, selector: 'iframe' });
        if (!q || !q.nodeId) return null;
        const d = await call('DOM.describeNode', { nodeId: q.nodeId });
        return (d.node && d.node.frameId) || null;
      } catch { return null; }
    };
    const fid = await getFrameId();
    check('exactly one reusable iframe', frameCount === 1 && !!fid, 'count=' + frameCount + ' frameId=' + !!fid);
    const sandbox = await ev(`document.querySelector('iframe').getAttribute('sandbox')`);
    check('frame sandbox exactly allow-scripts', sandbox === 'allow-scripts', String(sandbox));
    const srcdocLen = await ev(`(document.querySelector('iframe').getAttribute('srcdoc') || '').length`);
    check('frame srcdoc mounted', srcdocLen > 1000, String(srcdocLen));
    let frameAlive = false;
    try { await evFrame(`'alive'`); frameAlive = true; } catch {}
    check('frame context visible', frameAlive);
    // render delivered into the frame: nonce text inside frame doc,
    // read over one persistent target session (re-attached on navigate)
    let frameText = '';
    let link = null;
    for (let i = 0; i < 30; i++) {
      try {
        if (!link) link = await frameLink();
        frameText = String(await link.read(`document.getElementById('r').innerText`) || '');
      } catch {
        try { if (link) await link.close(); } catch {}
        link = null;
      }
      if (frameText.indexOf(nonce) >= 0) break;
      await sleep(1000);
    }
    try { if (link) await link.close(); } catch {}
    check('frame render delivers nonce answer', frameText.indexOf(nonce) >= 0, frameText.slice(0, 200));
    {
      const before = await ev(`document.getElementById('connection-status').textContent`);
      await evFrame(`parent.postMessage({op:'bogus-op-xyz'},'*')`);
      await sleep(800);
      const after = await ev(`document.getElementById('connection-status').textContent`);
      check('bogus frame op ignored', before === after, before + ' -> ' + after);
      // welcome token captured off the real socket frames
      let tok = null, fcx = null;
      for (let i = 0; i < 40 && !tok; i++) {
        for (const f of wsFrames) {
          try { const m = JSON.parse(f); if (m.op === 'welcome' && m.body && m.body.frame_token) { tok = m.body.frame_token; fcx = m.body.frame_context; } } catch {}
        }
        if (!tok) await sleep(500);
      }
      await evFrame(`parent.postMessage({op:'action-click', action_id:'a.evil'},'*')`);
      await sleep(800);
      const ignored = await ev(`document.getElementById('connection-status').textContent`);
      check('tokenless frame action ignored', ignored === after, String(ignored));
      if (tok) {
        await evFrame(`parent.postMessage({op:'action-click', token:${JSON.stringify(tok)}, context:${JSON.stringify(fcx)}, action_id:'a.evil', fragment_id:'f-x'},'*')`);
        let acted = '';
        for (let i = 0; i < 30; i++) {
          acted = String(await ev(`document.getElementById('connection-status').textContent`));
          if (/unknown-action/.test(acted)) break;
          await sleep(1000);
        }
        check('frame action forwarded through domain validation', /unknown-action/.test(acted), acted);
      } else {
        check('frame action forwarded through domain validation', false, 'no welcome token captured');
      }
      // Authenticated resize is clamped to the configured policy max;
      // tokenless / context-stale / unknown-surface frame events are
      // fenced in the parent and never forwarded or applied.
      if (tok) {
        await evFrame(`parent.postMessage({op:'resize', token:${JSON.stringify(tok)}, context:${JSON.stringify(fcx)}, height:5000},'*')`);
        await sleep(500);
        const h = await ev(`document.getElementById('frag-frame').style.height`);
        check('frame resize clamped to configured max', h === '800px', String(h));
      } else {
        check('frame resize clamped to configured max', false, 'no welcome token captured');
      }
      const hBefore = await ev(`document.getElementById('frag-frame').style.height`);
      const fenceBefore = await ev(`window.__chatFenceIgnored()`);
      await evFrame(`parent.postMessage({op:'resize', height:5000},'*')`);
      await sleep(500);
      const hAfter = await ev(`document.getElementById('frag-frame').style.height`);
      check('tokenless frame resize ignored', hAfter === hBefore, String(hBefore) + ' -> ' + String(hAfter));
      await evFrame(`parent.postMessage({op:'form-state', fragment_id:'f-bogus', values:{x:1}},'*')`);
      await sleep(500);
      const fenceAfter = await ev(`window.__chatFenceIgnored()`);
      check('tokenless frame form-state ignored', fenceAfter > fenceBefore, String(fenceBefore) + ' -> ' + String(fenceAfter));
      if (tok) {
        const fenceBefore2 = await ev(`window.__chatFenceIgnored()`);
        await evFrame(`parent.postMessage({op:'form-state', token:${JSON.stringify(tok)}, context:${JSON.stringify(fcx)}, fragment_id:'f-bogus', values:{x:1}},'*')`);
        await sleep(500);
        const fenceAfter2 = await ev(`window.__chatFenceIgnored()`);
        check('unknown-fragment form-state ignored', fenceAfter2 > fenceBefore2, String(fenceBefore2) + ' -> ' + String(fenceAfter2));
      } else {
        check('unknown-fragment form-state ignored', false, 'no welcome token captured');
      }
    }
    // reload mid-send: second nonce, reload before completion, no dup/loss
    await ev(`document.getElementById('composer-input').value = 'Reply with only this exact line and nothing else: ACK ${nonce}-reload'; document.getElementById('composer-send').click();`);
    await sleep(2000);
    await navLoad(baseUrl + '/');
    const status2 = await waitReady();
    check('reconnect after reload mid-send', status2.indexOf('ready') === 0, status2);
    let arts2 = '';
    for (let i = 0; i < 150; i++) {
      arts2 = String(await ev(`Array.from(document.querySelectorAll('#bubbles article')).map((a) => (a.querySelector('strong') ? a.querySelector('strong').innerText : '') + '|' + (a.querySelector('p') ? a.querySelector('p').innerText : '')).join('\\n')`));
      if (arts2.indexOf(nonce + '-reload') >= 0) break;
      await sleep(1000);
    }
    const hermesHits = arts2.split('\n').filter((l) => l.indexOf('hermes|') === 0 && l.indexOf(nonce + '-reload') >= 0).length;
    const youHits = arts2.split('\n').filter((l) => l.indexOf('you|') === 0 && l.indexOf(nonce + '-reload') >= 0).length;
    check('reload mid-send: answer arrives exactly once', hermesHits === 1 && youHits === 1, 'hermes=' + hermesHits + ' you=' + youHits);
    // connection loss and recovery: drop the socket, backoff reconnects
    // (the reconnect lands in under a second, faster than a status poll,
    // so the proof is a fresh welcome on the wire plus a ready socket)
    const welcomesBefore = wsFrames.filter((f) => f.indexOf('"welcome"') >= 0).length;
    await ev(`try { window.__chatWs.close(); } catch (e) {}`);
    const status3 = await waitReady();
    let welcomesAfter = welcomesBefore;
    for (let i = 0; i < 30; i++) {
      welcomesAfter = wsFrames.filter((f) => f.indexOf('"welcome"') >= 0).length;
      if (welcomesAfter > welcomesBefore) break;
      await sleep(1000);
    }
    check('socket drop reconnects with fresh welcome', welcomesAfter > welcomesBefore, 'welcomes ' + welcomesBefore + ' -> ' + welcomesAfter);
    check('backoff recovery returns to ready', status3.indexOf('ready') === 0, status3);
    // wrong-origin upgrade rejection: raw client against this live stack
    // (browsers cannot forge Origin; S005 covers origin strings in depth)
    const { request: httpRequest } = await import('node:http');
    const rawReject = await new Promise((res) => {
      try {
        const u = new URL(baseUrl);
        const req = httpRequest({ host: '127.0.0.1', port: u.port, path: '/app/ws', method: 'GET',
          headers: { Host: u.host, Upgrade: 'websocket', Connection: 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==', 'Sec-WebSocket-Version': '13',
            Origin: 'https://evil.test', 'Sec-WebSocket-Protocol': 'hermes.web.v1' } });
        req.on('response', (r) => { r.resume(); res(r.statusCode); });
        req.on('error', () => res('error'));
        req.setTimeout(10000, () => { try { req.destroy(); } catch {} res('timeout'); });
        req.end();
      } catch (e) { res('harness-error'); }
    });
    check('wrong-origin upgrade rejected', rawReject === 403, String(rawReject));
    // untrusted frame content cannot execute under the page CSP
    const cspProbe = await ev(`new Promise((res) => {
      var got = [];
      var h = function(e){ got.push(String(e.data)); };
      window.addEventListener('message', h);
      var f = document.createElement('iframe');
      f.setAttribute('sandbox', 'allow-scripts');
      f.srcdoc = '<script>parent.postMessage("probe-alive", "*");</scr' + 'ipt>';
      document.body.appendChild(f);
      setTimeout(function(){
        window.removeEventListener('message', h);
        try { f.remove(); } catch (x) {}
        res(JSON.stringify(got));
      }, 2500);
    })`);
    check('untrusted frame script blocked by CSP', cspProbe === '[]', String(cspProbe).slice(0, 120));
    // drawer persistence across reload
    const drawerBefore = await ev(`Array.from(document.querySelectorAll('#drawer-items li')).map((li) => li.textContent).join('|')`);
    await navLoad(baseUrl + '/');
    await waitReady();
    const drawerAfter = await ev(`Array.from(document.querySelectorAll('#drawer-items li')).map((li) => li.textContent).join('|')`);
    check('drawer list stable across reload', drawerBefore === drawerAfter && drawerBefore.length > 0, drawerBefore + ' -> ' + drawerAfter);
  }
  report.netUrls = netReqs;
  report.wsUrls = wsUrls;
  try {
    report.lastClose = await ev(`(function(){ try { return sessionStorage.getItem('chat-last-close'); } catch (e) { return 'nostore'; } })()`);
    report.closeLog = await ev(`(function(){ try { return sessionStorage.getItem('chat-close-log'); } catch (e) { return 'nostore'; } })()`);
    report.welcomes = wsFrames.filter((f) => f.indexOf('"welcome"') >= 0).length;
  } catch {}
} catch (e) {
  report.errors.push(String((e && e.message) || e));
} finally {
  try { writeFileSync(outPath, JSON.stringify(report, null, 2)); } catch {}
  await cleanup();
}
const failed = Object.values(report.checks).filter((v) => String(v).indexOf('fail') === 0);
if (failed.length || report.errors.length) { console.log('GATE FAIL ' + failed.length + ' checks, ' + report.errors.length + ' errors'); process.exit(0); }
console.log('GATE OK');
process.exit(0);
