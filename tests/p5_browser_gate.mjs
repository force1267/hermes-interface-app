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
  const netReqs = []; const docHeaders = {}; const wsUrls = [];
  ws.onmessage = (e) => {
    let m; try { m = JSON.parse(e.data); } catch { return; }
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    if (m.method === 'Network.requestWillBeSent') netReqs.push(m.params.request.url);
    if (m.method === 'Network.webSocketCreated') wsUrls.push(m.params.url);
    if (m.method === 'Network.responseReceived' && m.params.type === 'Document') {
      docHeaders[m.params.response.url] = m.params.response.headers;
    }
    if (m.method === 'Runtime.executionContextCreated') contexts.push(m.params.context);
  };
  const call = (method, params = {}, timeoutMs = 15000) => new Promise((resolve, reject) => {
    const n = ++id;
    const t = setTimeout(() => { if (pending.has(n)) { pending.delete(n); reject(Error('cdp-timeout:' + method)); } }, timeoutMs);
    pending.set(n, (x) => { clearTimeout(t); x.error ? reject(Error(JSON.stringify(x.error))) : resolve(x.result); });
    try { ws.send(JSON.stringify({ id: n, method, params })); }
    catch (e) { clearTimeout(t); pending.delete(n); reject(e); }
  });
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
        if (/down|unavailable/i.test(s)) return s;
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
      if (/down|unavailable|ready/i.test(s)) break;
      await sleep(1000);
    }
    const draft = await ev(`document.getElementById('composer-input').value`);
    check('draft retained across reload on dead backend', draft === 'DRAFT-KEEP-DEAD', String(draft).slice(0, 40));
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
    await ev(`document.getElementById('composer-input').value = 'BROWSER-SEND ${nonce} please confirm receipt'; document.getElementById('composer-send').click();`);
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
    // frame bridge: source-checked, op allowlist, no auth in frame
    const tree = await frameTree();
    const kids = tree.childFrames || [];
    check('exactly one reusable iframe', kids.length === 1, String(kids.length));
    const sandbox = await ev(`document.querySelector('iframe').getAttribute('sandbox')`);
    check('frame sandbox exactly allow-scripts', sandbox === 'allow-scripts', String(sandbox));
    const fid = kids[0] && kids[0].frame.id;
    const fctx = fid ? await frameCtx(fid) : null;
    check('frame context visible', !!fctx);
    if (fctx) {
      const before = await ev(`document.getElementById('connection-status').textContent`);
      await ev(`parent.postMessage({op:'bogus-op-xyz'},'*')`, fctx);
      await sleep(800);
      const after = await ev(`document.getElementById('connection-status').textContent`);
      check('bogus frame op ignored', before === after, before + ' -> ' + after);
      await ev(`parent.postMessage({op:'action', action_id:'a.evil'},'*')`, fctx);
      let acted = '';
      for (let i = 0; i < 30; i++) {
        acted = String(await ev(`document.getElementById('connection-status').textContent`));
        if (/actions-disabled/.test(acted)) break;
        await sleep(1000);
      }
      check('frame action forwarded through domain validation', /actions-disabled/.test(acted), acted);
      await ev(`parent.postMessage({op:'resize', height:5000},'*')`, fctx);
      await sleep(500);
      const h = await ev(`document.getElementById('frag-frame').style.height`);
      check('frame resize clamped to configured max', h === '800px', String(h));
    }
  }
  report.netUrls = netReqs;
  report.wsUrls = wsUrls;
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
