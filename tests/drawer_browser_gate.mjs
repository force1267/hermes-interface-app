// P3 drawer browser gate: real Chrome drives the durable drawer ops.
//
// Fixture page is built by tests/test_drawer_browser.py (A,B,C,A entries
// with C pinned and B needs_repair, plus seven pinned P-entries).
// This script clicks the actual UI and asserts the row set really
// changes: rename with input, duplicate auto-numbering through Add,
// pin/unpin reorder, two-step confirm/cancel delete, repair clearing the
// degraded flag, injected Add failure with operable retry, localStorage
// persistence across reload, and no id reuse after delete.
//
// Exit 0 = all gates pass. Any FAIL prints and exits 1.
import { spawn } from 'node:child_process';

const [pagePath, chromeBin, userDir, portArg] = process.argv.slice(2);
let port = Number(portArg || 0);
if (!pagePath || !chromeBin || !userDir) {
  console.log('usage: drawer_browser_gate.mjs <page.html> <chrome-bin> <user-data-dir> [port|0]');
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
      await new Promise((r) => {
        const t = setTimeout(r, 5000);
        chrome.once('exit', () => { clearTimeout(t); r(); });
      });
    }
  }
}
try {
  chrome = spawnChrome(port);
  if (!port) {
    port = await waitForDevToolsPort(chrome, 20000);
    console.log('PASS isolated debug port ' + port);
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
  let id = 0; const pending = new Map(); const contexts = [];
  ws.onmessage = (e) => {
    let m; try { m = JSON.parse(e.data); } catch { return; }
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    if (m.method === 'Runtime.executionContextCreated') contexts.push(m.params.context);
  };
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
  const topFrameId = async () => (await call('Page.getFrameTree')).frameTree.frame.id;
  const mainCtx = async () => {
    const fid = await topFrameId();
    const c = contexts.findLast((x) => x.auxData?.frameId === fid && x.auxData?.isDefault);
    if (!c) throw Error('no main execution context');
    return c.id;
  };
  await call('Page.enable'); await call('Runtime.enable');
  await call('Page.navigate', { url: 'file://' + pagePath });
  await sleep(900);
  let ctx = await mainCtx();
  const ev = async (expr) => {
    const r = await call('Runtime.evaluate',
      { expression: expr, contextId: ctx, awaitPromise: true, returnByValue: true });
    return r.result?.value ?? r.exceptionDetails?.exception?.description ?? r.exceptionDetails;
  };
  const names = () => ev(`Array.from(document.querySelectorAll('#drawer li[data-page]')).map(li => li.getAttribute('data-page'))`);
  const count = () => ev(`document.querySelectorAll('#drawer li[data-page]').length`);
  const statusText = () => ev(`document.getElementById('drawer-status').textContent`);
  const click = (sel) => ev(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if(!el) return 'missing'; el.click(); return 'clicked'; })()`);
  const setInput = (sel, v) => ev(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if(!el) return 'missing'; el.value = ${JSON.stringify(v)}; el.dispatchEvent(new Event('input', {bubbles: true})); return 'set'; })()`);

  // --- static render: pinned-first, creation order, Add last, degraded ---
  const order = await names();
  gate('pinned-first creation order Add-last',
    JSON.stringify(order) === JSON.stringify(['pg-3', 'pg-5', 'pg-6', 'pg-7', 'pg-8', 'pg-9', 'pg-10', 'pg-11', 'pg-1', 'pg-2', 'pg-4']),
    JSON.stringify(order));
  gate('eight pins rendered',
    await ev(`document.querySelectorAll('#drawer li[data-pinned="1"]').length`) === 8);
  gate('degraded entry visible',
    (await ev(`document.querySelector('li[data-page="pg-2"]').className`)).includes('degraded') &&
    (await ev(`document.querySelector('li[data-page="pg-2"] [data-needs="1"]') ? document.querySelector('li[data-page="pg-2"] [data-needs="1"]').textContent : ''`)) === 'needs_repair');
  gate('add affordance immediately after list',
    await ev(`document.querySelector('#drawer ul').nextElementSibling && document.querySelector('#drawer ul').nextElementSibling.getAttribute('data-drawer-op')`) === 'add-page');

  // --- rename via i-flow: input, DOM change, status from result ---
  gate('rename opens input', await click('button[data-drawer-op="rename"][data-page="pg-1"]') === 'clicked');
  gate('rename input present', await ev(`!!document.getElementById('drawer-rename-name')`) === true);
  await setInput('#drawer-rename-name', 'Zed');
  await click('button[data-drawer-ui="rename-save"]');
  gate('rename changes DOM name',
    await ev(`document.querySelector('li[data-page="pg-1"] .dname').textContent`) === 'Zed',
    await ev(`document.querySelector('#drawer').innerHTML.slice(0,200)`));
  gate('rename status names result', String(await statusText()).includes('Renamed pg-1 to "Zed"'), await statusText());

  // --- Add duplicate auto-numbers through the real Add UI ---
  const beforeAdd = await count();
  await click('button[data-drawer-op="add-page"]');
  gate('add opens form', await ev(`!!document.getElementById('drawer-add-name')`) === true);
  await setInput('#drawer-add-name', 'Zed');
  await click('button[data-drawer-ui="add-confirm"]');
  gate('add duplicate auto-numbered in DOM',
    await ev(`Array.from(document.querySelectorAll('#drawer li[data-page] .dname')).map(s => s.textContent).filter(n => n === 'Zed 2').length`) === 1);
  gate('add grows row set', await count() === beforeAdd + 1, String(await count()) + ' vs ' + beforeAdd);
  gate('add status names new id', String(await statusText()).includes('Zed 2'), await statusText());

  // --- pin reorders, unpin restores button ---
  await click('button[data-drawer-op="pin"][data-page="pg-4"]');
  gate('pin mutates row to pinned',
    await ev(`document.querySelector('li[data-page="pg-4"]').getAttribute('data-pinned')`) === '1' &&
    String(await statusText()).includes('Pinned pg-4'), await statusText());
  gate('pinned entry renders before unpinned',
    (await names()).indexOf('pg-4') < (await names()).indexOf('pg-1'), JSON.stringify(await names()));
  await click('button[data-drawer-op="unpin"][data-page="pg-3"]');
  gate('unpin mutates row', await ev(`document.querySelector('li[data-page="pg-3"]').getAttribute('data-pinned')`) === '0');

  // --- delete needs explicit confirm; cancel preserves ---
  const beforeDel = await count();
  await click('button[data-drawer-op="delete"][data-page="pg-5"]');
  gate('first delete click only arms (entry kept)',
    await count() === beforeDel && await ev(`!!document.querySelector('li[data-page="pg-5"]')`) === true);
  gate('confirm affordance appears', await ev(`!!document.querySelector('button[data-drawer-ui="confirm"]')`) === true);
  await click('button[data-drawer-ui="cancel"]');
  gate('cancel preserves entry',
    await ev(`!!document.querySelector('li[data-page="pg-5"]')`) === true && String(await statusText()).includes('kept'),
    await statusText());
  await click('button[data-drawer-op="delete"][data-page="pg-5"]');
  await click('button[data-drawer-ui="confirm"]');
  gate('confirmed delete removes row',
    await ev(`!!document.querySelector('li[data-page="pg-5"]')`) === false && await count() === beforeDel - 1,
    String(await count()));
  gate('delete status only after success', String(await statusText()).includes('Deleted pg-5'), await statusText());

  // --- repair clears the degraded flag ---
  await click('button[data-drawer-op="repair"][data-page="pg-2"]');
  await click('button[data-drawer-ui="confirm"]');
  gate('repair clears needs_repair',
    await ev(`!!document.querySelector('li[data-page="pg-2"] [data-needs="1"]')`) === false &&
    String(await statusText()).includes('Repaired pg-2'), await statusText());

  // --- injected mid-write failure through the Add path: retry, no orphan ---
  const beforeFail = await count();
  await ev(`window.DrawerOps.injectFailure('add', 'injected mid-write failure')`);
  await click('button[data-drawer-op="add-page"]');
  await setInput('#drawer-add-name', 'Frag');
  await click('button[data-drawer-ui="add-confirm"]');
  gate('failed add keeps chat with error + retry',
    String(await statusText()).includes("add that page") &&
    String(await statusText()).includes("Nothing was added") &&
    await ev(`!!document.querySelector('button[data-drawer-ui="add-retry"]')`) === true,
    await statusText());
  gate('failed add creates no row', await count() === beforeFail, String(await count()));
  await click('button[data-drawer-ui="add-retry"]');
  const fragId = await ev(`Array.from(document.querySelectorAll('#drawer li[data-page]')).filter(li => li.querySelector('.dname').textContent === 'Frag').map(li => li.getAttribute('data-page'))[0] || ''`);
  gate('retry adds the page', typeof fragId === 'string' && fragId.startsWith('pg-') && await count() === beforeFail + 1,
    fragId + ' count=' + await count());
  gate('deleted id never reused by Add', fragId !== 'pg-5', fragId);

  // --- reload: durable store restores every op ---
  await call('Page.navigate', { url: 'file://' + pagePath });
  await sleep(900);
  ctx = await mainCtx();
  gate('reload keeps row count', await count() === beforeFail + 1, String(await count()));
  gate('reload keeps rename', await ev(`document.querySelector('li[data-page="pg-1"] .dname').textContent`) === 'Zed');
  gate('reload keeps confirmed delete', await ev(`!!document.querySelector('li[data-page="pg-5"]')`) === false);
  gate('reload keeps retried add', await ev(`!!document.querySelector('li[data-page="${fragId}"]')`) === true);
  gate('reload keeps repair', await ev(`!!document.querySelector('li[data-page="pg-2"] [data-needs="1"]')`) === false);
} catch (e) {
  console.log('FAIL harness-error :: ' + String(e && e.stack || e));
  failures.push('harness-error');
} finally {
  await cleanup();
}
if (failures.length) { console.log('GATE RESULT: FAIL ' + failures.length); process.exitCode = 1; }
else console.log('GATE RESULT: PASS');
