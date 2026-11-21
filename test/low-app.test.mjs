import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCollector } from '../src/collector.js';
import { RU, setLang, t } from '../src/i18n.js';

function loaderEnv({ lang = 'en-US', unreadable = false } = {}) {
  const calls = { run: 0, alerts: [], blobs: [], mem: null, interval: null };
  const url = 'blob:https://shop.test/1';
  const doc = { URL: url, readyState: 'complete', body: { append() {} }, head: { append() {} }, createElement: () => ({ append() {} }) };
  const tab = { closed: false, CSSStyleSheet: class { replaceSync() {} }, setTimeout, clearTimeout, location: {}, history: {} };
  Object.defineProperty(tab, 'document', { get() { if (unreadable) throw new Error('cross-origin'); return doc; } });
  globalThis.window = {
    location: { origin: 'https://shop.test', href: 'https://shop.test/', host: 'shop.test' }, document: { cookie: '' }, navigator: { language: lang },
    URL: { createObjectURL: () => url, revokeObjectURL() {} }, Blob: class { constructor(p) { calls.blobs.push(p.join('')); } },
    open: () => (lang === 'blocked' ? null : tab), alert: (m) => calls.alerts.push(m), addEventListener() {},
    setInterval: (fn) => { calls.interval = fn; return 1; }, clearInterval() {}, setTimeout
  };
  globalThis.RL_CSS = ''; globalThis.RL_ICON = 'data:,'; globalThis.RL_RUN = (...a) => { calls.run++; calls.mem = a[4]; };
  return { calls, tab, doc };
}
let n = 0;
const load = () => import('../src/bookmarklet.js?low' + ++n);

test('31-F7: memoryStorage хранит, отдаёт и удаляет значения', async () => {
  const { calls } = loaderEnv(); await load(); calls.interval();
  const m = calls.mem; assert.equal(m.getItem('k'), null);
  m.setItem('k', 5); assert.equal(m.getItem('k'), '5');
  m.removeItem('k'); assert.equal(m.getItem('k'), null);
});

test('31-F7: документ вкладки недоступен — интерфейс не запускается, исключения нет', async () => {
  const { calls } = loaderEnv({ unreadable: true }); await load();
  assert.doesNotThrow(() => calls.interval()); assert.equal(calls.run, 0);
});

test('значок вкладки есть (по просьбе пользователя; на строгой CSP он просто не покажется)', async () => {
  const { calls } = loaderEnv(); await load();
  assert.ok(calls.blobs.length && /rel="icon"/.test(calls.blobs[0]));
});

test('15-F3: сообщение о блокировке окна следует языку браузера', async () => {
  for (const [lang, re] of [['ru-RU', /заблокировал/], ['en-US', /blocked/]]) {
    const { calls } = loaderEnv({ lang }); window.open = () => null; await load();
    assert.match(calls.alerts[0], re);
  }
});

test('15-F6: вкладка так и не загрузилась — говорим об этом, а не молчим', async () => {
  const { calls, doc } = loaderEnv(); doc.readyState = 'loading'; await load();
  const real = Date.now; Date.now = () => real() + 31000;
  try { calls.interval(); } finally { Date.now = real; }
  assert.equal(calls.run, 0); assert.equal(calls.alerts.length, 1);
});

function colEnv(extra = {}) {
  const sent = [], listeners = [], cleared = [], cb = {};
  const appWin = { closed: false, postMessage: (m) => sent.push(m) };
  const doc = { contentType: 'text/html', cookie: 'sid=1', documentElement: { outerHTML: '<html></html>' }, querySelector: () => null, querySelectorAll: () => [] };
  const win = Object.assign({
    location: { href: 'https://a.test/', origin: 'https://a.test', protocol: 'https:', host: 'a.test', pathname: '/' }, document: doc,
    performance: { getEntriesByType: () => [] }, localStorage: { length: 0 }, sessionStorage: { length: 0 },
    addEventListener: (t, fn) => listeners.push(fn), setInterval: (fn) => { cb.tick = fn; return 7; }, clearInterval: (i) => cleared.push(i)
  }, extra);
  const c = createCollector({ win, tab: appWin, sleep: async () => {} });
  const send = (m) => listeners.forEach((fn) => fn({ origin: 'https://a.test', source: appWin, data: Object.assign({ rl: 2 }, m) }));
  return { c, send, sent, appWin, cleared, cb };
}

test('31-F6: cookieStore, service worker с push и PerformanceObserver выполняются на заглушках', async () => {
  let observed = null, disconnected = false;
  const e = colEnv({
    cookieStore: { getAll: async () => [{ name: 'sid', domain: 'a.test', path: '/', secure: true, sameSite: 'strict', expires: 0 }] },
    navigator: { serviceWorker: { getRegistrations: async () => [
      { scope: 'https://a.test/', active: { scriptURL: 'https://a.test/sw.js', state: 'activated' }, pushManager: { getSubscription: async () => ({ endpoint: 'https://push.test/abcdef0123456789xyz' }) } },
      { scope: 'https://a.test/x/', active: { scriptURL: 'https://a.test/x.js', state: 'activated' } }] } },
    PerformanceObserver: class { constructor(fn) { observed = fn; } observe() {} disconnect() { disconnected = true; } }
  });
  e.c.start(); e.send({ type: 'hello' }); await e.c.idle();
  const snap = e.sent.find((m) => m.type === 'snapshot').page;
  assert.equal(snap.cookies[0].secure, true); assert.equal(snap.cookies[0].attrsKnown, true);
  assert.equal(snap.sw.length, 2); assert.match(snap.sw[0].push, /^push\.test/); assert.equal(snap.sw[1].push, null);
  observed({ getEntries: () => [{ name: 'https://a.test/api/x', initiatorType: 'fetch', duration: 3, startTime: 1 }] });
  assert.equal(e.sent.find((m) => m.type === 'traffic').entries[0].url, 'https://a.test/api/x');
  // after the tab closes the timer and observer are removed
  e.appWin.closed = true; await e.cb.tick();
  assert.deepEqual(e.cleared, [7]); assert.equal(disconnected, true);
});

// --- i18n: 27-F2/F3/F6 ---
test('27-F6: подписи вкладок и типов файлов переведены (или это технические имена)', () => {
  const TECH = new Set(['API', 'HTML', 'CSS', 'JSON', 'JavaScript']);
  const labels = [];
  const main = readFileSync(new URL('../src/app/main.js', import.meta.url), 'utf8');
  for (const m of main.slice(main.indexOf('const SECTIONS'), main.indexOf('function sectionCount')).matchAll(/\['[a-z]+', '([^']+)'\]/g)) labels.push(m[1]);
  const files = readFileSync(new URL('../src/app/ui/files.js', import.meta.url), 'utf8');
  for (const m of files.match(/const TYPES = (\[.*\]);/)[1].matchAll(/\['[a-z]*', '([^']+)'\]/g)) labels.push(m[1]);
  for (const m of files.matchAll(/chk\('[a-z]+', '([^']+)'\)/g)) labels.push(m[1]);
  assert.ok(labels.length > 25);
  setLang('ru');
  try { for (const l of labels) assert.ok(TECH.has(l) || (RU[l] && t(l) !== l), 'no RU for ' + l); } finally { setLang('en'); }
});
