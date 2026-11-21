import test from 'node:test';
import assert from 'node:assert/strict';

// Fake page window and tab: check the bookmarklet start order without a browser
function setup({ closed = false } = {}) {
  const calls = { run: 0, revoked: [], cleared: 0, interval: null, alerts: [] };
  const url = 'blob:https://shop.test/1';
  const doc = { URL: 'about:blank', readyState: 'loading', body: { append() {} }, head: { append() {} }, createElement: () => ({ append() {} }) };
  const tab = { closed, document: doc, CSSStyleSheet: class { replaceSync() {} }, setTimeout, clearTimeout, location: {}, history: {} };
  globalThis.window = {
    location: { origin: 'https://shop.test', href: 'https://shop.test/', host: 'shop.test' }, document: { cookie: '' },
    URL: { createObjectURL: () => url, revokeObjectURL: (u) => calls.revoked.push(u) }, Blob: class {},
    open: (u) => (u === url ? tab : null), alert: (m) => calls.alerts.push(m), addEventListener() {},
    setInterval: (fn) => { calls.interval = fn; return 1; }, clearInterval: () => { calls.cleared++; }, setTimeout
  };
  globalThis.RL_CSS = ''; globalThis.RL_ICON = 'data:,'; globalThis.RL_RUN = () => { calls.run++; };
  return { calls, doc, url, tab };
}
let n = 0;
const load = () => import('../src/bookmarklet.js?' + ++n);

test('закладка открывает blob-адрес и запускает интерфейс только после загрузки вкладки', async () => {
  const { calls, doc, url } = setup();
  await load();
  calls.interval(); assert.equal(calls.run, 0); // tab is still loading
  Object.assign(doc, { URL: url, readyState: 'complete' });
  calls.interval(); calls.interval();
  assert.equal(calls.run, 1); assert.equal(calls.cleared, 1); assert.deepEqual(calls.revoked, [url]);
});

test('вкладку закрыли до загрузки: ожидание прекращается, интерфейс не запускается', async () => {
  const { calls, tab } = setup();
  await load();
  tab.closed = true; calls.interval();
  assert.equal(calls.run, 0); assert.equal(calls.cleared, 1);
});
