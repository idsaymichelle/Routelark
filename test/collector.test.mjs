import test from 'node:test';
import assert from 'node:assert/strict';
import { createCollector } from '../src/collector.js';

const PAGE = 'https://app.example.org/page';
// Вкладка Routelark — about:blank, открытая страницей: у неё тот же origin, что у страницы
const APP_ORIGIN = 'https://app.example.org';

function env(opts = {}) {
  const sent = [], net = [], listeners = [], sleeps = [];
  const appWin = { closed: false, postMessage: (m, o) => sent.push({ m, o: o || APP_ORIGIN }), focus() {} };
  const doc = { contentType: 'text/html', cookie: 'sid=1', documentElement: { outerHTML: '<html><script src="/app.js"></script></html>' }, querySelector: () => null, querySelectorAll: (sel) => (/script/.test(sel) ? [{ src: 'https://app.example.org/app.js' }] : []), createElement: () => ({ click() {}, remove() {}, setAttribute() {} }), body: { append() {} } };
  const win = {
    location: { href: PAGE, origin: 'https://app.example.org', protocol: 'https:' }, document: doc,
    performance: { getEntriesByType: () => [] }, localStorage: { length: 0 }, sessionStorage: { length: 0 },
    addEventListener: (t, fn) => listeners.push(fn),
    fetch: async (url) => { net.push(url); const r = opts.responses && opts.responses[url] || { status: 200, body: 'x', type: 'application/javascript' }; return { status: r.status, ok: r.status < 400, headers: new Map([['content-type', r.type || 'application/javascript']]), text: async () => r.body }; }
  };
  const c = createCollector({ win, tab: appWin, sleep: async (ms) => { sleeps.push(ms); } });
  const send = (m, origin = APP_ORIGIN, source = appWin) => listeners.forEach((fn) => fn({ origin, source, data: Object.assign({ rl: 2 }, m) }));
  const replies = (type) => sent.filter((s) => s.m.type === type).map((s) => s.m);
  return { win, doc, c, send, sent, net, sleeps, listeners, replies, appWin };
}

test('hello → снимок страницы уходит только на origin вкладки', async () => {
  const e = env(); e.c.start(); e.send({ type: 'hello', version: 2 }); await e.c.idle();
  const snap = e.replies('snapshot')[0];
  assert.equal(snap.page.url, PAGE);
  assert.match(snap.page.html, /app\.js/);
  assert.ok(e.sent.every((s) => s.o === APP_ORIGIN));
});

test('сообщение с чужого origin игнорируется', async () => {
  const e = env(); e.c.start(); e.send({ type: 'hello' }, 'https://evil.org'); e.send({ type: 'fetch', id: 1, url: 'https://app.example.org/app.js' }, 'https://evil.org'); await e.c.idle();
  assert.equal(e.sent.length, 0); // чужому origin ничего не отвечаем
  assert.equal(e.net.length, 0);
});

test('адрес API не запрашивается, служебный файл запрашивается', async () => {
  const e = env(); e.c.start(); e.send({ type: 'hello' });
  e.send({ type: 'fetch', id: 1, url: 'https://app.example.org/api/x' });
  e.send({ type: 'fetch', id: 2, url: 'https://app.example.org/app.js' });
  await e.c.idle();
  const r = e.replies('fetched');
  assert.equal(r.find((x) => x.id === 1).error, 'not-js');
  assert.ok(r.find((x) => x.id === 2).ok);
  assert.deepEqual(e.net, ['https://app.example.org/app.js']);
});

test('пауза между запросами не меньше 300 мс × 0.7, бюджет соблюдается', async () => {
  const e = env(); e.c.start(); e.send({ type: 'hello' }); e.send({ type: 'settings', delay: 10, budget: 2 });
  for (let i = 1; i <= 3; i++) e.send({ type: 'fetch', id: i, url: 'https://app.example.org/a' + i + '.js' });
  await e.c.idle();
  assert.equal(e.net.length, 2);
  assert.equal(e.replies('fetched').find((x) => x.id === 3).error, 'budget');
  assert.ok(e.sleeps.slice(1).every((ms) => ms >= 210));
});

test('после 429 хост блокируется', async () => {
  const e = env({ responses: { 'https://app.example.org/a.js': { status: 429, body: '' } } }); e.c.start(); e.send({ type: 'hello' });
  e.send({ type: 'fetch', id: 1, url: 'https://app.example.org/a.js' }); e.send({ type: 'fetch', id: 2, url: 'https://app.example.org/b.js' });
  await e.c.idle();
  assert.match(e.replies('fetched').find((x) => x.id === 1).blocked, /429/);
  assert.equal(e.replies('fetched').find((x) => x.id === 2).error, 'blocked');
  assert.equal(e.net.length, 1);
});

test('cookie-set пишет document.cookie строкой writeString', async () => {
  const e = env(); e.c.start(); e.send({ type: 'hello' });
  e.send({ type: 'cookie-set', id: 7, cookie: { name: 'a', value: '1', path: '/' } }); await e.c.idle();
  assert.equal(e.doc.cookie, 'a=1; path=/');
  assert.ok(e.replies('cookie-result').find((x) => x.id === 7).ok);
});

test('bye и stop очищают очередь', async () => {
  const e = env(); e.c.start(); e.send({ type: 'hello' });
  e.send({ type: 'fetch', id: 1, url: 'https://app.example.org/a.js' }); e.send({ type: 'fetch', id: 2, url: 'https://app.example.org/b.js' }); e.send({ type: 'bye' });
  await e.c.idle();
  assert.ok(e.net.length <= 1);
});

test('снимок: только читаемые фреймы своего origin; фрейм с ошибкой и чужой пропускаются', async () => {
  const e = env();
  const own = { contentDocument: { location: { href: 'https://app.example.org/widget' }, documentElement: { outerHTML: '<html>w</html>' }, querySelectorAll: () => [{ src: 'https://app.example.org/w.js' }] } };
  const thrower = { get contentDocument() { throw new Error('SecurityError'); } };
  const foreign = { contentDocument: null };
  const base = e.doc.querySelectorAll;
  e.doc.querySelectorAll = (sel) => (/iframe/.test(sel) ? [own, thrower, foreign] : base(sel));
  e.c.start(); e.send({ type: 'hello' }); await e.c.idle();
  assert.deepEqual(e.replies('snapshot')[0].page.frames, [{ url: 'https://app.example.org/widget', html: '<html>w</html>', scripts: ['https://app.example.org/w.js'] }]);
});

// Банка cookies как в браузере: cookie с domain= и без хранятся отдельно, document.cookie показывает обе
function jarEnv(initial) {
  const e = env(), jar = new Map(initial.map((c) => [c.name + '|' + (c.domain || ''), c]));
  Object.defineProperty(e.doc, 'cookie', {
    get: () => Array.from(jar.values()).map((c) => c.name + '=' + c.value).join('; '),
    set: (s) => { const [nv, ...attrs] = s.split(/;\s*/), i = nv.indexOf('='), name = nv.slice(0, i), value = nv.slice(i + 1); const a = Object.fromEntries(attrs.map((x) => { const [k, ...v] = x.split('='); return [k.toLowerCase(), v.join('=')]; })); const key = name + '|' + (a.domain || ''); if (a.expires && Date.parse(a.expires) < Date.now()) jar.delete(key); else jar.set(key, { name, value, domain: a.domain }); }
  });
  e.win.location.host = 'app.example.org';
  return { e, jar };
}

test('cookie без известного домена: правка заменяет cookie на весь домен, а не создаёт вторую', async () => {
  const { e, jar } = jarEnv([{ name: 'sid', value: 'old', domain: 'example.org' }]);
  e.c.start(); e.send({ type: 'hello' }); await e.c.idle();
  e.send({ type: 'cookie-set', id: 7, cookie: { name: 'sid', value: 'new', path: '/' } }); await e.c.idle();
  assert.deepEqual(Array.from(jar.values()), [{ name: 'sid', value: 'new', domain: 'example.org' }]);
  assert.equal(e.replies('cookie-result').find((r) => r.id === 7).ok, true);
  e.send({ type: 'cookie-delete', id: 8, cookie: { name: 'sid', value: 'new', path: '/' } }); await e.c.idle();
  assert.equal(jar.size, 0);
  assert.equal(e.replies('cookie-result').find((r) => r.id === 8).ok, true);
});

test('если вторая cookie с тем же именем осталась, ответ помечен duplicate, а не ok', async () => {
  const { e } = jarEnv([]);
  Object.defineProperty(e.doc, 'cookie', { get: () => 'sid=new; sid=other', set: () => {} });
  e.c.start(); e.send({ type: 'hello' }); await e.c.idle();
  e.send({ type: 'cookie-set', id: 9, cookie: { name: 'sid', value: 'new', path: '/', attrsKnown: true } }); await e.c.idle();
  const r = e.replies('cookie-result').find((x) => x.id === 9);
  assert.equal(r.ok, false); assert.equal(r.duplicate, true);
});

test('E3: сборщик только читает service worker, кеши и IndexedDB', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../src/collector.js', import.meta.url), 'utf8').replace(/\/\/.*$/gm, '');
  assert.ok(!/caches\.open|\.register\(|\.subscribe\(|indexedDB\.open|\.unregister\(|caches\.delete/.test(src));
  assert.ok(/getRegistrations\(\)/.test(src) && /caches\.keys\(\)/.test(src) && /indexedDB\.databases\(\)/.test(src));
});
