import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/core.js';
import { runScan } from '../src/app/scan.js';
import { connect } from '../src/app/link.js';
import { createCollector, channel } from '../src/collector.js';

const PAGE = 'https://app.example.org/shop';
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const JWT = b64({ alg: 'HS256' }) + '.' + b64({ sub: '1', role: 'admin' }) + '.sig';
const SNAP = {
  url: PAGE, contentType: 'text/html', html: '<html><script src="/app.js"></script><script>fetch("/api/inline")</script></html>',
  scripts: ['https://app.example.org/app.js'], links: [], resources: [{ url: 'https://app.example.org/api/seen?x=1', initiator: 'fetch', status: 200 }],
  globals: [{ name: 'jQuery', version: '3.4.1' }], ngVersion: null,
  storage: { local: [['token', JWT]], session: [] }, cookies: [{ name: 'sid', value: 'x', path: '/' }], cookieStore: false
};
const FILES = { 'https://app.example.org/app.js': 'axios.post("/api/v2/orders"); //# sourceMappingURL=app.js.map', 'https://app.example.org/app.js.map': JSON.stringify({ sources: ['a.js'], sourcesContent: ['fetch("/api/from-map")'] }) };
const fetcher = (asked) => async (url, o) => { asked.push(url + (o && o.doc ? '#doc' : '')); if (o && o.doc) return { ok: true, status: 200, headers: { server: 'nginx' }, text: '' }; return FILES[url] ? { ok: true, status: 200, headers: {}, text: FILES[url] } : { ok: false, status: 404, headers: {}, text: '' }; };
const memory = () => { const m = {}; return { get: (k) => m[k], set: (k, v) => { m[k] = v; }, del: (k) => { delete m[k]; } }; };

test('runScan: ходит только по служебным файлам, собирает всё из снимка', async () => {
  const asked = [], store = new Store(PAGE), osvCalls = [];
  await runScan({ store, snapshot: SNAP, fetchText: fetcher(asked), settings: { depth: 3, wellKnown: true, osv: true }, isStopped: () => false, osv: async (n, v) => { osvCalls.push(n + '@' + v); return [{ id: 'GHSA-xxxx', summary: 'тест' }]; }, history: memory() });
  assert.ok(!asked.some((u) => /\/api\//.test(u)), asked.join());
  assert.ok(asked.includes(PAGE + '#doc'));
  for (const u of ['/api/inline', '/api/v2/orders', '/api/from-map', '/api/seen?x=']) assert.ok(store.items.some((f) => f.url === u), u);
  assert.ok(store.items.find((f) => f.url === '/api/seen?x=').observed);
  const jq = store.items.find((f) => f.kind === 'tech' && f.name === 'jQuery');
  assert.ok(jq.advisories.some((a) => a.id === 'CVE-2020-11022') && jq.advisories.some((a) => a.id === 'GHSA-xxxx'));
  assert.deepEqual(osvCalls, ['jQuery@3.4.1']);
  assert.ok(store.items.some((f) => f.kind === 'secret' && f.sources[0].file === 'localStorage: token'));
  assert.ok(store.items.some((f) => f.kind === 'cookie' && /sid/.test(f.url)));
  assert.ok(store.items.some((f) => f.kind === 'config' && /server: nginx/.test(f.url)));
});

test('runScan: сравнение с прошлым запуском', async () => {
  const history = memory(), base = { fetchText: fetcher([]), settings: {}, isStopped: () => false, history };
  const first = await runScan(Object.assign({ store: new Store(PAGE), snapshot: SNAP }, base));
  assert.equal(first.diff, null);
  const snap2 = Object.assign({}, SNAP, { html: '<html><script src="/app.js"></script><script>fetch("/api/new-one")</script></html>' });
  const second = await runScan(Object.assign({ store: new Store(PAGE), snapshot: snap2 }, base));
  assert.ok(second.diff.added.some((f) => f.url === '/api/new-one'));
  assert.ok(second.diff.removed.some((id) => /api\/inline/.test(second.prevLabels[id])));
});

test('свои правила срабатывают на загруженных файлах', async () => {
  const store = new Store(PAGE);
  await runScan({ store, snapshot: SNAP, fetchText: fetcher([]), settings: { rules: [{ id: 'orders', title: 'Заказы', regex: 'v2/orders', risk: 2 }] }, isStopped: () => false });
  assert.ok(store.items.some((f) => f.kind === 'custom' && f.url === 'Заказы'));
});

test('link ↔ сборщик через прямой канал: снимок, файл, cookies', async () => {
  // Как в закладке: сборщик и интерфейс в одном окне, вкладка получает канал в __rlPort
  const pageWin = { setTimeout, location: { href: PAGE, origin: 'https://app.example.org' }, document: { contentType: 'text/html', cookie: '', documentElement: { outerHTML: SNAP.html }, querySelector: () => null, querySelectorAll: () => [] }, performance: { getEntriesByType: () => [] }, localStorage: { length: 0 }, sessionStorage: { length: 0 }, fetch: async (u) => ({ ok: true, status: 200, headers: new Map(), text: async () => FILES[u] || '' }) };
  const tab = { closed: false, addEventListener() {} }, ch = channel(pageWin, tab);
  tab.__rlPort = ch.port;
  createCollector(Object.assign({ sleep: async () => {} }, ch.collector)).start();
  const link = connect({ win: tab });
  const snap = await link.ready;
  assert.equal(snap.url, PAGE);
  const r = await link.fetchText('https://app.example.org/app.js', {});
  assert.match(r.text, /orders/);
  assert.equal((await link.fetchText('https://app.example.org/api/x', {})).error, 'not-js');
  const cs = await link.setCookie({ name: 'a', value: '1', path: '/', attrsKnown: true });
  assert.equal(pageWin.document.cookie, 'a=1; path=/');
  assert.ok(Array.isArray(cs.cookies));
  tab.closed = true; assert.equal(link.closed, false); // страница жива, даже если вкладку закрыли
});

test('npm: незарегистрированный scoped-пакет даёт находку, без настройки запросов нет', async () => {
  const snap = Object.assign({}, SNAP), asked = [];
  const map = JSON.stringify({ sources: ['webpack:///node_modules/@corp-internal/ui/index.js', 'webpack:///node_modules/@babel/runtime/x.js'], sourcesContent: ['', ''] });
  const fetchText = async (url) => (/\.map$/.test(url) ? { ok: true, status: 200, headers: {}, text: map } : /\.js$/.test(url) ? { ok: true, status: 200, headers: {}, text: '//# sourceMappingURL=app.js.map' } : { ok: false, status: 404, headers: {} });
  const store = new Store(PAGE);
  await runScan({ store, snapshot: snap, fetchText, settings: { depth: 3, wellKnown: false }, npm: async (n) => { asked.push(n); return n.startsWith('@corp') ? 404 : 200; } });
  assert.deepEqual(asked.sort(), ['@babel/runtime', '@corp-internal/ui']);
  assert.ok(store.items.some((f) => f.url === 'Package @corp-internal/ui is not on npm' && f.risk === 2));
});

test('runScan: фреймы своего origin разбираются, их скрипты скачиваются; страница с #/ хранится без хеша', async () => {
  const asked = [], store = new Store(PAGE + '#/login');
  const snap = Object.assign({}, SNAP, { url: PAGE + '#/login', frames: [{ url: 'https://app.example.org/widget', html: '<!-- TODO internal widget --><script>fetch("/api/from-frame")</script>', scripts: ['https://app.example.org/frame.js'] }, { url: 'about:blank', html: '', scripts: [] }] });
  await runScan({ store, snapshot: snap, fetchText: fetcher(asked), settings: { wellKnown: false, noRequests: false }, isStopped: () => false, history: null });
  assert.ok(store.items.some((f) => f.url === '/api/from-frame'));
  assert.ok(store.items.some((f) => f.kind === 'dom' && f.sources[0].file === 'https://app.example.org/widget'));
  assert.ok(asked.includes('https://app.example.org/frame.js'));
  assert.ok(store.texts.has(PAGE) && !store.texts.has(PAGE + '#/login'));
});

test('аудит: секрет из того же значения хранилища не попадает во фрагмент находки с персональными данными, поддомены скрыты в пакете для ИИ', async () => {
  const { toJSON, FORMATS } = await import('../src/core/export.js');
  const key = 'sk_live_' + 'aB3'.repeat(10);
  const snap = Object.assign({}, SNAP, { storage: { local: [['user', '{"card":"4539 5787 6362 1486","key":"' + key + '"}']], session: [] } });
  const store = new Store(SNAP.url);
  await runScan({ store, snapshot: snap, fetchText: fetcher([]), settings: { depth: 1, wellKnown: false, osv: false }, isStopped: () => false, history: memory() });
  assert.ok(store.items.some((f) => f.kind === 'pii'));
  assert.ok(!toJSON(store.list(), { reveal: false }).includes(key));
  const s = new Store('https://www.shop.example/');
  s.addSimple('infra', { title: 'Test-environment host: staging-api.shop.example', risk: 1, why: ['x'], file: 'a' });
  const ai = FORMATS.find((f) => f.id === 'ai').build(s, s.list(), {});
  assert.ok(!/shop\.example/.test(ai) && ai.includes('target.example'));
});

test('QA Wave 1: маски в хранилище, HAR, ключ PEM, отчёты, списки для сканеров', async () => {
  const { toJSON, FORMATS } = await import('../src/core/export.js');
  const { sessionFile } = await import('../src/core/session.js');
  const snap = Object.assign({}, SNAP, { storage: { local: [['user', '{"card":"4539 5787 6362 1486","email":"tom@x.com"}']], session: [] } });
  const store = new Store(SNAP.url);
  await runScan({ store, snapshot: snap, fetchText: fetcher([]), settings: { depth: 1, wellKnown: false, osv: false }, isStopped: () => false, history: memory() });
  const out = toJSON(store.list(), { reveal: false });
  assert.ok(!out.includes('tom@x.com') && !out.includes('4539 5787 6362 1486'), 'чужое значение во фрагменте');
  const s = new Store('https://a.example/');
  const get = (id, o) => FORMATS.find((f) => f.id === id).build(s, s.list(), Object.assign({ target: 'https://a.example/' }, o));
  assert.ok(!get('har', { traffic: [{ url: 'https://a.example/api?apikey=SECRET123456', t: 1 }] }).includes('SECRET123456'));
  const { analyzeInto } = await import('../src/core.js');
  analyzeInto(s, 'const k = `-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAexampleKEYBODY\n-----END RSA PRIVATE KEY-----`; fetch("https://evil.example/x"); fetch("/api/own"); var a="tom@x.com", b="tim@x.com";', 'https://a.example/a.js');
  assert.ok(!JSON.stringify(sessionFile(s)).includes('MIIE'));
  assert.equal(s.items.filter((f) => f.kind === 'pii' && f.type === 'email').length, 2, 'разные адреса с одной маской не сливаются');
  assert.ok(!get('urls').includes('evil.example') && get('urls').includes('/api/own'));
  s.addConfig({ risk: 2, title: 'T\n## X', why: 'w\n- [ ] fake' }, '(doc)');
  assert.ok(!/^## X|^- \[ \] fake/m.test(get('h1')));
});

test('QA Wave 2: остановленный скан, cookie с «;», офлайн-пачка, заглушка SPA, скоуп для realtime', async () => {
  const { writeString } = await import('../src/core/cookies.js');
  const { analyzeFiles } = await import('../src/app/offline.js');
  const { isOutOfProgram } = await import('../src/core/program.js');
  const { crawl, makeScope } = await import('../src/core.js');
  const hist = memory();
  await runScan({ store: new Store(SNAP.url), snapshot: SNAP, fetchText: fetcher([]), settings: { depth: 1, wellKnown: false, osv: false }, isStopped: () => false, history: hist });
  const stopped = await runScan({ store: new Store(SNAP.url), snapshot: SNAP, fetchText: fetcher([]), settings: { depth: 1, wellKnown: false, osv: false }, isStopped: () => true, history: hist });
  assert.equal(stopped.diff, null);
  const again = await runScan({ store: new Store(SNAP.url), snapshot: SNAP, fetchText: fetcher([]), settings: { depth: 1, wellKnown: false, osv: false }, isStopped: () => false, history: hist });
  assert.equal(again.diff.added.length, 0);
  assert.throws(() => writeString({ name: 'a', value: 'x;path=/admin' }));
  const f = (name, text) => ({ name, text: async () => text });
  const env = await analyzeFiles([f('app.env', 'STRIPE_KEY=sk_live_Ab3dEf7hIj9kLm2nOp4q')], '', {});
  assert.ok(env.store.items.some((x) => x.kind === 'secret') && !env.cookies.length);
  const sess = JSON.stringify({ format: 'routelark-session', version: 2, origin: 'https://x.test', url: 'https://x.test/', date: '2026-11-17', findings: [{ id: 'aaaaaaaa', kind: 'api', url: '/old', risk: 0 }] });
  const batch = await analyzeFiles([f('cap.har', JSON.stringify({ log: { entries: [{ request: { method: 'GET', url: 'https://x.test/api/harfirst' }, response: { status: 200 } }] } })), f('s.json', sess)], '', {});
  assert.ok(batch.store.items.some((x) => /harfirst/.test(x.url || '')) && batch.store.items.some((x) => x.url === '/old'));
  const s = new Store('https://a.example/'), files = { 'https://a.example/app.js.map': '<!-- SPA --><html></html>' };
  await crawl({ store: s, seeds: [{ url: 'https://a.example/app.js.map', depth: 1, via: 'sourcemap' }], fetchText: async (u) => ({ ok: true, status: 200, headers: {}, text: files[u] || '' }), isStopped: () => false, conc: 1, maxFiles: 10, maxDepth: 2, scope: makeScope({ pageUrl: 'https://a.example/' }) });
  assert.ok(!s.files.includes('https://a.example/app.js.map'));
  assert.ok(isOutOfProgram({ kind: 'realtime', host: '' }, 'localhost:3000', [{ host: 'nonexistent-example.test', wild: true, out: false }]));
});

test('тихий режим: ни одного своего запроса — ни к сайту, ни к OSV и npm', async () => {
  const { settingsFor } = await import('../src/app/modes.js');
  const asked = [], calls = [];
  const set = settingsFor('quiet', { depth: 3, wellKnown: true, osv: true, npmCheck: true, guessMaps: true });
  const store = new Store(SNAP.url);
  await runScan({ store, snapshot: SNAP, fetchText: fetcher(asked), settings: set, isStopped: () => false, osv: set.osv ? async () => { calls.push('osv'); return []; } : null, npm: set.npmCheck ? async () => { calls.push('npm'); return 200; } : null, history: memory() });
  assert.deepEqual(asked, []); assert.deepEqual(calls, []);
  assert.ok(store.items.length > 0); // снимок страницы всё равно разобран
  assert.equal(settingsFor('full', { osv: true }).osv, true);
});

test('кеш режимов: возврат без нового скана, сброс во время скана, ошибка не сохраняется', async () => {
  const { modeCache, scanChanged } = await import('../src/app/modes.js');
  const c = modeCache(), a = { store: 'A' }, b = { store: 'B' };
  const ta = c.start('quiet', a); assert.equal(c.get('quiet'), a); // идущий скан виден сразу
  assert.ok(c.finish('quiet', ta, { store: 'A', diff: 1 }, true)); assert.equal(c.get('quiet').diff, 1);
  const tb = c.start('full', b); c.drop('full'); // настройки сменились во время скана
  assert.equal(c.finish('full', tb, b, true), false); assert.equal(c.get('full'), null);
  const t2 = c.start('full', b); assert.equal(c.finish('full', t2, b, false), false); assert.equal(c.get('full'), null); // упал — не сохранён
  assert.deepEqual(c.drop(), ['quiet', 'full']); assert.equal(c.get('quiet'), null);
  assert.ok(scanChanged({ depth: 3 }, { depth: 2 })); assert.ok(!scanChanged({ depth: 3, lang: 'ru' }, { depth: 3, lang: 'en' }));
});
