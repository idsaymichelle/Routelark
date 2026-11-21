import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../src/core.js';
import { innOk, snilsOk, ogrnOk, ogrnipOk, ssnOk } from '../src/core/pii.js';
import { parseTrafficExport } from '../src/core/imports.js';
import { displayPosition, prettyJs } from '../src/core/files.js';
import { authMap } from '../src/core/map.js';
import { connect } from '../src/app/link.js';

test('INN 12-digit checksum: known valid accepted, flipped last digit rejected', () => {
  assert.equal(innOk('500100732259'), true);
  assert.equal(innOk('500100732258'), false);
  assert.equal(innOk('770708389'), false);
});
test('SNILS checksum, 001-001-998 exemption returns null', () => {
  assert.equal(snilsOk('112-233-445 95'), true);
  assert.equal(snilsOk('112-233-445 96'), false);
  assert.equal(snilsOk('001-001-998 00'), null);
});
test('OGRN and OGRNIP checksums', () => {
  assert.equal(ogrnOk('1027700132195'), true);
  assert.equal(ogrnOk('1027700132196'), false);
  assert.equal(ogrnipOk('304500116000157'), true);
  assert.equal(ogrnipOk('304500116000158'), false);
});
test('SSN structural rules reject 000, 666, 9xx, 00 group, 0000 serial', () => {
  assert.equal(ssnOk('123-45-6789'), true);
  for (const bad of ['000-12-3456', '666-12-3456', '900-12-3456', '123-00-4567', '123-45-0000', '12345-6789'])
    assert.equal(ssnOk(bad), false, bad);
});

const PAGE = 'https://app.acme-shop.io/';
test('robots.txt: Disallow path becomes a hit, cross-host Sitemap is not followed', () => {
  const s = new C.Store(PAGE); const enq = [];
  C.analyzeInto(s, 'User-agent: *\nDisallow: /admin\nSitemap: https://cdn.other.io/s.xml', PAGE + 'robots.txt', { enqueue: (...a) => enq.push(a) });
  assert.ok(s.items.some((f) => f.url === '/admin' || f.raw === '/admin'), JSON.stringify(s.items.map((f) => f.url)));
  assert.equal(enq.length, 1);
});
test('sitemapindex enqueues at most 5 children', () => {
  const s = new C.Store(PAGE); const enq = [];
  const locs = Array.from({ length: 9 }, (_, i) => `<sitemap><loc>https://app.acme-shop.io/s${i}.xml</loc></sitemap>`).join('');
  C.analyzeInto(s, `<?xml version="1.0"?><sitemapindex>${locs}</sitemapindex>`, PAGE + 'sitemap.xml', { enqueue: (...a) => enq.push(a) });
  assert.equal(enq.length, 5);
});
test('sitemap urlset keeps same-host paths only', () => {
  const s = new C.Store(PAGE);
  C.analyzeInto(s, '<urlset><url><loc>https://app.acme-shop.io/pricing</loc></url><url><loc>https://evil.io/x</loc></url></urlset>', PAGE + 'sitemap.xml', {});
  const raws = s.items.map((f) => f.raw || f.url);
  assert.ok(raws.includes('/pricing'), JSON.stringify(raws));
  assert.ok(!raws.some((r) => String(r).includes('evil')), JSON.stringify(raws));
});
test('внешний скрипт получает via external-script, внешний не-скрипт — нет', async () => {
  const s = new C.Store(PAGE), asked = [];
  await C.crawl({ store: s, seeds: [{ url: 'https://cdn.other.io/lib.js', depth: 1, via: 'script-src' }, { url: 'https://cdn.other.io/page', depth: 1, via: 'link' }], fetchText: async (u) => { asked.push(u); return { ok: false }; }, isStopped: () => false, conc: 1, maxFiles: 10, maxDepth: 1, scope: C.makeScope({ pageUrl: PAGE }) });
  assert.deepEqual(asked, []);
  assert.ok(s.items.some((f) => (f.vias || []).includes('external-script') && /lib\.js$/.test(f.resolved)));
  assert.ok(!s.items.some((f) => (f.vias || []).includes('external-script') && /\/page$/.test(f.resolved || '')));
});

test('QA 19/20/34/31-F8: импорт, Files, модель, канал', () => {
  // unclosed <item> must not cause quadratic time; broken ZAP; base64 bodies
  const t0 = Date.now(); parseTrafficExport('<items burpVersion="1">' + '<item>'.repeat(50000)); assert.ok(Date.now() - t0 < 1000);
  assert.deepEqual(parseTrafficExport(JSON.stringify({ site: [null, { alerts: [null, { instances: [{ uri: 'https://a.b/x', method: 'GET' }] }] }] })).requests, [{ url: 'https://a.b/x', method: 'GET' }]);
  const har = { log: { entries: [{ request: { url: 'https://a.b/' }, response: { content: { encoding: 'base64', text: Buffer.from('fetch("/api/hidden")').toString('base64') } } }] } };
  assert.deepEqual(parseTrafficExport(JSON.stringify(har)).bodies, ['fetch("/api/hidden")']);
  const inj = '<items burpVersion="1"><item><url><![CDATA[https://a.com/x]]></url><method>GET</method><response base64="false"><![CDATA[foo <item><url>https://evil.com/inj</url><method>POST</method></item>]]></response></item></items>';
  assert.deepEqual(parseTrafficExport(inj).requests, [{ url: 'https://a.com/x', method: 'GET' }]);
  // semicolons inside a parenthesized function split into lines; position in reformatted JSON
  assert.equal(prettyJs('(function(){a();b();})()').split('\n').length >= 4, true);
  const j = '{"a":1,"b":{"key":"s"},"c":{"key":2}}';
  assert.deepEqual(displayPosition(j, 'json', 1, j.lastIndexOf('"key') + 1), { line: 7, col: 5 });
  // '?' does not stick to the first method; externals not in levels; auth map without externals
  const s = new C.Store('https://a.example/');
  s.addHit({ raw: '/api/w', method: 'POST', via: 'call', file: 'x', line: 1, col: 1 });
  s.addHit({ raw: '/api/w', method: 'GET', via: 'call', file: 'x', line: 1, col: 1 });
  s.addHit({ raw: '/api/w', via: 'string', file: 'y', line: 2, col: 1 });
  const w = s.items.filter((f) => f.path === '/api/w');
  assert.equal(w.length, 2); assert.ok(w.every((f) => f.sources.length === 2));
  s.addHit({ raw: 'https://cdn.other.io/x?email=1', via: 'string', file: 'x', line: 1, col: 1 });
  assert.ok(!s.addHit({ raw: 'https://{host}/x', via: 'string', file: 'x', line: 1, col: 1 }));
  const ext = s.items.find((f) => f.kind === 'external'); assert.ok(ext);
  const c = s.counts(); assert.equal(Object.values(c.levels).reduce((a, b) => a + b, 0), c.total);
  assert.ok(!authMap(s).some((r) => r.host === 'cdn.other.io'));
});

test('31-F8: канал принимает cookies только с origin страницы', async () => {
  let fn; const opener = { closed: false, postMessage() {} };
  const win = { __rlPort: { opener, listen: (f) => { fn = f; } } };
  const link = connect({ win }); const got = [];
  link.onCookies((c) => got.push(c));
  fn({ source: opener, origin: 'https://app.example.org', data: { rl: 2, type: 'snapshot', page: { url: 'https://app.example.org/' } } });
  fn({ source: opener, origin: 'https://evil.example', data: { rl: 2, type: 'cookies', cookies: [1] } });
  assert.equal(got.length, 0);
  fn({ source: opener, origin: 'https://app.example.org', data: { rl: 2, type: 'cookies', cookies: [1] } });
  assert.equal(got.length, 1);
});

test('проверка волны low: итог и плитки сходятся, React/react одна запись, [id] в Markdown без слэшей, fileType по якорю', async () => {
  const { toMarkdown } = await import('../src/core/export.js');
  const { fileType } = await import('../src/core/files.js');
  const s = new C.Store('https://a.test/');
  s.addTech({ name: 'React', version: '18.2.0' }, 'x'); s.addTech({ name: 'react', version: '18.2.0' }, 'y');
  s.addHit({ raw: '/a.png', file: 'x', line: 1, col: 1 }); s.addHit({ raw: '/api/users/[id]', via: 'call', file: 'x', line: 1, col: 1 }); s.addHit({ raw: 'https://ext.com/api', via: 'call', file: 'x', line: 1, col: 1 });
  assert.equal(s.items.filter((f) => f.kind === 'tech').length, 1);
  const c = s.counts(); assert.equal(Object.values(c.levels).reduce((a, b) => a + b, 0), c.total);
  assert.ok(!/\\\[/.test(toMarkdown(s, {})));
  assert.equal(fileType('https://a.test/x.js#y'), 'js'); assert.equal(fileType('https://a.test/x.svg#y'), 'image');
});

test('аудит: ответ без Content-Length режется по пределу при чтении; обход стоит после исчерпания лимита; deniedPath одно правило', async () => {
  const { createCollector } = await import('../src/collector.js');
  const { deniedPath } = await import('../src/core/scope.js');
  const chunk = new TextEncoder().encode('a'.repeat(5e6)); let reads = 0, cancelled = false;
  const sent = [], listeners = [], tab = { closed: false, postMessage: (m) => sent.push(m) };
  const win = { location: { href: 'https://a.test/p', origin: 'https://a.test', pathname: '/p', search: '' }, document: { contentType: 'text/html', cookie: '' },
    addEventListener: (t, fn) => listeners.push(fn), setTimeout,
    fetch: async () => ({ status: 200, ok: true, headers: new Map(), body: { getReader: () => ({ read: async () => (++reads > 100 ? { done: true } : { value: chunk, done: false }), cancel: async () => { cancelled = true; } }) } }) };
  const c = createCollector({ win, tab, sleep: async () => {} }); c.start();
  listeners.forEach((fn) => fn({ origin: 'https://a.test', source: tab, data: { rl: 2, type: 'fetch', id: 1, url: 'https://a.test/big.js' } }));
  await c.idle();
  const r = sent.find((m) => m.type === 'fetched');
  assert.equal(r.error, 'too-large'); assert.ok(cancelled); assert.ok(reads < 10);
  // crawl: after 'budget' the remaining files are not requested
  const s = new C.Store('https://a.test/'); let n = 0;
  await C.crawl({ store: s, seeds: Array.from({ length: 50 }, (_, i) => ({ url: 'https://a.test/' + i + '.js', depth: 1 })), fetchText: async () => (++n > 5 ? { ok: false, status: 0, error: 'budget' } : { ok: true, status: 200, text: 'var a', headers: {} }), isStopped: () => false, conc: 1, maxFiles: 2000, maxDepth: 3, scope: C.makeScope({ pageUrl: 'https://a.test/' }) });
  assert.equal(n, 6);
  assert.ok(deniedPath('/%256Cogout')); assert.ok(deniedPath('/a?action=logout')); assert.ok(!deniedPath('/catalog'));
});
