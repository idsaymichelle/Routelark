import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze, analyzeInto, Store, headerFindings, techFromText } from '../src/core.js';

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
const run = (text, src) => { const st = new Store('https://a.test/'); analyzeInto(st, text, src || 'https://a.test/x.js'); return st; };

test('04-F5/F7: cleanSource keeps src/, admin location is the source in the map', () => {
  const map = JSON.stringify({ version: 3, sources: ['webpack:///src/admin/panel.js', 'webpack://my-app/./src/x.js'], sourcesContent: ['fetch("/api/admin/x")', 'var a=1'] });
  const st = run(map, 'https://a.test/b.js.map');
  const adm = st.items.find((f) => f.kind === 'code' && /Admin component/.test(f.url));
  assert.match(adm.url, /src\/admin\//);
  assert.equal(adm.sources[0].file, 'https://a.test/b.js.map#src/admin/panel.js');
  assert.ok(st.files.length >= 0 && st.texts.has('https://a.test/b.js.map#src/x.js'));
});

test('04-F8: percent-encoded inline map is decoded', () => {
  const m = JSON.stringify({ version: 3, sources: ['a.js'], sourcesContent: ['var k="AKIAIOSFODNN7EXAMPLQ";'] });
  const a = analyze('x\n//# sourceMappingURL=data:application/json;charset=utf-8,' + encodeURIComponent(m), 'https://a.test/i.js');
  assert.equal(a.inlineMaps.length, 1);
  const b = analyze('x\n//# sourceMappingURL=data:application/json;base64,' + b64(JSON.parse(m)), 'https://a.test/i.js');
  assert.equal(b.inlineMaps.length, 1);
});

test('04-F9: map without sourcesContent gets a note', () => {
  const st = run(JSON.stringify({ version: 3, sources: ['a.js', 'b.js'] }), 'https://a.test/n.js.map');
  assert.ok(st.items.some((f) => /without sourcesContent: 2/.test(f.url)));
});

test('09-F7: CORS * with credentials is risk 1; fixed origin with credentials is reported', () => {
  const t = (o) => headerFindings({ 'access-control-allow-origin': o, 'access-control-allow-credentials': 'true' }, true, 'https://a.test/').filter((f) => /CORS/.test(f.title));
  assert.equal(t('*')[0].risk, 1);
  assert.equal(t('https://b.test')[0].risk, 1);
});

test('11-F2/F5: Angular runtime form, Vite not named from import.meta.env', () => {
  assert.deepEqual(techFromText('x[`ng-version`,`22.2.2`]'), [{ name: 'Angular', version: '22.2.2' }]);
  assert.deepEqual(techFromText('a=import.meta.env.MODE'), []);
});

test('11-F4: versioned banner reaches Stack', () => {
  const st = run('/*! foo-lib v1.2.3 */', 'https://a.test/a.js');
  assert.ok(st.items.some((f) => f.kind === 'tech' && f.url === 'foo-lib 1.2.3'));
});

test('29-F5/F7/F8: store hygiene', () => {
  const st = new Store('https://a.test/');
  st.replaceHeaders({ server: 'a' }, true); st.reset();
  assert.equal(st.docHeaders, null);
  assert.equal(st.addSimple('custom', { title: 't', risk: 7 }).level, 'critical');
});

test('34-F5: static items are not counted in total', () => {
  const st = new Store('https://a.test/'); st.addHit({ raw: '/a.png', via: 'string', file: 'x', line: 1, col: 1 }); st.addHit({ raw: '/api/x', via: 'call', method: 'GET', file: 'x', line: 1, col: 1 });
  assert.equal(st.counts().total, 1);
});

test('31-F9: chunk-map refs and relative call path', () => {
  const a = analyze('o.p="/static/js/";var u=o.p+{"1":"aaaaaa11","2":"bbbbbb22","3":"cccccc33"}[e]+".chunk.js"', 'https://a.test/main.js');
  assert.ok(a.refs.some((r) => r.via === 'chunk-map' && r.abs === 'https://a.test/static/js/1.aaaaaa11.chunk.js'), JSON.stringify(a.refs));
  const st = run('fetch("rest/items")', 'https://a.test/m.js');
  assert.ok(st.items.some((f) => f.path === '/rest/items'));
});

test('22-F7: analyze stays fast on keyword-heavy 200 KB input', () => {
  const t0 = Date.now(); analyze('host-dev.example.com a-a-a-a '.repeat(8000), 'https://a.test/big.js');
  analyze('api_key = x; token '.repeat(10000), 'https://a.test/big2.js');
  assert.ok(Date.now() - t0 < 3000);
});
