import test from 'node:test'; import assert from 'node:assert/strict';
import { makeScope, clampSettings, FORCEABLE } from '../src/core/scope.js';
import { parseProgram } from '../src/core/program.js';
import { fileKey, readSession } from '../src/core/session.js';
import { parseTrafficExport } from '../src/core/imports.js';
import { mapping } from '../src/core/mapping.js';
import { fileType, isMinified, searchTexts } from '../src/core/files.js';
import { faviconHash } from '../src/core/favicon.js';
import { officeMeta, fontMeta } from '../src/core/office.js';
import { bountyReport } from '../src/core/reportdraft.js';
import { FORMATS } from '../src/core/export.js';

const sc = makeScope({ pageUrl: 'https://app.example.com/' });
test('scope: варианты logout и двойное кодирование запрещены, deleteModal нет', () => {
  for (const p of ['log-out.js', 'log_out.js', 'sign_out.js', 'deactivate.js', 'unsubscribe.js', '%256Cogout.js']) assert.equal(sc.check('https://app.example.com/' + p).ok, false, p);
  assert.equal(sc.check('https://app.example.com/js/deleteModal.chunk.js').ok, true);
  assert.equal(sc.check('https://app.example.com/api/x.xml', true).ok, false);
  assert.equal(sc.check('https://app.example.com/sitemap.xml', true).ok, true);
});
test('scope: allowHosts не пускает публичный суффикс', () => {
  assert.deepEqual(clampSettings({ allowHosts: ['*.com', '*', '*.a.com', 'x.com'] }).allowHosts, ['*.a.com', 'x.com']);
});
test('program: комментарий в конце строки и строка с [', () => {
  assert.deepEqual(parseProgram('example.com # main').rules.map((r) => r.host), ['example.com']);
  assert.deepEqual(parseProgram('[::1]\napi.example.com\n').rules.map((r) => r.host), ['api.example.com']);
});
test('session: fileKey убирает только настоящие хеши', () => {
  const k = (n) => fileKey('https://x/' + n);
  assert.equal(k('main.3f2a9c1b.js'), 'https://x/main.js'); assert.equal(k('index-Dk3vB9x2.js'), 'https://x/index.js');
  for (const n of ['vendor-analytics2024.js', 'vendor-admin-dashboard-2.js', 'chunk-ABCDEFGH.js']) assert.equal(k(n), 'https://x/' + n);
  assert.equal(readSession(JSON.stringify({ format: 'routelark-session', findings: [null, { id: 1 }] })).findings.length, 1);
});
test('imports: HAR только с абсолютным URL, Burp декодирует &amp;, список картинок не трафик', () => {
  const har = (u) => JSON.stringify({ log: { entries: [{ request: { url: u, method: 'GET' } }] } });
  for (const u of [42, 'javascript:alert(1)', '/rel']) assert.equal(parseTrafficExport(har(u)).requests.length, 0);
  const b = parseTrafficExport('<items burpVersion="2"><item><url>https://x.test/p?q=1&amp;r=2</url><method>GET</method></item><item><url><![CDATA[https://x.test/c?a=1&amp;b=2]]></url><method>GET</method></item></items>');
  assert.deepEqual(b.requests.map((r) => r.url), ['https://x.test/p?q=1&r=2', 'https://x.test/c?a=1&amp;b=2']);
  assert.equal(parseTrafficExport('[{"name":"logo","url":"https://cdn.x.test/logo.png"}]'), null);
});
test('mapping: JWT не CWE-347, CSP без CLNT-01', () => {
  assert.deepEqual(mapping({ kind: 'secret', type: 'jwt', url: 'x' }).cwe, ['CWE-798']);
  assert.deepEqual(mapping({ kind: 'config', url: 'Missing CSP' }).wstg, []);
});
test('files: svg — image, длинная строка, лимит на файл, пустой favicon', () => {
  assert.equal(fileType('https://x/logo.svg'), 'image');
  assert.equal(isMinified(('a\n'.repeat(1500)) + 'b'.repeat(4000)), true);
  assert.equal(searchTexts([{ url: 'u', text: 'a '.repeat(80) }], 'a').truncated, true);
  assert.equal(faviconHash(new Uint8Array(0)), 0);
});
test('office: сущности XML декодируются, шрифт берёт Windows-запись', async () => {
  const font = (recs) => { const n = recs.length, str = recs.map((r) => r.b), strLen = str.reduce((a, x) => a + x.length, 0), hdr = 6 + n * 12, b = new Uint8Array(12 + 16 + hdr + strLen), dv = new DataView(b.buffer);
    dv.setUint32(0, 0x10000); dv.setUint16(4, 1); b.set([110, 97, 109, 101], 12); dv.setUint32(20, 28); dv.setUint16(30 - 0, 0);
    dv.setUint32(12 + 8, 28); const o = 28; dv.setUint16(o + 2, n); dv.setUint16(o + 4, hdr); let off = 0;
    recs.forEach((r, i) => { const q = o + 6 + i * 12; dv.setUint16(q, r.p); dv.setUint16(q + 6, 1); dv.setUint16(q + 8, r.b.length); dv.setUint16(q + 10, off); b.set(r.b, o + hdr + off); off += r.b.length; }); return b; };
  const f = fontMeta(font([{ p: 1, b: Uint8Array.from([0x43, 0x61, 0x66, 0x8e]) }, { p: 3, b: Uint8Array.from([0, 0x43, 0, 0x61, 0, 0x66, 0, 0xe9]) }]));
  assert.deepEqual(f.fields, [['Family', 'Café']]);
});
test('reportdraft: $& в URL не раскрывается', () => {
  const st = { pageHost: 'a.test', pageUrl: 'https://a.test/?ref=$&tail', files: [], items: [] };
  const f = { kind: 'config', url: 'Missing CSP', risk: 2, why: ['w'], sources: [], cats: [], confidence: 'low', priority: false, id: 'i' };
  assert.ok(bountyReport(st, [f], { platform: 'h1' }).includes('Open https://a.test/?ref=$&tail.'));
});
test('export: CRLF и CR в CSV, nuclei path как YAML-строка, ', () => {
  const st = { pageHost: 'a.test', pageOrigin: 'https://a.test', pageUrl: 'https://a.test/', files: [], blocked: [], errors: [], deps: new Map(), paramStats: () => [], counts: () => ({ levels: {} }), list() { return []; } };
  const f = { id: 'i', kind: 'api', url: '/api/s/\\d+', path: '/api/s/\\d+', resolved: 'https://a.test/api/s/\\d+', method: 'GET', host: 'a.test', params: [], owasp: [], level: 'low', risk: 1, why: ['a\rb'], sources: [], confidence: 'low', observed: false };
  const get = (id, l) => FORMATS.find((x) => x.id === id).build(st, l || [f], {});
  const csv = get('csv'); assert.ok(csv.includes('\r\n') && !/[^\r]\n/.test(csv)); assert.ok(csv.includes('"a\rb"'));
  assert.ok(get('nuclei-template').includes('- "{{BaseURL}}/api/s/\\\\d+"'));
  assert.ok(get('md', [f]).includes('\\[') === false);
  assert.ok(get('html', [{ ...f, kind: 'static' }]).includes('Content-Security-Policy'));
});
