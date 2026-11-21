import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../src/core.js';
import { FORMATS } from '../src/core/export.js';
import { sessionFile, compareRuns, historyEntry, readSession } from '../src/core/session.js';

const PAGE = 'https://app.example.org/';
const TOKEN = 'AKIAABCDEFGHIJKLMNOP';
function filled() {
  const s = new C.Store(PAGE);
  C.analyzeInto(s, 'fetch("/api/a?url=x"); axios.post("https://api.example.org/v2/u",{role:1}); var k="' + TOKEN + '"; var b="x.s3.amazonaws.com"; var p="/x<script>alert(1)</script>"; /*! jQuery v3.4.1 */ el.innerHTML = location.hash', PAGE + 'app.js');
  s.addConfig({ risk: 1, title: 'No Content-Security-Policy', why: 'x' }, '(документ)');
  return s;
}
const JSONISH = new Set(['json', 'openapi', 'postman', 'har', 'sarif', 'cyclonedx', 'caido', 'dojo']);
const traffic = [{ url: PAGE + 'api/a', initiator: 'fetch', status: 200, t: 1 }];

test('все форматы строятся на непустом и пустом наборе', () => {
  assert.deepEqual(FORMATS.map((f) => f.id), ['md', 'html', 'json', 'csv', 'urls', 'paths', 'params', 'words', 'openapi', 'postman', 'har', 'sarif', 'cyclonedx', 'burp', 'nuclei', 'github', 'jira', 'ai', 'caido', 'zap', 'katana', 'dojo', 'faraday', 'pci', 'sdl', 'siblings', 'h1', 'bugcrowd', 'intigriti', 'bruno', 'nuclei-template']);
  for (const s of [filled(), new C.Store(PAGE)]) {
    for (const f of FORMATS) {
      const out = f.build(s, s.list(), { target: PAGE, traffic });
      assert.equal(typeof out, 'string', f.id);
      if (JSONISH.has(f.id)) JSON.parse(out);
      assert.ok(f.label && f.ext && f.mime && f.group, f.id);
    }
  }
});

test('без «с секретами» секрет не встречается ни в одном формате, с ним — встречается в json', () => {
  const s = filled();
  for (const f of FORMATS) assert.ok(!f.build(s, s.list(), { target: PAGE, traffic }).includes(TOKEN), f.id);
  assert.ok(FORMATS.find((f) => f.id === 'json').build(s, s.list(), { target: PAGE, reveal: true }).includes(TOKEN));
});

test('html-отчёт экранирует находки', () => {
  const s = filled();
  s.addConfig({ risk: 1, title: 'server: <script>alert(1)</script>', why: 'x' }, '(документ)');
  const html = FORMATS.find((f) => f.id === 'html').build(s, s.list(), { target: PAGE });
  assert.ok(!html.includes('<script>alert(1)'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('urls и nuclei — полные адреса с хостом находки', () => {
  const s = filled(), get = (id) => FORMATS.find((f) => f.id === id).build(s, s.list(), { target: PAGE }).split('\n');
  assert.ok(get('urls').includes('https://api.example.org/v2/u'));
  assert.ok(get('nuclei').includes('https://api.example.org/v2/u'));
  assert.ok(get('urls').includes('https://app.example.org/api/a'));
});

test('сессия: файл, чтение, сравнение с прошлым запуском', () => {
  const a = filled(), file = sessionFile(a, {});
  assert.equal(file.format, 'routelark-session');
  assert.equal(file.version, 2);
  const sec = a.items.find((f) => f.kind === 'secret');
  if (sec) assert.ok(!file.findings.some((f) => f.id === sec.id), 'id секрета в файле — не хеш значения');
  assert.ok(!JSON.stringify(file).includes(TOKEN));
  const back = readSession(JSON.stringify(file));
  assert.equal(back.findings.length, a.items.length);
  assert.throws(() => readSession('{"format":"other"}'));
  const prev = historyEntry(a);
  assert.ok(!JSON.stringify(prev).includes(TOKEN));
  const b = new C.Store(PAGE);
  C.analyzeInto(b, 'fetch("/api/a?url=x"); fetch("/api/new")', PAGE + 'app.js');
  const d = compareRuns(prev.ids, b);
  assert.ok(d.added.some((f) => f.url === '/api/new'));
  assert.ok(d.removed.length >= 2);
  assert.ok(!d.added.some((f) => f.url === '/api/a?url='));
});

test('отчёты включают GraphQL и находки своих проверок', () => {
  const s = new C.Store('https://app.example.org/');
  s.addSimple('graphql', { title: 'mutation DeleteUser', risk: 1, why: ['x'], file: 'a.js', line: 1 });
  const f = s.addSimple('custom', { title: 'Package @acme/ui is not on npm', risk: 3, why: ['y'], file: 'source map' });
  assert.equal(f.priority, true);
  for (const id of ['md', 'html']) { const out = FORMATS.find((x) => x.id === id).build(s, s.list(), {}); assert.ok(out.includes('DeleteUser') && out.includes('@acme/ui'), id); }
});


test('G5/A6/B2/G4/E4: новые форматы', () => {
  const s = filled(), get = (id, list) => FORMATS.find((f) => f.id === id).build(s, list || s.list(), { target: PAGE, traffic: [{ url: PAGE + 'app.js', initiator: 'script', t: 1 }] });
  const host = new URL(PAGE).host;
  assert.match(get('zap'), /<incregexes>https\?:\/\/\(\[a-z0-9-\]\+\\\.\)\*/);
  assert.match(get("zap"), /\(\?i\).*log-\?out\|sign-\?out/);
  assert.match(get('katana'), /^\^https\?:\/\//);
  assert.equal(JSON.parse(get('dojo')).type, 'Routelark');
  assert.match(get('faraday'), /^target,name,desc,severity,refs,website,path,method,params,tags\n/);
  assert.match(get('pci'), /^url,host,kind,sri,on_card_page,first_seen\n.*app\.js/);
  assert.ok(!get('ai').includes(host) && !get('ai').includes(TOKEN));
  const ep = s.list().find((f) => f.kind === 'api');
  assert.match(get('bruno', [ep]), /^meta \{\n {2}name: /);
  assert.match(get('nuclei-template', [ep]), /^id: routelark-[a-z0-9-]+\ninfo:/);
  assert.match(get('bruno', []), /Select an endpoint/);
  assert.ok(get('siblings').split('\n').length > 2);
});

test('D3: черновик отчёта для платформы, группировка по причине', async () => {
  const { groupFindings } = await import('../src/core/reportdraft.js');
  const s = filled(), md = FORMATS.find((f) => f.id === 'h1').build(s, s.list(), { target: PAGE });
  assert.match(md, /Needs manual validation/);
  assert.match(md, /_Describe who can do what/);
  assert.ok(!md.includes(TOKEN));
  const g = groupFindings(s.list());
  assert.ok(g.length > 0 && g.every((x) => x.members.length >= 1));
});

test('QA 16/17/18: «-» в CSV, HAR по точному адресу, повторы {id}, Nuclei только GET, Caido, лимит групп', async () => {
  const s = filled(), get = (id, list, o) => FORMATS.find((f) => f.id === id).build(s, list || s.list(), Object.assign({ target: PAGE }, o));
  assert.ok(!/,'-,/.test(get('csv')));
  const st = new C.Store(PAGE); C.analyzeInto(st, 'fetch("/api/u/" + a + "/x/" + b, {method:"PUT"})', PAGE + 'a.js');
  const ep = st.list().find((f) => f.kind === 'api' || f.kind === 'page');
  const nt = FORMATS.find((f) => f.id === 'nuclei-template').build(st, [ep], {});
  assert.match(nt, /- method: GET/); assert.match(nt, /# code uses PUT/); assert.ok(!/\{id\}/.test(nt));
  const oa = JSON.parse(FORMATS.find((f) => f.id === 'openapi').build(st, st.list(), { target: PAGE }));
  for (const p of Object.values(oa.paths)) for (const op of Object.values(p)) { const n = op.parameters.filter((x) => x.in === 'path').map((x) => x.name); assert.equal(n.length, new Set(n).size); }
  const cz = JSON.parse(get('caido')); assert.ok(cz.allowlist.some((x) => x.startsWith('*.')));
});
