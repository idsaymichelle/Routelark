import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../src/core.js';
import { t, setLang, getLang, plural, RU } from '../src/i18n.js';
import { auditCookie } from '../src/core/cookies.js';
import { blockedReason } from '../src/core/scope.js';
import { FORMATS } from '../src/core/export.js';

const PAGE = 'https://app.example.org/';
const CYR = /[А-Яа-яЁё]/;
const FIXTURE = 'fetch("/api/admin/users/"+id,{method:"DELETE"}); var k="AKIAABCDEFGHIJKLMNOP"; fetch("/x?role=1&url=2&userId=3");'
  + ' var apiKey="aB3dE5gH7jK9mN2pQ4rS6tU"; var b="x.s3.amazonaws.com"; /*! jQuery v3.4.1 */ el.innerHTML = location.hash;'
  + ' window.addEventListener("message", function (e) { run(e.data); }); var r={path:"/admin/panel"}; var ip="10.0.0.5"; var m="dev@corp.io"; if (isAdmin) {} // TODO fix';

test('t: неизвестная строка не меняется в обоих языках', () => {
  for (const l of ['en', 'ru']) { setLang(l); assert.equal(t('x'), 'x'); assert.equal(t('some unknown {a}'), 'some unknown {a}'); assert.equal(t('a {n}', { n: 3 }), 'a 3'); assert.equal(t(undefined), undefined); }
  setLang('en');
});

test('RU: все ключи — непустые строки, отличающиеся от значения', () => {
  for (const [k, v] of Object.entries(RU)) { assert.ok(typeof v === 'string' && v.length, k); assert.notEqual(k, v); }
});

test('все why и заголовки находок кода переводятся на русский', () => {
  const s = new C.Store(PAGE);
  C.analyzeInto(s, FIXTURE, PAGE + 'app.js');
  C.headerFindings({ server: 'nginx', 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }, true).forEach((c) => s.addConfig({ risk: c.risk, title: c.title, why: c.why }, '(document)'));
  assert.ok(s.items.length > 8);
  setLang('ru');
  const bad = [];
  for (const f of s.items) {
    f.why.forEach((w) => { if (!CYR.test(t(w)) && !/^server: /.test(w)) bad.push(w); });
    if ((f.kind === 'code' || f.kind === 'config') && !CYR.test(t(f.url)) && !/^server: /.test(f.url)) bad.push(f.url);
  }
  const extra = [].concat(
    auditCookie({ name: 'sid', value: 'x'.repeat(5000), secure: false, sameSite: 'None', attrsKnown: true, expires: Date.now() + 500 * 864e5 }, true).why,
    [blockedReason({ status: 429 }), blockedReason({ headers: { 'cf-mitigated': 'challenge' } })],
    [C.eolNote('AngularJS', '1.8.0'), C.eolNote('Vue', '2.7.0'), C.eolNote('jQuery', '1.12.4'), C.eolNote('Bootstrap', '3.3.7'), C.eolNote('Moment.js', '2.29.4')],
    C.jwtInfo('eyJhbGciOiJub25lIn0.' + Buffer.from('{"role":"a"}').toString('base64url') + '.').why.filter((w) => !/^(?:alg=none|claims: )/.test(w))
  );
  extra.forEach((w) => { if (!CYR.test(t(w))) bad.push(w); });
  setLang('en');
  assert.deepEqual(bad, []);
});

test('plural: en и ru', () => {
  const f = { en: ['finding', 'findings'], ru: ['находка', 'находки', 'находок'] };
  assert.equal(plural(1, f), '1 finding'); assert.equal(plural(2, f), '2 findings'); assert.equal(plural(5, f), '5 findings');
  setLang('ru');
  assert.equal(plural(1, f), '1 находка'); assert.equal(plural(2, f), '2 находки'); assert.equal(plural(5, f), '5 находок'); assert.equal(plural(21, f), '21 находка'); assert.equal(plural(12, f), '12 находок');
  setLang('en');
  assert.equal(getLang(), 'en');
});

test('отчёт Markdown следует языку', () => {
  const s = new C.Store(PAGE);
  C.analyzeInto(s, FIXTURE, PAGE + 'app.js');
  const md = FORMATS.find((x) => x.id === 'md');
  assert.match(md.build(s, s.list(), {}), /## Summary/);
  setLang('ru');
  const ru = md.build(s, s.list(), {}), json = FORMATS.find((x) => x.id === 'json').build(s, s.list(), {});
  setLang('en');
  assert.match(ru, /## Сводка/);
  assert.doesNotMatch(json, /[А-Яа-яЁё]/); // machine formats are not translated
});

test('данные сайта не переводятся: имя файла и сниппет остаются как есть', async () => {
  const { tLabel } = await import('../src/i18n.js');
  setLang('ru');
  assert.equal(tLabel('localStorage: a, fixed in b'), 'localStorage: a, fixed in b');
  assert.equal(tLabel('info'), 'info');
  assert.equal(tLabel('(page)'), '(страница)');
  setLang('en');
});

test('у каждой строки интерфейса t(\'…\') есть русский перевод', async () => {
  const { readdirSync, readFileSync } = await import('node:fs');
  const files = ['src/app/main.js', 'src/app/scan.js'].concat(readdirSync('src/app/ui').map((f) => 'src/app/ui/' + f));
  const miss = new Set();
  for (const f of files) for (const m of readFileSync(f, 'utf8').matchAll(/\bt\('((?:[^'\\]|\\.)+)'/g)) { const k = m[1].replace(/\\'/g, "'"); if (!(k in RU)) miss.add(k); }
  assert.deepEqual(Array.from(miss), []);
});

test('QA Wave 5: подписи вкладок, разделов и статусов переведены; Scope с push; OWASP API', async () => {
  const { readFileSync } = await import('node:fs');
  const src = (f) => readFileSync(new URL('../src/' + f, import.meta.url), 'utf8');
  const tech = /^(?:API|HTML|JSON|CSS|JavaScript|SameSite|Lax|Strict|None|Cookies|GraphQL|Web3|WebSocket|OWASP.*|ASVS.*|CWE)$/;
  const labels = [...src('app/main.js').matchAll(/\['[a-z]+', '([^']+)'\]/g), ...(/const NAMES = \{([^}]*)\}/.exec(src('app/ui/overview.js'))[1]).matchAll(/[a-z]+: '([^']+)'/g), ...src('app/ui/compliance.js').matchAll(/(?:pass|fail|check|na): '([^']+)'/g)].map((m) => m[1]);
  const missing = Array.from(new Set(labels)).filter((l) => !tech.test(l) && !(l in RU));
  assert.deepEqual(missing, []);
  setLang('ru');
  assert.match(t('Scope https://a/, push subscription at fcm.example/x…. A service worker sees every request in its scope: read its script in Files'), /подписка на push/);
  assert.ok(CYR.test(t('Broken Object Level Authorization')));
  setLang('en');
});

test('QA Wave 5: CLNT-04 только для перенаправлений, шаги черновика для стека', async () => {
  const { complianceRows } = await import('../src/core/compliance.js');
  const { bountyReport } = await import('../src/core/reportdraft.js');
  const s = new C.Store(PAGE); s.files.push(PAGE + 'a.js');
  C.analyzeInto(s, 'fetch("/api/x?url=" + u)', PAGE + 'a.js');
  assert.equal(complianceRows(s, { cookies: [] }).find((r) => r.id === 'CLNT-04').status, 'na');
  s.addTech({ name: 'jQuery', version: '3.4.0' }, PAGE + 'a.js');
  assert.match(bountyReport(s, s.list().filter((f) => f.kind === 'tech'), {}), /Check the library version/);
});
