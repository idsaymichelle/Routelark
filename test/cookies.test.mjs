import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCookieHeader, parseCookieInput, exportCookies, decodeValue, auditCookie, writeString, deleteString } from '../src/core/cookies.js';

const pick = (l) => l.map((c) => [c.name, c.value, c.path, !!c.secure].join('|'));
const LIST = [
  { name: 'sid', value: 'abc%3D123', path: '/', secure: true, sameSite: 'Lax', domain: 'app.site.com', hostOnly: true, expires: Date.UTC(2030, 0, 1) },
  { name: 'pref', value: '{"t":"dark"}', path: '/app', secure: false, domain: '.site.com', hostOnly: false }
];

test('экспорт→импорт без потерь (json, netscape)', () => {
  for (const fmt of ['json', 'netscape']) assert.deepEqual(pick(parseCookieInput(exportCookies(LIST, fmt))), pick(LIST), fmt);
});

test('netscape: #HttpOnly_ только для httpOnly, TRUE во втором поле только для доменной', () => {
  const lines = exportCookies(LIST, 'netscape').split('\n');
  assert.ok(lines[0].startsWith('app.site.com\tFALSE\t'));
  assert.ok(lines[1].startsWith('.site.com\tTRUE\t'));
  assert.ok(exportCookies([{ name: 'a', value: '1', domain: 'x.com', httpOnly: true }], 'netscape').startsWith('#HttpOnly_x.com'));
});

test('заголовок Cookie и разбор строк', () => {
  assert.equal(exportCookies(LIST, 'header'), 'sid=abc%3D123; pref={"t":"dark"}');
  assert.deepEqual(parseCookieHeader('a=1; b=2=3; ;c').map((c) => c.name + '=' + c.value), ['a=1', 'b=2=3']);
  assert.equal(parseCookieInput('a=1; b=2').length, 2);
  const sc = parseCookieInput('token=xyz; Path=/api; Secure; SameSite=Strict; Domain=.site.com')[0];
  assert.deepEqual([sc.name, sc.value, sc.path, sc.secure, sc.sameSite, sc.domain, sc.hostOnly], ['token', 'xyz', '/api', true, 'Strict', '.site.com', false]);
});

test('writeString: host-only без domain, порт отбрасывается', () => {
  assert.ok(!writeString({ name: 'a', value: '1' }, 'site.com:8443').includes('domain='));
  assert.ok(!writeString({ name: 'a', value: '1', domain: 'app.site.com' }, 'app.site.com').includes('domain='));
  const d = writeString({ name: 'a', value: '1', domain: '.site.com', hostOnly: false, secure: true, sameSite: 'None', expires: Date.UTC(2030, 0, 1) }, 'app.site.com');
  assert.match(d, /^a=1; path=\/; domain=\.site\.com; secure; samesite=None; expires=Tue, 01 Jan 2030 00:00:00 GMT$/);
  assert.match(deleteString({ name: 'a', path: '/x' }, 'site.com'), /^a=; path=\/x; expires=Thu, 01 Jan 1970/);
});

test('decodeValue: url, base64, JSON, JWT, unix', () => {
  const labels = (v) => decodeValue(v).map((d) => d.label);
  assert.ok(labels('abc%3D123').includes('URL'));
  assert.ok(labels('eyJ0IjoxfQ==').includes('base64'));
  assert.ok(labels('{"t":1}').includes('JSON'));
  assert.ok(labels('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig').includes('JWT'));
  assert.ok(labels('1700000000').includes('Time'));
});

test('auditCookie: сессионная без Secure на https и без SameSite', () => {
  const a = auditCookie({ name: 'sid', value: 'x', secure: false, sameSite: null, attrsKnown: true }, true);
  assert.ok(a.risk >= 2);
  assert.ok(a.why.length >= 2);
  assert.equal(auditCookie({ name: 'theme', value: 'dark' }, true).risk, 0);
});

test('Netscape: host-only cookie переживает экспорт и импорт', () => {
  const back = parseCookieInput(exportCookies([{ name: 'sid', value: 'a', hostOnly: true }], 'netscape'));
  assert.equal(back.length, 1);
  assert.equal(back[0].name, 'sid');
});
test('JSON от Playwright: expires в секундах, -1 — сессия', () => {
  const [a, b] = parseCookieInput(JSON.stringify([{ name: 'a', value: '1', expires: 1893456000 }, { name: 'b', value: '2', expires: -1 }]));
  assert.equal(new Date(a.expires).getUTCFullYear(), 2030);
  assert.equal(b.expires, undefined);
});

test('cookieVariants: хост и родительские домены до регистрируемого; IP и localhost — только хост', async () => {
  const { cookieVariants } = await import('../src/core/cookies.js');
  assert.deepEqual(cookieVariants('a.shop.example.org', 'example.org').map((v) => v.domain || 'host'), ['host', 'a.shop.example.org', 'shop.example.org', 'example.org']);
  assert.deepEqual(cookieVariants('localhost:3000', 'localhost'), [{ hostOnly: true }]);
  assert.deepEqual(cookieVariants('10.0.0.5', '10.0.0.5'), [{ hostOnly: true }]);
});

test('cookie из Set-Cookie проходит проверку атрибутов', () => {
  const [c] = parseCookieInput('Set-Cookie: sid=abc; Path=/; HttpOnly');
  assert.equal(c.attrsKnown, true);
  assert.ok(auditCookie(c, true).risk >= 2);
});

test('QA 06/08/09/10/11/12: имена cookie, sameSite из JSON, Netscape-домен, продолжение заголовка, html, ghost, Angular', async () => {
  const { auditCookie, parseCookieInput, exportCookies } = await import('../src/core/cookies.js');
  const { auditHtml } = await import('../src/core/html.js');
  const { ghostRoutes } = await import('../src/core/ghost.js');
  const { matchAdvisories } = await import('../src/core/advisories.js');
  const { consentCase } = await import('../src/core/trackers.js');
  const C = await import('../src/core.js');
  assert.equal(auditCookie({ name: 'sidebar_state', value: 'x' }, true).risk, 0);
  assert.ok(auditCookie({ name: 'sessionid', value: 'x' }, true).risk >= 2);
  assert.equal(parseCookieInput('[{"name":"a","value":"1","sameSite":"no_restriction"}]')[0].sameSite, 'None');
  assert.match(exportCookies([{ name: 'a', value: '1', path: '/' }], 'netscape', 'shop.example'), /^shop\.example\t/m);
  assert.equal(C.parseHeaders('Content-Security-Policy: default-src \'self\';\n  script-src \'self\'')['content-security-policy'], "default-src 'self'; script-src 'self'");
  assert.deepEqual({ ...C.parseHeaders('https://a.example/x') }, {});
  assert.ok(!auditHtml('<a href="javascript:void(0);">x</a>', 'https://a/').some((f) => /javascript:/.test(f.title)));
  assert.ok(auditHtml('<input type="hidden" name="__VIEWSTATE" value="dDwtMTA4MDA">', 'https://a/').some((f) => /Hidden field/.test(f.title)));
  assert.ok(auditHtml('<iframe src="https://x.example/p" hidden></iframe>', 'https://a/').some((f) => /Hidden frame/.test(f.title)));
  const s = new C.Store('https://a.example/'); C.analyzeInto(s, 'routes=[{path:"/admin/search"}]', 'https://a.example/a.js');
  ghostRoutes(s, ['#/admin/search']); assert.ok(!s.items.some((f) => f.type === 'ghost-route'));
  assert.ok(matchAdvisories('Angular', '18.2.0').some((a) => a.id === 'CVE-2026-50557'));
  assert.equal(matchAdvisories('Angular', '19.2.22').some((a) => a.id === 'CVE-2026-50557'), false);
  assert.equal(consentCase([{ name: '_ga', value: '1' }, { name: 'CookieConsent', value: '{marketing:false,statistics:true}' }], {}), null);
});
