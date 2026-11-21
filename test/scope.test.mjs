import test from 'node:test';
import assert from 'node:assert/strict';
import { siteOf, makeScope, clampSettings } from '../src/core/scope.js';

const PAGE = 'https://app.example.org/';

test('siteOf: регистрируемый домен', () => {
  assert.equal(siteOf('app.example.co.uk'), 'example.co.uk');
  assert.equal(siteOf('a.b.example.com'), 'example.com');
  assert.equal(siteOf('127.0.0.1'), '127.0.0.1');
  assert.equal(siteOf('localhost:8888'), 'localhost');
});

test('scope: поддомены сайта разрешены, чужие хосты нет', () => {
  const sc = makeScope({ pageUrl: PAGE });
  assert.ok(sc.check('https://static.example.org/a.js').ok);
  assert.ok(sc.check('https://example.org/a.js').ok);
  assert.equal(sc.check('https://evil.org/a.js').reason, 'external-host');
  assert.equal(sc.check('https://notexample.org/a.js').reason, 'external-host');
  assert.ok(makeScope({ pageUrl: PAGE, allowHosts: ['cdn.evil.org'] }).check('https://cdn.evil.org/a.js').ok);
});

test('scope: OpenAPI и security.txt разрешены, API нет', () => {
  const sc = makeScope({ pageUrl: PAGE });
  assert.equal(sc.check(PAGE + 'api/x').reason, 'not-js');
  assert.ok(sc.check(PAGE + 'openapi.json').ok);
  assert.ok(sc.check(PAGE + 'docs/swagger.yaml').ok);
  assert.ok(sc.check(PAGE + 'v2/api-docs.json').ok);
  assert.ok(sc.check(PAGE + '.well-known/security.txt', true).ok);
  assert.equal(sc.check(PAGE + '.well-known/security.txt').reason, 'not-js');
});

test('clampSettings: жёсткие пределы', () => {
  const s = clampSettings({ delay: 10, budget: 1e9, depth: 99, allowHosts: 'x' });
  assert.equal(s.delay, 300);
  assert.equal(s.budget, 2000);
  assert.equal(s.depth, 4);
  assert.deepEqual(s.allowHosts, []);
  assert.equal(clampSettings({}).delay, 500);
  assert.equal(clampSettings({}).budget, 400);
});

test('общий хостинг: соседний поддомен не входит в скоуп', () => {
  assert.equal(siteOf('me.vercel.app'), 'me.vercel.app');
  assert.equal(makeScope({ pageUrl: 'https://me.vercel.app/' }).check('https://victim.vercel.app/a.js').reason, 'external-host');
});

test('QA 13/14: запрет по частям пути, общие хостинги, SLD, IDN и лимит скоупа', async () => {
  const { DEFAULT_DENY, siteOf, makeScope } = await import('../src/core/scope.js');
  const { parseProgram } = await import('../src/core/program.js');
  assert.ok(!DEFAULT_DENY.test('/assets/deleteModal.js') && DEFAULT_DENY.test('/account/delete') && DEFAULT_DENY.test('/logout'));
  assert.equal(siteOf('a.blogspot.com'), 'a.blogspot.com');
  assert.equal(siteOf('shop.example.or.jp'), 'example.or.jp');
  assert.equal(makeScope({ pageUrl: 'https://a.myshopify.com/' }).check('https://b.myshopify.com/x.js').ok, false);
  assert.equal(parseProgram('*.bücher.example').rules[0].host, 'xn--bcher-kva.example');
  assert.throws(() => parseProgram(Array.from({ length: 2001 }, (_, i) => 'h' + i + '.example').join('\n')), /2000/);
  assert.equal(parseProgram(JSON.stringify({ data: [{ attributes: { asset_identifier: 'com.app', asset_type: 'GOOGLE_PLAY_APP_ID' } }, { attributes: { asset_identifier: 'a.example', asset_type: 'URL' } }] })).rules.length, 1);
});
