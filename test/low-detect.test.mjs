import test from 'node:test';
import assert from 'node:assert/strict';
import { piiFindings } from '../src/core/pii.js';
import { auditHtml } from '../src/core/html.js';
import { speculationFindings } from '../src/core/browser.js';
import { extraHeaderFindings } from '../src/core/headers2.js';
import { decodeValue } from '../src/core/cookies.js';
import { fileMeta } from '../src/core/meta.js';

const types = (t, s = 'a.js') => piiFindings(t, s).map((f) => f.type);
const bytes = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0) & 255);

test('03-pii F7: hash key needs a left boundary', () => {
  assert.deepEqual(types('{contenthash:"0123456789abcdef0123456789abcdef"}', 'app.js'), []);
  assert.deepEqual(types('var o={bypass:"5f4dcc3b5aa765d61d8327deb882cf99"}'), []);
  assert.deepEqual(types('{password:"5f4dcc3b5aa765d61d8327deb882cf99"}'), ['hash']);
});
test('03-pii F8: camelCase inn is not the INN keyword', () => {
  assert.deepEqual(types('a.innHeight=7707083893;'), []);
  assert.deepEqual(types('inn: 7707083893'), ['inn']);
});
test('03-pii F9: file-like strings are not emails', () => {
  for (const s of ['pkg="cache@tmp.json"', 'x="index@app.component.ts"', 'x="styles@main.scss"']) assert.deepEqual(types(s), []);
  assert.deepEqual(types('x="bob@corp.com"'), ['email']);
});
test('03-pii F10: Diners and Maestro cards', () => {
  assert.deepEqual(types('card: "3056 9309 0259 04"'), ['card']);
  assert.deepEqual(types('card: "6759 6498 2643 8453"'), ['card']);
});
test('08-html F11/F4: comment word boundary, unquoted rel', () => {
  assert.deepEqual(auditHtml('<!-- latest release footer -->', 'https://a.example/'), []);
  assert.equal(auditHtml('<!-- test account -->', 'https://a.example/').length, 1);
  assert.deepEqual(auditHtml('<a href="https://x.example.net" target="_blank" rel=noopener>x</a>', 'https://a.example/'), []);
});
test('08-html F13: big speculationrules block is parsed', () => {
  const j = JSON.stringify({ prerender: [{ urls: ['/logout'], eagerness: 'eager' }], pad: 'x'.repeat(21000) });
  assert.equal(speculationFindings('<script type="speculationrules">' + j + '</script>').length, 1);
});
test('09-headers F9/F10/F13', () => {
  const t = (h) => extraHeaderFindings(h, true, '').map((f) => f.title);
  assert.ok(!t({ 'set-cookie': 'a=1', 'cache-control': 'public, max-age=0' }).includes('Response sets a cookie and looks cacheable'));
  assert.ok(t({ 'set-cookie': 'a=1', 'cache-control': 'public, max-age=60' }).includes('Response sets a cookie and looks cacheable'));
  assert.ok(!t({ 'server-timing': 'cache;dur=5' }).includes('Server-Timing exposes internal metrics'));
  assert.ok(t({ 'server-timing': 'db;dur=5' }).includes('Server-Timing exposes internal metrics'));
  assert.match(extraHeaderFindings({ 'feature-policy': "payment 'self'" }, true, '')[0].why, /Feature-Policy/);
});
test('10-cookies F8: plain word is not base64', () => {
  assert.deepEqual(decodeValue('blueWidget42'), []);
  assert.equal(decodeValue('aGVsbG8gd29ybGQ=')[0].label, 'base64');
});
test('31-tests F5 / 08-html F12: GIF, WebP, PDF meta', () => {
  assert.deepEqual(fileMeta(bytes('GIF89a\x20\x03\x58\x02')).fields, [['Size', '800 × 600']]);
  assert.equal(fileMeta(bytes('RIFF\0\0\0\0WEBPVP8 ')).format, 'WebP');
  assert.deepEqual(fileMeta(bytes('%PDF-1.4 /Author (x)')).fields, [['Author', 'x']]);
  assert.deepEqual(fileMeta(bytes('%PDF-1.4 /Author <FEFF0041006C0069>')).fields, [['Author', 'Ali']]);
});
