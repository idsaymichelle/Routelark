import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../src/core.js';
import { complianceRows } from '../src/core/compliance.js';

test('D1: статусы ASVS и WSTG по данным из браузера', () => {
  const s = new C.Store('https://a.example/');
  const st = (rows, id) => rows.find((r) => r.id === id).status;
  let rows = complianceRows(s, { cookies: [] });
  assert.equal(st(rows, '3.4.3'), 'na');
  assert.equal(rows.find((r) => r.id === '3.4.3').reason, 'headers not read');
  s.replaceHeaders({ 'content-security-policy': "script-src 'self' 'unsafe-inline'", 'strict-transport-security': 'max-age=63072000; includeSubDomains', server: 'nginx' }, true);
  s.files.push('https://a.example/app.js');
  C.analyzeInto(s, 'addEventListener("message", e => { run(e.data) })', 'https://a.example/app.js');
  rows = complianceRows(s, { cookies: [{ name: 'sid', value: 'x', secure: false, attrsKnown: true }] });
  assert.equal(st(rows, '3.4.3'), 'fail');
  assert.equal(st(rows, '3.4.1'), 'pass');
  assert.equal(st(rows, '3.3.1'), 'fail');
  assert.equal(st(rows, '3.5.5'), 'fail');
  assert.equal(st(rows, 'INFO-02'), 'fail');
  assert.ok(rows.every((r) => r.status !== 'na' || r.reason));
});
