import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../src/core.js';
import { mapping, ruleOf } from '../src/core/mapping.js';

test('D2: правила и категории OWASP 2025 / CWE', () => {
  const s = new C.Store('https://a.example/');
  C.analyzeInto(s, 'fetch("/api/admin/users"); el.innerHTML = location.hash; k="sk_live_' + 'aB3'.repeat(10) + '"', 'https://a.example/app.js');
  const m = (pred) => mapping(s.items.find(pred));
  assert.deepEqual(m((f) => f.url === '/api/admin/users').top10, ['A01']);
  assert.deepEqual(m((f) => f.type === 'sink').cwe, ['CWE-79']);
  assert.deepEqual(m((f) => f.kind === 'secret').top10, ['A07']);
  assert.equal(ruleOf({ kind: 'config', url: 'CSP allows scripts from any host' }), 'hdr.csp');
  assert.equal(ruleOf({ kind: 'ai', url: 'System prompt in client code (300 characters)' }), 'ai.prompt');
  assert.deepEqual(mapping({ kind: 'ai', url: 'System prompt contains a secret' }).llm, ['LLM07']);
});
