import test from 'node:test';
import assert from 'node:assert/strict';
import { parseTrafficExport } from '../src/core/imports.js';

test('Burp XML', () => {
  const x = '<?xml version="1.0"?><items burpVersion="2024.1"><item><time>t</time><url><![CDATA[https://a.test/api/users?id=1]]></url><method><![CDATA[POST]]></method></item><item><url><![CDATA[https://a.test/x.js]]></url><method>GET</method></item></items>';
  assert.deepEqual(parseTrafficExport(x), { source: 'Burp', requests: [{ url: 'https://a.test/api/users?id=1', method: 'POST' }, { url: 'https://a.test/x.js', method: 'GET' }] });
});

test('ZAP и Caido JSON, HAR, список адресов', () => {
  const zap = JSON.stringify({ messages: [{ requestHeader: 'PUT https://a.test/api/v1/orders HTTP/1.1\r\nHost: a.test' }] });
  assert.deepEqual(parseTrafficExport(zap).requests, [{ url: 'https://a.test/api/v1/orders', method: 'PUT' }]);
  const caido = JSON.stringify([{ host: 'a.test', port: 443, is_tls: true, path: '/rest/basket/1', query: 'x=1', method: 'get' }]);
  assert.deepEqual(parseTrafficExport(caido).requests, [{ url: 'https://a.test/rest/basket/1?x=1', method: 'GET' }]);
  assert.equal(parseTrafficExport(JSON.stringify({ log: { entries: [{ request: { url: 'https://a.test/', method: 'GET' } }] } })).source, 'HAR');
  assert.equal(parseTrafficExport('https://a.test/a\nhttps://a.test/b\n').requests.length, 2);
  assert.equal(parseTrafficExport('var a = 1'), null);
  assert.equal(parseTrafficExport('[{"name":"sid","value":"1"}]'), null);
});

test('проверка: Burp с DTD, ZAP report, порт Caido, список объектов без метода — не трафик', () => {
  const dtd = '<?xml version="1.0"?><!DOCTYPE items [' + '<!ELEMENT item (time, url)>'.repeat(20) + ']><items burpVersion="2024"><item><url><![CDATA[https://a.test/x]]></url><method><![CDATA[GET]]></method></item></items>';
  assert.equal(parseTrafficExport(dtd).requests.length, 1);
  const zap = JSON.stringify({ site: [{ alerts: [{ instances: [{ uri: 'https://a.test/q?x=1', method: 'POST' }] }] }] });
  assert.deepEqual(parseTrafficExport(zap).requests, [{ url: 'https://a.test/q?x=1', method: 'POST' }]);
  assert.equal(parseTrafficExport(JSON.stringify([{ host: 'a.test', port: 8443, is_tls: true, path: '/z', method: 'GET' }])).requests[0].url, 'https://a.test:8443/z');
  assert.equal(parseTrafficExport(JSON.stringify({ data: [{ url: 'https://cdn.test/img.png' }] })), null);
});
