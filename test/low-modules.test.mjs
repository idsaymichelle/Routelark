import test from 'node:test'; import assert from 'node:assert/strict';
import { graphqlFromText, graphqlFindings, sdlDraft } from '../src/core/graphql.js';
import { openApiEndpoints } from '../src/core/openapi.js';
import { realtimeFindings } from '../src/core/realtime.js';
import { web3Findings } from '../src/core/web3.js';
import { viteSignature } from '../src/core/frameworks.js';
import { parseWasm, wasmFields } from '../src/core/wasm.js';
import { ghostRoutes } from '../src/core/ghost.js';
import { devbuildText } from '../src/core/devbuild.js';
import { wellKnownFile, mobileHints } from '../src/core/wellknown.js';
import { infraFromText } from '../src/core/infra.js';
import { scanIdentity } from '../src/core/identity.js';
import { badMatch } from '../src/core/supply.js';

test('graphql: операции и фрагменты в середине строки, __typename, sensitive, relay metadata', () => {
  const g = graphqlFromText('const a = "query A { me { id } } query B { x }"; const f = "{ a } fragment UserFields on User { id name }"');
  assert.deepEqual(g.ops.map((o) => o.name), ['A', 'B']);
  assert.equal(g.fragments[0].name, 'UserFields');
  assert.ok(!/__typename/.test(sdlDraft(graphqlFindings('query A { me { __typename id } }'))));
  const risk = (t) => graphqlFindings(t)[0].risk;
  assert.equal(risk('mutation updateBanner($id: ID!) { x }'), 1);
  assert.equal(risk('mutation SetBankAccount { x }'), 1);
  assert.equal(risk('mutation { deleteUser(id: 1) { id } }'), 2);
  assert.equal(graphqlFromText('x = {params:{id:"abc12345",metadata:{},name:"PostQuery",operationKind:"query",text:null}}').persisted[0].id, 'abc12345');
});

test('openapi: $ref параметров и path item, servers с переменной', () => {
  const r = openApiEndpoints(JSON.stringify({ openapi: '3.0.0', components: { parameters: { x: { name: 'x', in: 'path' } }, pathItems: { z: { get: {} } } }, paths: { '/a/{x}': { get: { parameters: [{ $ref: '#/components/parameters/x' }, { name: 'y' }] } }, '/z': { $ref: '#/components/pathItems/z' } } }));
  assert.deepEqual(r.find((e) => e.path === '/a/{x}').params, ['x', 'y']);
  assert.ok(r.some((e) => e.path === '/z'));
  const s = openApiEndpoints(JSON.stringify({ openapi: '3.0.0', servers: [{ url: '{scheme}://api.example.com/v4', variables: { scheme: { default: 'https' } } }], paths: { '/a': { get: {} } } }));
  assert.equal(s[0].path, '/v4/a');
});

test('realtime: path не литерал не заменяется на /socket.io/', () => {
  const hit = (t) => realtimeFindings(t).filter((x) => x.t === 'hit').map((x) => x.raw);
  assert.deepEqual(hit('io("https://rt.a.example", {path: base + "socket.io"})'), ['https://rt.a.example']);
  assert.deepEqual(hit('io("https://rt.a.example", {path: "/ws/"})'), ['https://rt.a.example/ws/']);
  assert.deepEqual(hit('new WebSocket("wss://rt.example.org/socket", ["graphql-ws"])'), ['wss://rt.example.org/socket']);
});

test('web3: SDK без версии и @latest; точная версия молчит; константы библиотеки не находка', () => {
  const t = (u) => web3Findings('<script src="' + u + '">', 'a.html').map((x) => x.title);
  assert.equal(t('https://unpkg.com/@rainbow-me/rainbowkit@latest/dist/index.js').length, 1);
  assert.equal(t('https://cdn.jsdelivr.net/npm/@walletconnect/ethereum-provider').length, 1);
  assert.equal(t('https://unpkg.com/@rainbow-me/rainbowkit@2.1.4/dist/index.js').length, 0);
  assert.equal(web3Findings('a = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e; ethers; chainId: 3', 'c.js').length, 0);
});

test('frameworks: Vite с нестандартной папкой ассетов', () => {
  assert.ok(viteSignature('<script type="module" src="/static/index-DOw1gmz1.js"></script>'));
  assert.ok(!viteSignature('<script src="/static/index-DOw1gmz1.js"></script>'));
});

test('wasm: Component Model, неизвестный kind, env не toolchain, пути отдельно', () => {
  assert.equal(parseWasm(new Uint8Array([0, 0x61, 0x73, 0x6d, 0x0d, 0, 1, 0])).error, 'component');
  const hdr = [0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
  const bad = parseWasm(new Uint8Array([...hdr, 2, 6, 1, 1, 0x6d, 1, 0x66, 9]));
  assert.equal(bad.truncated, true); assert.equal(bad.imports.length, 0);
  const env = parseWasm(new Uint8Array([...hdr, 2, 7, 1, 1, 0x65, 1, 0x66, 0, 0]));
  assert.equal(env.imports[0].module, 'e'); // собственный модуль
  assert.ok(!wasmFields({ imports: [{ module: 'env', name: 'f' }], exports: [], producers: {}, customs: [], funcNames: [], urls: [] }).some((x) => x[0] === 'Toolchain hint'));
  const data = [...'/usr/lib/x https://a.example/b'].map((c) => c.charCodeAt(0));
  const w = parseWasm(new Uint8Array([...hdr, 11, data.length, ...data]));
  assert.deepEqual(w.paths, ['/usr/lib/x']); assert.deepEqual(w.urls, ['https://a.example/b']);
});

test('ghost: корень и динамические сегменты Next', () => {
  const run = (route, anchor) => { const items = [{ kind: 'code', type: 'route', url: 'Hidden client route: ' + route, sources: [{}], snippet: '' }], added = []; ghostRoutes({ pageUrl: 'https://s.example/', items, addCode: (x) => added.push(x) }, [anchor]); return added.length; };
  assert.equal(run('/', '/'), 0);
  assert.equal(run('/users/[id]', '/users/42'), 0);
  assert.equal(run('/docs/[...slug]', '/docs/a/b'), 0);
  assert.equal(run('/users/[id]', '/other'), 1);
});

test('devbuild: Sentry DSN и домен Firebase Auth публичны, API key нет', () => {
  const r = (k) => devbuildText('{"' + k + '":"v"}', 'a.js').length;
  assert.equal(r('VITE_SENTRY_DSN'), 0);
  assert.equal(r('REACT_APP_FIREBASE_AUTH_DOMAIN'), 0);
  assert.equal(r('NEXT_PUBLIC_API_KEY'), 1);
});

test('wellknown: issuer с путём, null, security.txt, assetlinks, схемы web3', () => {
  const kc = JSON.stringify({ issuer: 'https://kc.acme-shop.io/realms/shop', authorization_endpoint: 'https://kc.acme-shop.io/a', code_challenge_methods_supported: ['S256'] });
  assert.ok(!wellKnownFile(kc, 'https://kc.acme-shop.io/realms/shop/.well-known/openid-configuration', 'x').simple.some((s) => /issuer does not match/.test(s.title)));
  assert.equal(wellKnownFile('null', 'https://s.acme-shop.io/.well-known/apple-app-site-association', 's.acme-shop.io').miss, true);
  const sec = (t) => wellKnownFile(t, 'https://s.acme-shop.io/.well-known/security.txt', 's.acme-shop.io').simple.map((s) => s.title);
  assert.ok(sec('Contact: mailto:a@b.c\nExpires: Sun, 14 Nov 2020 17:23:37 GMT').some((t) => /expired/.test(t)));
  assert.ok(sec('Expires: Sun, 14 Nov 2099 17:23:37 GMT').some((t) => /no Contact/.test(t)));
  assert.deepEqual(sec('Contact: mailto:a@b.c\nExpires: Sun, 14 Nov 2099 17:23:37 GMT'), []);
  const al = wellKnownFile(JSON.stringify([{ target: { package_name: 'com.acme.shop' } }]), 'https://s.acme-shop.io/.well-known/assetlinks.json', 's.acme-shop.io');
  assert.equal(al.simple[0].title, 'Android app: com.acme.shop');
  assert.equal(mobileHints('a = "ipfs://" + x; b = "myapp://open"').map((x) => x.title).join(), 'App deep-link scheme: myapp://');
});

test('infra: целые метки, полный хост, расширения кода', () => {
  const h = (t) => infraFromText(t, 'acme.io').map((x) => x.title);
  assert.deepEqual(h('x = "api.dev.example.com"'), ['Test-environment host: api.dev.example.com']);
  assert.deepEqual(h('staging.example.com dev-2.acme.io'), ['Test-environment host: staging.example.com', 'Test-environment host: dev-2.acme.io']);
  for (const s of ['internalPendingTask.hasPendingTasksObservable.pipe', 'developer.mozilla.org', 'stage.controller.ts', 'testnets.opensea.io', 'testnet.polygonscan.com']) assert.deepEqual(h(s), [], s);
});

test('identity: placeholder по значению, redirect_uri в query, look-alike localhost', () => {
  const t = (s) => scanIdentity(s).map((x) => x.title + '|' + x.risk);
  assert.deepEqual(t('firebase; projectId: "examplecorp-prod"'), ['Firebase config: examplecorp-prod|0']);
  assert.deepEqual(t('firebase; projectId: "your-project-id"'), []);
  assert.ok(t('auth0; go("https://x.auth0.com/authorize?redirect_uri=https%3A%2F%2Fshop.acme-shop.io%2Fcb")').includes('Redirect URI: https://shop.acme-shop.io/cb|1'));
  const ru = (u) => t('auth0; redirect_uri: "' + u + '"')[0];
  assert.equal(ru('http://localhost.acme-shop.io/cb'), 'Redirect URI: http://localhost.acme-shop.io/cb|2');
  assert.equal(ru('http://127.0.0.1.acme-shop.io/cb'), 'Redirect URI: http://127.0.0.1.acme-shop.io/cb|2');
  assert.equal(ru('http://localhost:3000/cb'), 'Redirect URI: http://localhost:3000/cb|1');
});

test('supply: id OSV в сообщении', () => {
  assert.ok(badMatch('keyv', '6.0.0').why[0].startsWith('MAL-2026-11524'));
});
