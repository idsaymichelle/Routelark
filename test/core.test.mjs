// node --test test/
import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../src/core.js';
import { codeFindings } from '../src/core/code.js';

const PAGE = 'https://app.example.org/';
const scan = (text, src = PAGE + 'app.js') => { const s = new C.Store(PAGE); C.analyzeInto(s, text, src); return s; };
const routes = (s) => s.items.filter((f) => f.kind !== 'tech').map((f) => f.method + ' ' + f.url).sort();

test('метод «?» сливается с известным методом, дублей нет', () => {
  const s = scan('fetch("/api/v1/users/"+id,{method:"DELETE"}); var u="/api/v1/users/{id}"; axios.post("/api/v2/orders"); var p="/api/v2/orders";');
  assert.deepEqual(routes(s), ['DELETE /api/v1/users/{id}', 'POST /api/v2/orders']);
});

test('`${API_URL}/orders` превращается в один путь /orders', () => {
  const s = scan('fetch(`${API_URL}/orders?page=1`)');
  assert.deepEqual(routes(s), ['GET /orders?page=']);
});

test('/v1/ не помечается как старая версия, /legacy/ помечается', () => {
  const s = scan('fetch("/api/v1/me"); fetch("/api/legacy/me")');
  const v1 = s.items.find((f) => f.url === '/api/v1/me'), old = s.items.find((f) => f.url === '/api/legacy/me');
  assert.equal(v1.why.length, 0);
  assert.match(old.why.join(), /Old or test/);
});

test('секрет со словом latest не пропускается фильтром заглушек, а test пропускается', () => {
  const s = scan('var apiKey="latest9Xk2LmQ8vR4tZ7wP3nB"; var apiToken="test";');
  assert.equal(s.items.filter((f) => f.kind === 'secret').length, 1);
});

test('Underscore не становится Lodash', () => {
  assert.deepEqual(C.techFromRuntime({ _: { VERSION: '1.13.6' } }), [{ name: 'Underscore', version: '1.13.6' }]);
  assert.deepEqual(C.techFromRuntime({ _: { VERSION: '4.17.21', runInContext() {} } }), [{ name: 'Lodash', version: '4.17.21' }]);
});

test('jquery.min.js и bootstrap.min.css не дают версию «.»', () => {
  const t = C.techFromText('load("jquery.min.js"); link("bootstrap.min.css")');
  assert.deepEqual(t, []);
  assert.deepEqual(C.techFromText('/*! jQuery v3.4.1 | (c) */'), [{ name: 'jQuery', version: '3.4.1' }]);
});

test('EOL ставится только при известной версии', () => {
  assert.equal(C.eolNote('Vue', null), null);
  assert.equal(C.eolNote('Vue', '3.4.0'), null);
  assert.match(C.eolNote('Vue', '2.7.16'), /Vue 2/);
  const s = new C.Store(PAGE);
  assert.equal(s.addTech({ name: 'React', version: null }, 'x').risk, 0);
});

test('секрет из source map находится и маскируется в сниппете', () => {
  const map = JSON.stringify({ version: 3, sources: ['webpack:///src/a.js', 'webpack:///node_modules/@acme/ui/i.js'], sourcesContent: ['const k="AKIAABCDEFGHIJKLMNOP"; fetch("/api/x")', 'x'] });
  const s = new C.Store(PAGE);
  C.analyzeInto(s, map, PAGE + 'app.js.map');
  const sec = s.items.find((f) => f.kind === 'secret');
  assert.equal(sec.raw, 'AKIAABCDEFGHIJKLMNOP');
  assert.ok(!sec.snippet.includes(sec.raw));
  assert.ok(s.deps.get('@acme/ui').scoped);
  assert.ok(s.items.some((f) => f.url === '/api/x'));
});

test('scope: адреса API, внешние хосты и deny-path не запрашиваются', () => {
  const sc = C.makeScope({ pageUrl: PAGE, self: PAGE + 'routelark.js' });
  assert.equal(sc.check(PAGE + 'api/v1/users/5').reason, 'not-js');
  assert.equal(sc.check('https://cdn.other.com/a.js').reason, 'external-host');
  assert.equal(sc.check(PAGE + 'logout.js').reason, 'deny-path');
  assert.equal(sc.check(PAGE + 'routelark.js').reason, 'self');
  assert.ok(sc.check(PAGE + 'app.js').ok);
  assert.equal(C.makeScope({ pageUrl: PAGE, fetchExternal: true, denyHosts: ['*.other.com'] }).check('https://cdn.other.com/a.js').reason, 'deny-host');
});

test('blockedReason: 403 на .map и слово captcha в JS не считаются WAF', () => {
  assert.equal(C.blockedReason({ status: 403, headers: { 'content-type': 'application/xml' }, text: '<Error><Code>AccessDenied</Code></Error>' }), null);
  assert.equal(C.blockedReason({ status: 200, headers: { 'content-type': 'application/javascript' }, text: 'grecaptcha challenge-platform' }), null);
  assert.ok(C.blockedReason({ status: 403, headers: { 'cf-mitigated': 'challenge' }, text: '' }));
  assert.ok(C.blockedReason({ status: 429, headers: {}, text: '' }));
});

test('crawl: ходит только по JS, останавливает хост после 429', async () => {
  const files = {
    [PAGE + 'app.js']: 'import("./b.js"); import("./c.js"); fetch("/api/users"); //# sourceMappingURL=app.js.map',
    [PAGE + 'app.js.map']: JSON.stringify({ sources: ['a.js'], sourcesContent: ['fetch("/api/from-map")'] }),
    [PAGE + 'b.js']: 'x', [PAGE + 'c.js']: 'y'
  };
  const asked = [];
  const fetchText = async (url) => {
    asked.push(url);
    if (url.endsWith('c.js')) return { ok: false, status: 429, headers: {}, text: '' };
    return files[url] != null ? { ok: true, status: 200, headers: {}, text: files[url] } : { ok: false, status: 404, headers: {}, text: '' };
  };
  const s = new C.Store(PAGE);
  await C.crawl({ store: s, scope: C.makeScope({ pageUrl: PAGE }), seeds: [{ url: PAGE + 'app.js' }], fetchText, conc: 1 });
  assert.ok(asked.every((u) => /\.(?:js|map)$/.test(u)), asked.join());
  assert.ok(!asked.some((u) => u.includes('/api/')));
  assert.equal(s.blocked.length, 1);
  assert.ok(!asked.includes(PAGE + 'app.js.map'), 'после 429 хост больше не запрашивается');
});

test('заголовки: нет CSP и HSTS, Server раскрыт', () => {
  const titles = C.headerFindings({ server: 'nginx/1.18' }, true).map((x) => x.title).join('|');
  assert.match(titles, /Content-Security-Policy/);
  assert.match(titles, /Strict-Transport-Security/);
  assert.match(titles, /server: nginx/);
});

test('JWT: alg=none и отсутствие exp видны', () => {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const info = C.jwtInfo(b({ alg: 'none' }) + '.' + b({ sub: '1', role: 'admin' }) + '.');
  assert.equal(info.risk, 3);
  assert.match(info.why.join(), /no exp/);
  assert.match(info.why.join(), /roles in token: role/);
});

test('правила риска работают и при query в пути', () => {
  const s = scan('fetch("/api/admin?page=1"); fetch("/api/users/"+id+"?expand=1")');
  assert.match(s.items.find((f) => f.path === '/api/admin').why.join(), /Admin/);
  assert.match(s.items.find((f) => f.path === '/api/users/{id}').why.join(), /BOLA/);
});

test('варианты с query сливаются, у GET и POST разные id', () => {
  const s = scan('axios.post("/api/z?x=1"); var b="/api/z"; fetch("/api/w",{method:"POST"}); fetch("/api/w")');
  assert.deepEqual(routes(s), ['GET /api/w', 'POST /api/w', 'POST /api/z?x=']);
  const w = s.items.filter((f) => f.path === '/api/w');
  assert.notEqual(w[0].id, w[1].id);
});

test('из robots и sitemap не качаются произвольные адреса, а sitemap.xml качается', () => {
  const sc = C.makeScope({ pageUrl: PAGE });
  assert.equal(sc.check(PAGE + 'api/v1/export?format=xml', true).reason, 'not-js');
  assert.equal(sc.check(PAGE + 'api/manifest', true).reason, 'not-js');
  assert.ok(sc.check(PAGE + 'sitemap-1.xml', true).ok);
  assert.equal(sc.check(PAGE + 'log%6Fut.js').reason, 'deny-path');
});

test('кривой манифест или map не роняет скан, map больше 8 МБ разбирается', async () => {
  const big = JSON.stringify({ sources: [null, 'a.js'], sourcesContent: [null, 'fetch("/api/early")' + ' '.repeat(8.1e6)] });
  const files = { [PAGE + 'manifest.json']: '{"name":"x","shortcuts":[null]}', [PAGE + 'big.js.map']: big, [PAGE + 'ok.js']: 'fetch("/api/after")' };
  const s = new C.Store(PAGE);
  await C.crawl({ store: s, scope: C.makeScope({ pageUrl: PAGE }), seeds: Object.keys(files).map((url) => ({ url })), fetchText: async (u) => ({ ok: true, status: 200, headers: {}, text: files[u] }), conc: 1 });
  assert.ok(s.items.some((f) => f.url === '/api/early'));
  assert.ok(s.items.some((f) => f.url === '/api/after'));
  assert.equal(s.errors.length, 1);
});

test('секрет в адресе не попадает в эндпоинты открытым', () => {
  const tok = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab';
  const s = scan('fetch("/api/v1/hook/' + tok + '")');
  const l = s.list();
  assert.ok(!C.toCSV(l, {}).includes(tok));
  assert.ok(C.toCSV(l, { reveal: true }).includes(tok));
  assert.ok(s.items.some((f) => f.url === '/api/v1/hook/{secret}'));
});

test('все экспорты работают на непустом и пустом наборе', () => {
  for (const s of [scan('fetch("/api/a?url=x"); var k="AKIAABCDEFGHIJKLMNOP"; var b="x.s3.amazonaws.com";'), new C.Store(PAGE)]) {
    const l = s.list(), o = { target: PAGE };
    assert.ok(C.toMarkdown(s, o).startsWith('# Routelark'));
    JSON.parse(C.toJSON(l, o));
    assert.ok(C.toCSV(l, o).startsWith('priority'));
    C.toURLs(l); C.toPaths(l);
  }
  const s = scan('fetch("https://api.example.org/v2/users/"+id)');
  assert.equal(C.toURLs(s.list()), '');
  assert.equal(C.toPaths(s.list()), '/v2/users/FUZZ');
});

test('Supabase: service_role критичен, новые токены находятся', () => {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const info = C.jwtInfo(b({ alg: 'HS256' }) + '.' + b({ iss: 'supabase', role: 'service_role', exp: 4102444800 }) + '.sig');
  assert.equal(info.risk, 4);
  const s = scan('var a="npm_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"; var b="shpat_' + '0123456789abcdef0123456789abcdef";');
  assert.deepEqual(s.items.filter((f) => f.kind === 'secret').map((f) => f.url).sort(), ['Shopify access token', 'npm token']);
});
test('заголовки: слабая CSP, короткий HSTS, Referrer-Policy', () => {
  const titles = C.headerFindings({ 'content-security-policy': "default-src 'self'; script-src https: 'self'", 'strict-transport-security': 'max-age=3600', 'referrer-policy': 'unsafe-url', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY' }, true).map((x) => x.title).join('|');
  assert.match(titles, /scripts from any host/);
  assert.match(titles, /base-uri/);
  assert.match(titles, /under 6 months/);
  assert.match(titles, /Referrer-Policy/);
  assert.doesNotMatch(titles, /nosniff|object-src/);
});
test('карта кода из заголовка SourceMap', async () => {
  const asked = [];
  const fetchText = async (url) => { asked.push(url); return url.endsWith('a.js') ? { ok: true, status: 200, headers: { sourcemap: '/maps/a.js.map' }, text: 'x' } : { ok: true, status: 200, headers: {}, text: JSON.stringify({ sources: ['s.js'], sourcesContent: ['fetch("/api/hidden")'] }) }; };
  const s = new C.Store(PAGE);
  await C.crawl({ store: s, scope: C.makeScope({ pageUrl: PAGE }), seeds: [{ url: PAGE + 'a.js' }], fetchText, conc: 1 });
  assert.ok(asked.includes(PAGE + 'maps/a.js.map'));
  assert.ok(s.items.some((f) => f.url === '/api/hidden'));
});

test('Next.js: страницы из __NEXT_DATA__ и манифеста, манифест ставится в очередь', () => {
  const s = new C.Store(PAGE), queued = [];
  C.analyzeInto(s, '<script id="__NEXT_DATA__" type="application/json">{"page":"/orders/[id]","buildId":"abc12345"}</script><script src="/_next/static/chunks/main.js"></script>', PAGE, { enqueue: (u) => queued.push(u), depth: 0 });
  assert.ok(s.items.some((f) => f.path === '/orders/{id}'));
  assert.ok(queued.includes(PAGE + '_next/static/abc12345/_buildManifest.js'));
  C.analyzeInto(s, 'self.__BUILD_MANIFEST={"/admin/reports":["static/chunks/a.js"],"/_app":["x.js"],"/blog/[slug]":["b.js"]}', PAGE + '_next/static/abc12345/_buildManifest.js');
  assert.ok(s.items.some((f) => f.path === '/admin/reports'));
  assert.ok(s.items.some((f) => f.path === '/blog/{slug}'));
});
test('GraphQL: имена операций, мутация выше запроса', () => {
  const s = scan('const Q = `query GetUser($id: ID!) { user(id: $id) { name } }`; const M = "mutation DeleteUser($id: ID!) { deleteUser(id: $id) }"; function query(a) {}');
  const g = s.items.filter((f) => f.kind === 'graphql').map((f) => f.url + ':' + f.risk).sort();
  assert.deepEqual(g, ['mutation DeleteUser:2', 'query GetUser:0']);
});

test('длинные строки не подвешивают анализ (ограниченные шаблоны облаков и email)', () => {
  const t0 = Date.now();
  scan('var x="' + 'a-'.repeat(60000) + '"; var y="' + 'a.'.repeat(60000) + '";');
  assert.ok(Date.now() - t0 < 3000, 'анализ занял ' + (Date.now() - t0) + ' мс');
});
test('GraphQL: обычный код «query builder(x)» не считается операцией; истёкший service_role не критичен', () => {
  const s = scan('var a = "x\\nquery builder(x)"; var q = "query GetUser { me { id } }";');
  assert.deepEqual(s.items.filter((f) => f.kind === 'graphql').map((f) => f.url), ['query GetUser']);
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  assert.equal(C.jwtInfo(b({ alg: 'HS256' }) + '.' + b({ role: 'service_role', exp: 1 }) + '.s').risk, 1);
});
test('CSP: unsafe-inline только в style-src не даёт находку про скрипты', () => {
  const titles = C.headerFindings({ 'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'self'", 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY' }, false).map((x) => x.title);
  assert.deepEqual(titles.filter((x) => /CSP|script/i.test(x)), []);
});

test('один секрет не показывается дважды (точное правило и общий поиск)', () => {
  const s = scan('const aws = { accessKeyId: "AKIAQ7XJ4M2PL5KD3WTB" };');
  assert.equal(s.items.filter((f) => f.kind === 'secret').length, 1);
});

test('новые секреты: OpenAI, GitLab, Telegram, Discord, Mailchimp, Authorization в коде', () => {
  const tg = '1234567890:AA' + 'b'.repeat(33), oa = 'sk-proj-' + 'A'.repeat(24) + 'T3BlbkFJ' + 'B'.repeat(24);
  const text = [oa, 'glpat-Ab3dE5gH7jK9mN2pQ4rS', tg, 'https://discord.com/api/webhooks/123456789012345678/' + 'z'.repeat(68), 'abcdef0123456789abcdef0123456789-us12', 'h = "Bearer eyabcdefghijklmnopqrstuvwxyz0123"'].map((s) => 'var a = "' + s.replace(/"/g, "'") + '";').join('\n');
  const types = C.scanSecrets(text, 'x.js').map((s) => s.type);
  for (const id of ['openai', 'gitlab', 'telegram', 'discord-hook', 'mailchimp', 'auth-header']) assert.ok(types.includes(id), id + ' in ' + types);
});

test('parseHeaders: строки из DevTools и Burp, статус и мусор пропускаются, повторы склеиваются', () => {
  const h = C.parseHeaders('HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: a=1\nSet-Cookie: b=2\nVary: Origin\nvary: Accept\n\nnot a header\nhttps://x.test/');
  assert.deepEqual({ ...h }, { 'content-type': 'text/html', 'set-cookie': 'a=1\nb=2', vary: 'Origin, Accept' });
  assert.ok(C.headerFindings(h, true).some((f) => /Content-Security-Policy/.test(f.title)));
});

test('id находки не зависит от порядка файлов', () => {
  const run = (order) => { const s = new C.Store('https://a.test/'); order.forEach((m) => s.addHit({ raw: '/api/v1/orders', method: m, file: 'x', line: 1, col: 1, via: m === '?' ? 'string' : 'call' })); return Object.fromEntries(s.items.map((f) => [f.method, f.id])); };
  assert.deepEqual(run(['GET', 'POST']), run(['POST', 'GET']));
  assert.deepEqual(run(['?', 'POST']), run(['POST', '?']));
});

test('replaceHeaders: вставка дважды оставляет один набор находок по заголовкам', () => {
  const s = new C.Store('https://a.test/');
  s.addHit({ raw: '/api/x', file: 'f', line: 1, col: 1, via: 'call' });
  s.replaceHeaders({ server: 'nginx/1.2' }, true, '(pasted headers)');
  const n = s.items.filter((f) => f.kind === 'config').length;
  assert.ok(n > 1);
  s.replaceHeaders({ server: 'nginx/1.2' }, true, '(pasted headers)');
  assert.equal(s.items.filter((f) => f.kind === 'config').length, n);
  s.replaceHeaders({ 'content-security-policy': "default-src 'self'; object-src 'none'; base-uri 'none'", 'strict-transport-security': 'max-age=63072000' }, true);
  assert.ok(!s.items.some((f) => f.kind === 'config' && /No Content-Security-Policy/.test(f.url)));
  assert.ok(s.items.some((f) => f.url === '/api/x'));
});

test('находка кода в нескольких файлах — одна запись, риск наибольший', () => {
  const s = new C.Store('https://a.example/');
  s.addCode({ type: 'sink', title: 'X', risk: 1, file: 'https://a.example/a.1234abcd.js', line: 1, col: 1, snippet: '' });
  s.addCode({ type: 'sink', title: 'X', risk: 2, file: 'https://a.example/b.js', line: 5, col: 1, snippet: '' });
  const list = s.items.filter((f) => f.kind === 'code');
  assert.equal(list.length, 1);
  assert.equal(list[0].risk, 2);
  assert.equal(list[0].sources.length, 2);
});

test('A1/A2/H2/H3: новые форматы ключей и публичные ключи', () => {
  const ty = (t) => C.scanSecrets(t, 'a.js').map((s) => s.type + (s.publicKey ? '+pub' : '') + ':' + s.risk);
  const r = 'aB3'.repeat(14);
  assert.deepEqual(ty('k="pk_live_' + r + '"'), ['stripe-pub+pub:1']);
  assert.deepEqual(ty('k="sb_secret_AbCdEfGhIjKlMnOpQrSt_12345678"'), ['supabase-secret:4']);
  assert.deepEqual(ty('https://ab12ab12ab12ab12ab12ab12ab12ab12@o123.ingest.sentry.io/4500'), ['sentry-dsn+pub:0']);
  assert.deepEqual(ty('t="hf_' + 'abcdefghijklmnopqrstuvwxyzABCDEFGH' + '"'), ['huggingface:4']);
  assert.deepEqual(ty('t="pcsk_k9x2m_' + r + '"'), ['pinecone:4']);
  assert.deepEqual(ty('t="glcbt-Ab3Cd5Ef7Gh9Jk2Lm4Np6"'), ['gitlab-new:3']);
  assert.deepEqual(ty('t="cfut_' + 'a1B2'.repeat(12) + '"'), ['cloudflare-token:4']);
  assert.deepEqual(ty('adminApiKey: "ab12cd34ef56ab78cd90ef12ab34cd56"'), ['algolia-admin:4']);
  assert.deepEqual(ty('searchApiKey: "ab12cd34ef56ab78cd90ef12ab34cd56"'), ['algolia-search+pub:1']);
  assert.deepEqual(ty('t="hf_short"'), []);
  const aiza = 'AIza' + 'Sy0123456789abcdefghijABCDEFGHIJ_-x';
  assert.deepEqual(ty('firebase.initializeApp({apiKey:"' + aiza + '",authDomain:"a"})'), ['google-api+pub:1']);
  assert.deepEqual(ty('fetch("https://generativelanguage.googleapis.com/v1?key=' + aiza + '")'), ['google-api:3']);
  assert.deepEqual(ty('k="' + aiza + '"'), ['google-api:2']);
});

test('A3/A4: облачные конфиги и ИИ в коде', () => {
  const s = new C.Store('https://a.example/');
  C.analyzeInto(s, 'firebase.initializeApp({projectId:"shop-prod-1",databaseURL:"https://shop-prod-1-default-rtdb.europe-west1.firebasedatabase.app"}); var p="us-east-1:12345678-1234-1234-1234-123456789abc";', 'https://a.example/app.js');
  const titles = s.items.filter((f) => f.kind === 'identity').map((f) => f.url + ':' + f.risk);
  assert.ok(titles.includes('Firebase config: shop-prod-1:1'), titles.join());
  assert.ok(titles.some((t) => t.startsWith('Cognito identity pool us-east-1:12345678')));
  assert.ok(s.items.some((f) => f.kind === 'cloud' && /firebasedatabase\.app/.test(f.url)));
  const a = new C.Store('https://a.example/');
  C.analyzeInto(a, 'new OpenAI({dangerouslyAllowBrowser:true}); fetch("https://api.openai.com/v1/chat/completions"); const m=[{role:"system",content:"' + 'You are a helpful support bot. '.repeat(10) + '"}]; fetch("https://litellm.corp.example/v1/chat/completions")', 'https://a.example/app.js');
  const ai = a.items.filter((f) => f.kind === 'ai').map((f) => f.url + ':' + f.risk);
  assert.ok(ai.includes('Provider SDK allows browser use (OpenAI):3'), ai.join());
  assert.ok(ai.includes('Direct call to api.openai.com:1'));
  assert.ok(ai.some((t) => /^System prompt in client code/.test(t)));
  const gw = a.items.find((f) => f.url === 'LLM gateway: litellm.corp.example');
  assert.ok(gw && gw.why.some((w) => w.includes('CVE-2026-59822')));
});

test('H6/A7/F6: вредоносные версии, захваченные CDN, похожие домены, pnpm-пути', async () => {
  const { badMatch, pnpmPackage, hostFindings } = await import('../src/core/supply.js');
  assert.equal(badMatch('axios', '1.14.1').risk, 3);
  assert.equal(badMatch('axios', '1.14.0'), null);
  assert.equal(badMatch('plain-crypto-js', null).risk, 2);
  assert.deepEqual(pnpmPackage('webpack:///node_modules/.pnpm/@tanstack+react-router@1.169.5_react@18.3.1/node_modules/@tanstack/react-router/dist/x.js'), { name: '@tanstack/react-router', version: '1.169.5' });
  const f = hostFindings([{ url: 'https://cdn.polyfill.io/v3/polyfill.min.js', script: true }, { url: 'https://cdn.jsdelivr.net/npm/a.js', script: true }, { url: 'https://cdn.jsdeliver.net/npm/a.js', script: true }, { url: 'https://a.omappapi.com/app/js/api.min.js', script: true }], 'shop.example');
  assert.deepEqual(f.map((x) => x.risk), [4, 2, 2]);
  assert.ok(f[1].title.includes('close to jsdelivr.net'));
  const s = new C.Store('https://a.example/');
  s.addDep('@tanstack/react-router', '1.169.5', 'm.map');
  s.addTech({ name: 'Axios', version: '1.14.1' }, 'a.js');
  assert.deepEqual(s.items.filter((x) => x.kind === 'custom').map((x) => x.risk), [3, 3]);
  assert.deepEqual(C.techFromText('/*! Axios v1.14.1 Copyright (c) 2026 */').find((t) => t.name === 'Axios').version, '1.14.1');
});

test('F6: соседний LICENSE.txt и баннеры с версиями', () => {
  const a = C.analyze('/*! For license information please see main.3f2a.js.LICENSE.txt */ x()', 'https://a.example/static/js/main.3f2a.js');
  assert.ok(a.refs.some((r) => r.abs === 'https://a.example/static/js/main.3f2a.js.LICENSE.txt'));
  const s = new C.Store('https://a.example/');
  C.analyzeInto(s, '/*! axios v1.14.1 | (c) 2026 */\n/** @license React 18.3.1 */', 'https://a.example/static/js/main.js.LICENSE.txt');
  assert.equal(s.deps.get('axios').version, '1.14.1');
  assert.ok(s.items.some((f) => f.url === 'Known-bad release: axios@1.14.1'));
});

test('B1: метод из места вызова', () => {
  const hs = (t) => C.analyze(t, 'https://a.example/a.js').hits.filter((h) => h.via === 'call').map((h) => h.method + ' ' + h.raw + (h.params.length ? ' ' + h.params.join(',') : ''));
  assert.deepEqual(hs('fetch("/api/x", {method:"DELETE"})'), ['DELETE /api/x']);
  assert.deepEqual(hs('fetch("/api/x", {method:m})'), ['? /api/x']);
  assert.deepEqual(hs('fetch("/api/x", {...opts})'), ['? /api/x']);
  assert.deepEqual(hs('fetch("/api/x")'), ['GET /api/x']);
  assert.deepEqual(hs('axios({url:"/api/o", method:"put"})'), ['PUT /api/o']);
  assert.deepEqual(hs('axios({url:"/api/o"})'), ['GET /api/o']);
  assert.deepEqual(hs('this.http.get<User[]>("/api/users")'), ['GET /api/users']);
  assert.deepEqual(hs('httpClient.post("/api/p", {a:1})'), ['POST /api/p a']);
  assert.deepEqual(hs('http.request("PATCH", "/api/r")'), ['PATCH /api/r']);
  assert.deepEqual(hs('const backend = axios.create({}); backend.delete("/api/d")'), ['DELETE /api/d']);
});

test('B3: маршрут в коде без ссылки на странице', async () => {
  const { ghostRoutes } = await import('../src/core/ghost.js');
  const s = new C.Store('https://a.example/');
  C.analyzeInto(s, 'routes=[{path:"/admin/users/:id"},{path:"/admin/logs"}]', 'https://a.example/app.js');
  ghostRoutes(s, ['/admin/users/7', '#top']);
  assert.deepEqual(s.items.filter((f) => f.type === 'ghost-route').map((f) => f.url), ['Route in code, not linked on the page: /admin/logs']);
});

test('D5/B8: токены в хранилище, JWT, OAuth в литералах', async () => {
  const { storageFindings, oauthLiteral } = await import('../src/core/tokens.js');
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig';
  assert.deepEqual(storageFindings([['refresh_token', 'abc'], ['access_token', jwt], ['csrf_token', 'x'.repeat(30)], ['theme', 'dark']], [['sid', 'a'.repeat(20)]], [{ name: 'auth-store' }]).map((f) => f.risk), [3, 2, 1, 0]);
  const o = (u) => oauthLiteral('x="' + u + '"', 'app.example').map((f) => f.title + ':' + f.risk);
  assert.deepEqual(o('https://id.example/authorize?response_type=token&client_id=a&state=s'), ['OAuth implicit flow (response_type=token):3']);
  assert.deepEqual(o('/authorize?response_type=code&client_id=a'), ['OAuth code flow without PKCE in the URL:2', 'OAuth request without state:1']);
  assert.deepEqual(o('/cb?access_token=abc'), ['Token in URL query:3']);
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const tok = b64({ alg: 'RS256', jku: 'https://x/keys', kid: 'k1' }) + '.' + b64({ iat: 1e9, exp: 4e9 }) + '.s';
  const info = C.jwtInfo(tok);
  assert.ok(info.why.some((w) => w.startsWith('lifetime')) && info.why.includes('remote key URL in header: https://x/keys') && info.why.includes('kid: k1'));
  const cf = codeFindings('localStorage.setItem("access_token", t); const logout = () => { location.href = "/" }; const bc = new BroadcastChannel("auth"); bc.postMessage({token: t});', 'a.js').filter((f) => f.type === 'token-store').map((f) => f.title);
  assert.deepEqual(cf, ['Token written to localStorage: access_token', 'Logout function does not clear stored tokens', 'BroadcastChannel carries a token: auth']);
});

test('D7: трекеры, запись сессий, согласие, данные в адресах', async () => {
  const { trackerFindings } = await import('../src/core/trackers.js');
  const f = trackerFindings({ urls: ['https://www.googletagmanager.com/gtm.js?id=GTM-X', 'https://static.hotjar.com/c/h.js', 'https://px.ads.linkedin.com/c?email=a%40b.example', 'https://shop.example/app.js'], pageHost: 'shop.example', html: '<form><input type="password"></form>', cookies: [{ name: '_ga', value: '1' }], consent: { onetrust: 'object' }, referrer: 'unsafe-url' });
  const t = f.map((x) => x.title + ':' + x.risk);
  assert.ok(t.includes('Tracker: static.hotjar.com (Session replay):2'), t.join());
  assert.ok(t.includes('Personal data in a URL to px.ads.linkedin.com: email:3'));
  assert.ok(t.includes('Session replay on a page with a form: static.hotjar.com:3'));
  assert.ok(t.includes('Tracker cookies with no visible consent decision: 1:2'));
  assert.ok(!t.some((x) => x.includes('shop.example')));
  assert.equal(C.headerFindings({ 'referrer-policy': 'origin' }, true).filter((x) => /Referrer/.test(x.title)).length, 0);
});

test('E1: каналы реального времени', () => {
  const s = new C.Store('https://a.example/');
  C.analyzeInto(s, 'import "socket.io-client"; const so = io("https://rt.a.example", {path:"/ws/socket.io"}); const ws = new WebSocket("wss://a.example/live?token=x", ["graphql-ws"]); const c = new signalR.HubConnectionBuilder().withUrl("/hubs/chat").build(); const p = new Pusher("0123456789abcdef0123", {cluster:"eu", secret:"abcdef0123456789abcdef"}); const pc = new RTCPeerConnection({iceServers:[{urls:"turn:t.example", username:"u", credential:"s3cretpass"}]})', 'https://a.example/app.js');
  const leads = s.items.filter((f) => f.kind === 'realtime').map((f) => f.url);
  assert.ok(leads.includes('Realtime endpoint without a token in the handshake: https://rt.a.example/ws/socket.io'), leads.join('|'));
  assert.ok(leads.includes('Realtime endpoint without a token in the handshake: /hubs/chat'));
  assert.ok(!leads.some((l) => l.includes('live?token')));
  assert.ok(leads.includes('Pusher app key'));
  const sec = s.items.filter((f) => f.kind === 'secret').map((f) => f.url + ':' + f.risk);
  assert.ok(sec.includes('Pusher app secret:4') && sec.includes('TURN server credential:3'), sec.join());
  assert.ok(!s.items.some((f) => (f.snippet || '').includes('s3cretpass')));
});

test('E4: GraphQL — анонимные, фрагменты, переменные, persisted, черновик SDL', async () => {
  const { graphqlFindings, sdlDraft } = await import('../src/core/graphql.js');
  const g = graphqlFindings('const a = `query { me { id email } }`; const b = "fragment UserFields on User { id name }"; const r = {params:{id:"abc12345", name:"PostQuery", text:null}}; const c = `mutation Upd($id: ID!, $n: [String!]!) { updatePost(id: $id, tags: $n) { id } }`; ext = {persistedQuery:{version:1, sha256Hash:"' + 'a'.repeat(64) + '"}}');
  const t = g.map((x) => x.title + ':' + x.risk);
  assert.ok(t.includes('query (anonymous: me):0'), t.join('|'));
  assert.ok(t.includes('fragment UserFields on User:0') && t.includes('mutation Upd:1') && t.includes('persisted PostQuery abc12345:0'));
  assert.ok(g.find((x) => x.title === 'mutation Upd').why.includes('variables: $id: ID!, $n: [String!]!'));
  const sdl = sdlDraft(g);
  assert.match(sdl, /type Mutation \{\n {2}updatePost\(id: ID!, tags: \[String!\]!\): UpdatePostDraft # guessed/);
  assert.match(sdl, /type User \{[^}]*name: String # guessed/);
});

test('A8: server actions, tRPC, Module Federation, Nuxt/SvelteKit, манифест Vite', async () => {
  const F = await import('../src/core/frameworks.js');
  const s = new C.Store('https://a.example/');
  C.analyzeInto(s, '(0,r.createServerReference)("' + 'ab'.repeat(21) + '",x); import {httpBatchLink} from "@trpc/client"; trpc.post.byId.useQuery({id}); trpc.post.create.useMutation(); router.query.x(); var m={"./Button":()=>x}; __webpack_require__; init()', 'https://a.example/app.js');
  assert.ok(s.items.some((f) => f.url === 'Server action ' + 'ab'.repeat(6)));
  assert.ok(s.items.some((f) => f.url === 'Federated module ./Button'));
  const eps = s.items.filter((f) => /trpc/.test(f.url || '')).map((f) => f.method + ' ' + f.url);
  assert.deepEqual(eps.sort(), ['GET /api/trpc/post.byId', 'POST /api/trpc/post.create']);
  assert.deepEqual(F.pageDataHints('<script>window.__NUXT__={}</script>', 'https://a.example/shop/').map((x) => x.hit), ['/shop/_payload.json']);
  assert.deepEqual(F.pageDataHints('<script src="/_app/immutable/entry.js">', 'https://a.example/a.html').map((x) => x.hit), ['/a.html__data.json']);
  assert.ok(F.viteSignature('<script type="module" crossorigin src="/assets/index-AbC12345.js"></script>'));
  assert.deepEqual(F.viteManifest('{"src/main.ts":{"file":"assets/main-1a2b3c4d.js","src":"src/main.ts"}}', 'https://a.example/.vite/manifest.json').files, ['https://a.example/assets/main-1a2b3c4d.js']);
});

test('D4/D8/D9: discovery, AASA, assetlinks, webauthn, заглушки SPA, мобильные следы', async () => {
  const W = await import('../src/core/wellknown.js');
  const { FORCEABLE } = await import('../src/core/scope.js');
  assert.ok(FORCEABLE.test('/.well-known/openid-configuration') && FORCEABLE.test('/llms.txt') && !FORCEABLE.test('/.well-known/change-password'));
  const s = new C.Store('https://app.example/');
  C.analyzeInto(s, JSON.stringify({ issuer: 'https://app.example', authorization_endpoint: 'https://app.example/authorize', token_endpoint: 'https://app.example/token', response_types_supported: ['code', 'id_token token'], code_challenge_methods_supported: ['plain', 'S256'] }), 'https://app.example/.well-known/openid-configuration');
  const t = s.items.map((f) => f.url + ':' + f.risk);
  assert.ok(t.includes('Server advertises implicit response types:2') && t.includes('Server accepts plain PKCE:2'), t.join('|'));
  assert.ok(s.items.some((f) => f.url === '/token' || f.path === '/token'));
  C.analyzeInto(s, '<!doctype html><html>', 'https://app.example/.well-known/webauthn');
  assert.ok(!s.errors.length && !s.items.some((f) => /webauthn/.test(f.url)), 'заглушка SPA не считается ни файлом, ни ошибкой');
  const a = W.wellKnownFile('{"applinks":{"details":[{"appIDs":["TEAM.com.app"],"components":[{"/":"/*"}]}]}}', 'https://app.example/.well-known/apple-app-site-association', 'app.example');
  assert.deepEqual(a.simple.map((x) => x.title + ':' + x.risk), ['iOS app: TEAM.com.app:0', 'iOS app claims every path:1']);
  assert.equal(W.wellKnownFile('{"origins":["https://other.example"]}', 'https://app.example/.well-known/webauthn', 'app.example').simple[0].risk, 1);
  assert.deepEqual(W.mobileHints('<meta name="apple-itunes-app" content="app-id=123456789"> location.href="myapp://open?x=1"').map((x) => x.title), ['iOS app id: 123456789', 'App deep-link scheme: myapp://']);
});

test('D10: инфраструктура из CSP, preconnect, окружений и сборок', async () => {
  const I = await import('../src/core/infra.js');
  const h = I.infraFromHeaders({ 'content-security-policy': "default-src 'self'; connect-src https://api.segment.io https://app.example; script-src *.cdn.vendor.example", server: 'Vercel' }, '<link rel="preconnect" href="https://fonts.gstatic.com">', 'app.example');
  assert.deepEqual(h.map((x) => x.title + ':' + x.risk), ['Third-party host: api.segment.io:1', 'Third-party host: cdn.vendor.example:0', 'Third-party host: fonts.gstatic.com:0', 'Hosting: Vercel:0']);
  const t = I.infraFromText('fetch("https://staging-api.app.example/x"); cfg={APP_ENV:"staging", GIT_SHA:"a1b2c3d4e5f6"}', 'www.app.example').map((x) => x.title + ':' + x.risk);
  assert.deepEqual(t, ['Test-environment host: staging-api.app.example:1', 'Environment name: staging:1', 'Build or commit id: a1b2c3d4e5f6:0']);
});

test('B4/B5/F5: новые заголовки, префиксы cookie, кеш и CDN', async () => {
  const { auditCookie } = await import('../src/core/cookies.js');
  const t = C.headerFindings({ 'permissions-policy': 'camera=*, fullscreen=*, geolocation=()', 'cross-origin-opener-policy': 'same-origin', 'strict-transport-security': 'max-age=31536000', 'server-timing': 'db;dur=53', 'clear-site-data': 'cache, "cookies"', 'content-security-policy-report-only': "default-src 'self'", 'cache-control': 'private', 'cf-cache-status': 'HIT', 'x-debug-token-link': 'https://a/_profiler/1' }, true, 'https://a.example/').map((x) => x.title + ':' + x.risk);
  for (const e of ['Permissions-Policy allows camera for any origin:1', 'Permissions-Policy allows fullscreen for any origin:0', 'Cross-Origin-Embedder-Policy missing: page is not cross-origin isolated:0', 'HSTS is not ready for preload:0', 'Server-Timing exposes internal metrics:0', 'Clear-Site-Data values are not quoted: header is invalid:0', 'CSP is only Report-Only, nothing is blocked:1', 'CDN returned a cached copy of a response marked private or no-store:1', 'X-Debug-Token-Link: profiler link in response:1']) assert.ok(t.includes(e), e + ' | ' + t.join(' | '));
  assert.ok(!t.some((x) => x.startsWith('Permissions-Policy allows geolocation')));
  assert.equal(auditCookie({ name: '__Host-sid', value: 'x', secure: true, httpOnly: true, sameSite: 'Lax', path: '/app', hostOnly: true, attrsKnown: true }, true).risk, 1);
  assert.equal(auditCookie({ name: '__Host-sid', value: 'x', secure: true, httpOnly: true, sameSite: 'Lax', path: '/', hostOnly: true, attrsKnown: true }, true).risk, 0);
});

test('E6: Speculation Rules, Sanitizer, FedCM, WebAuthn, Storage Access', async () => {
  const B = await import('../src/core/browser.js');
  const { auditHtml } = await import('../src/core/html.js');
  assert.deepEqual(B.speculationFindings('<script type="speculationrules">{"prerender":[{"where":{"href_matches":"/logout"},"eagerness":"immediate"}],"prefetch":[{"urls":["/account/delete"]}]}</script>').map((x) => x.risk), [2, 1]);
  assert.ok(auditHtml('<script type="speculationrules">{"prerender":[{"urls":["/next"]}]}</script>', 'https://a.example/').some((f) => f.title === 'Speculation Rules prerender pages'));
  const t = B.browserFindings('navigator.credentials.get({publicKey:{rpId:"other.example", userVerification:"discouraged"}}); el.setHTML(x, {sanitizer: new Sanitizer({})}); document.requestStorageAccess()', 'app.example').map((x) => x.title + ':' + x.risk);
  assert.deepEqual(t, ['Custom Sanitizer config:1', 'WebAuthn rpId other.example is not the page host app.example:1', 'WebAuthn user verification: discouraged:1', 'Storage Access API used:0']);
  assert.ok(codeFindings('el.setHTMLUnsafe(location.hash)', 'a.js').some((f) => f.type === 'sink'));
});

test('E5: Web3 — RPC-ключи, контракты, дрейнер, SDK без версии', async () => {
  const { web3Findings } = await import('../src/core/web3.js');
  const sec = C.scanSecrets('rpc="https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef"', 'a.js');
  assert.deepEqual(sec.map((x) => x.type + ':' + x.raw.length), ['rpc-infura:32']);
  const t = (x) => web3Findings(x, 'app.js').map((f) => f.title + ':' + f.risk);
  assert.ok(t('const abi=[]; new Contract("0x' + 'a'.repeat(40) + '", abi); const cfg={chainId: 1}; ethereum.request({method:"eth_chainId"})').includes('chainId 1:0'));
  assert.deepEqual(t('setApprovalForAll(op, true); x={primaryType:"Permit", deadline: 2**256}'), ['Signing code that matches a drainer pattern: manual review:2']);
  assert.deepEqual(t('setApprovalForAll(op, true); x={primaryType:"Permit"}'), []);
  assert.deepEqual(t('s.src="https://cdn.jsdelivr.net/npm/@ledgerhq/connect-kit@1"'), ['Wallet SDK from a CDN without an exact version: @ledgerhq/connect-kit@1:1', 'Ledger Connect Kit present:1']);
  assert.deepEqual(t('s.src="https://cdn.jsdelivr.net/npm/@walletconnect/x@1.1.8"'), []);
});

test('G1: импорт скоупа программы', async () => {
  const P = await import('../src/core/program.js');
  const l = P.parseProgram('# scope\n*.example.com\n!blog.example.com\nhttps://api.other.example/v1\n10.0.0.0/8\nnot a host line');
  assert.equal(l.rules.length, 3);
  assert.deepEqual(l.rejected, ['not a host line']);
  assert.ok(P.inScope('app.example.com', l.rules) && !P.inScope('blog.example.com', l.rules) && P.inScope('api.other.example', l.rules) && !P.inScope('x.test', l.rules));
  const h1 = P.parseProgram(JSON.stringify({ data: [{ attributes: { asset_identifier: '*.shop.example', asset_type: 'WILDCARD', eligible_for_submission: true } }, { attributes: { asset_identifier: 'com.shop.app', asset_type: 'GOOGLE_PLAY_APP_ID' } }] }));
  assert.equal(h1.format, 'hackerone');
  assert.ok(P.isOutOfProgram({ kind: 'api', resolved: 'https://cdn.vendor.example/x' }, 'www.shop.example', h1.rules));
  assert.ok(!P.isOutOfProgram({ kind: 'secret' }, 'www.shop.example', h1.rules));
  assert.throws(() => P.parseProgram('{"a":1}'));
});

test('G6/B8: карта поверхности и авторизации', async () => {
  const M = await import('../src/core/map.js');
  const s = new C.Store('https://a.example/');
  C.analyzeInto(s, 'fetch("/api/admin/users"); fetch("/api/users/1"); fetch("/auth/login", {method:"POST"}); fetch("https://api.other.example/v1/me", {headers:{Authorization:"Bearer x"}})', 'https://a.example/app.js');
  const tree = M.surfaceTree(s);
  const own = tree.find((x) => x.name === 'a.example');
  assert.ok(own && own.kids.find((k) => k.name === 'api').kids.some((k) => k.name === 'admin'));
  const auth = M.authMap(s);
  assert.ok(auth.find((r) => r.host === 'api.other.example').crossAuth);
  assert.ok(auth.find((r) => r.host === 'a.example' || r.host === '').roles.includes('login'));
});

test('проверка: нет ReDoS на переводах строк и sk-, токены из адресов не попадают во фрагменты', async () => {
  const { toJSON } = await import('../src/core/export.js');
  let t0 = Date.now(); C.analyzeInto(new C.Store('https://x/'), '\n'.repeat(200000), 'https://x/a.js'); assert.ok(Date.now() - t0 < 3000);
  t0 = Date.now(); C.scanSecrets('sk-'.repeat(50000), 'a.js'); assert.ok(Date.now() - t0 < 3000);
  const s = new C.Store('https://a.example/');
  C.analyzeInto(s, 'new WebSocket("wss://x.io/s?token=SECRETTOKENabcdef123456");\nlocation="https://accounts.google.com/o/oauth2/auth?client_id=1&access_token=ya29.SECRETOAUTHTOKEN123456&redirect_uri=x";\nvar turn={urls:"turn:t.x.io",username:"u",credential:"TURNSECRETPASS99"};\nvar c="card 4539 5787 6362 1486"; h={Authorization:"Bearer SECRETBEARER1234567890"}', 'https://a.example/a.js');
  const out = toJSON(s.list(), { reveal: false });
  for (const v of ['SECRETTOKENabcdef123456', 'ya29.SECRETOAUTHTOKEN123456', 'TURNSECRETPASS99', 'SECRETBEARER1234567890']) assert.ok(!out.includes(v), v);
});

test('QA 29-review-core: маска своих правил, короткие значения, id секретов, debug-сегмент, заголовки, reset, risk', async () => {
  const { toJSON } = await import('../src/core/export.js');
  const { sessionFile, fileKey } = await import('../src/core/session.js');
  const s = new C.Store('https://site.test/'); s.rules = [{ id: 'k', regex: 'sk-[A-Za-z0-9]{12}', risk: 2 }];
  C.analyzeInto(s, 'const a = "sk-ABCDEFGHIJKL";', 'https://site.test/a.js');
  assert.ok(!toJSON(s.list(), { reveal: false }).includes('sk-ABCDEFGHIJKL'));
  assert.ok(!JSON.stringify(sessionFile(s)).includes('sk-ABCDEFGHIJKL'));
  assert.equal(C.mask('hunter2ab'), '**** (9)');
  const t = new C.Store('https://site.test/'), base = { type: 'generic', label: 'x', confidence: 'medium', risk: 2, why: ['x'], file: 'https://site.test/a.js', line: 1, col: 1, snippetRaw: 'x' };
  t.addSecret({ ...base, raw: 'Pa55w0rd' }); t.addSecret({ ...base, raw: 'Xy9!Qz2m' });
  const ids = sessionFile(t).findings.map((f) => f.id); assert.equal(new Set(ids).size, 2);
  const d = new C.Store('https://shop.test/'); C.analyzeInto(d, 'fetch("/products/consoles"); fetch("/debug")', 'https://shop.test/a.js');
  assert.equal(d.items.find((f) => f.url === '/products/consoles').kind, 'api');
  assert.equal(d.items.find((f) => f.url === '/debug').kind, 'debug');
  assert.equal(C.parseHeaders('Constructor: abc').constructor, 'abc');
  assert.equal(fileKey('https://s.test/js/vendor-admin-dashboard-2.js'), 'https://s.test/js/vendor-admin-dashboard-2.js');
  t.replaceHeaders({ server: 'a' }, true); t.reset(); assert.equal(t.docHeaders, null);
  assert.equal(t.addSimple('custom', { title: 'r7', risk: 7 }).level, 'critical');
});

test('QA 01 F3-F9: склейка шаблона, флаги, границы auth/debug, axios с вложенным объектом, имена параметров, this.fetch', () => {
  const hs = (t) => C.analyze(t, 'http://localhost:3000/a.js').hits.map((h) => h.method + ' ' + h.raw);
  assert.ok(hs('fetch(`/api/${a}` + "/x")').some((h) => h.endsWith('/api/${a}/x')));
  assert.ok(hs('fetch("/i")').includes('GET /i'));
  assert.ok(hs('axios({ headers: { a: 1 }, url: "/api/Orders", method: "post" })').includes('POST /api/Orders'));
  assert.equal(C.tplToPath('/u/${a+b}/${user.id}/${i}'), '/u/{param}/{id}/{param}');
  assert.deepEqual(hs('this.fetch("users/list")'), []);
  const s = new C.Store('https://a.example/'); C.analyzeInto(s, 'fetch("/api/tokens/list"); fetch("/products/loginbox")', 'https://a.example/a.js');
  assert.equal(s.items.find((f) => f.path === '/api/tokens/list').kind, 'auth');
  assert.notEqual(s.items.find((f) => f.path === '/products/loginbox').kind, 'auth');
});

test('QA 05: WebSocket без подпротокола, io.connect, метод JS не операция, директива с аргументами, YAML basePath и trace', async () => {
  const { realtimeFindings } = await import('../src/core/realtime.js');
  const { graphqlFindings } = await import('../src/core/graphql.js');
  const { openApiEndpoints } = await import('../src/core/openapi.js');
  assert.ok(realtimeFindings('new WebSocket("wss://a.example/live")').some((r) => r.t === 'hit'));
  assert.ok(realtimeFindings('io.connect("https://rt.example")').some((r) => r.t === 'hit'));
  assert.deepEqual(graphqlFindings('class A { query(a) { return 1 } }'), []);
  assert.equal(graphqlFindings('x=`query Q @cached(ttl: 60) { a }`').length, 1);
  assert.deepEqual(openApiEndpoints('swagger: "2.0"\nbasePath: /v1\npaths:\n  /u:\n    trace:\n      parameters:\n        - name: id\n'), [{ path: '/v1/u', method: 'TRACE', params: ['id'] }]);
});
