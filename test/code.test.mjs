import test from 'node:test';
import assert from 'node:assert/strict';
import { codeFindings } from '../src/core/code.js';
import { openApiEndpoints } from '../src/core/openapi.js';
import { matchAdvisories, osvQuery } from '../src/core/advisories.js';
import * as C from '../src/core.js';

const types = (t) => codeFindings(t, 'a.js').map((f) => f.type);

test('DOM-sink только рядом с источником данных', () => {
  assert.deepEqual(types('el.innerHTML = location.hash.slice(1)'), ['sink']);
  assert.deepEqual(types('el.innerHTML = "<b>x</b>"'), []);
});

test('message-обработчик: без проверки origin — риск, с проверкой — инфо', () => {
  const bad = codeFindings('window.addEventListener("message", e => { eval(e.data) })', 'a.js').find((f) => f.type === 'postmessage');
  const ok = codeFindings('addEventListener("message", function(e){ if (e.origin !== "https://x") return; run(e.data) })', 'a.js').find((f) => f.type === 'postmessage');
  assert.equal(bad.risk, 2);
  assert.equal(ok.risk, 0);
});

test('скрытые маршруты, внутренние хосты, TODO с подавлением шума', () => {
  assert.ok(types('routes=[{path:"/admin/users"}]').includes('route'));
  assert.ok(types('var h="10.0.0.5"').includes('internal'));
  assert.ok(!types('var h="http://localhost:3000"').includes('internal'));
  assert.equal(types('// TODO a\n// TODO b\n// FIXME c').filter((t) => t === 'todo').length, 1);
  assert.ok(!types('if (user.can && x.admin) {}').includes('authz'));
  assert.ok(types('if (user.isAdmin) show()').includes('authz'));
});

test('OpenAPI JSON и YAML → эндпоинты', () => {
  assert.deepEqual(openApiEndpoints('{"openapi":"3.0.0","paths":{"/u/{id}":{"get":{"parameters":[{"name":"id"}]}}}}'), [{ path: '/u/{id}', method: 'GET', params: ['id'] }]);
  assert.deepEqual(openApiEndpoints('openapi: 3.0.0\npaths:\n  /x:\n    post:\n      summary: s\n  /y/{id}:\n    get: {}\n'), [{ path: '/x', method: 'POST', params: [] }, { path: '/y/{id}', method: 'GET', params: [] }]);
  assert.equal(openApiEndpoints('{"a":1}'), null);
});

test('analyzeInto разбирает спецификацию в эндпоинты', () => {
  const s = new C.Store('https://app.example.org/');
  C.analyzeInto(s, '{"swagger":"2.0","basePath":"/api","paths":{"/orders":{"post":{"parameters":[{"name":"price"}]}}}}', 'https://app.example.org/swagger.json');
  const f = s.items.find((x) => x.path === '/api/orders');
  assert.equal(f.method, 'POST');
  assert.ok(f.vias.includes('openapi'));
  assert.ok(f.params.includes('price'));
  const s2 = new C.Store('https://app.example.org/');
  C.analyzeInto(s2, '{"info":{"title":"x"},"openapi":"3.1.0","paths":{"/abc":{"delete":{}}}}', 'https://app.example.org/openapi.json');
  assert.equal(s2.items.find((x) => x.path === '/abc').method, 'DELETE');
});

test('CVE по сверенной таблице, только с известной версией', () => {
  assert.ok(matchAdvisories('jQuery', '3.4.1').some((a) => a.id === 'CVE-2020-11022'));
  assert.ok(matchAdvisories('Bootstrap', '4.3.0').some((a) => a.id === 'CVE-2019-8331'));
  assert.deepEqual(matchAdvisories('Bootstrap', '4.2.1'), []);
  assert.deepEqual(matchAdvisories('Vue', null), []);
  assert.ok(matchAdvisories('Moment.js', '2.20.0').length);
  assert.deepEqual(matchAdvisories('Moment.js', '2.17.0'), []);
  assert.deepEqual(osvQuery('jQuery', '3.4.1').body, { package: { name: 'jquery', ecosystem: 'npm' }, version: '3.4.1' });
  assert.equal(osvQuery('jQuery', null), null);
});

test('находки кода и CVE попадают в Store', () => {
  const s = new C.Store('https://app.example.org/');
  C.analyzeInto(s, 'el.innerHTML = location.hash; /*! jQuery v3.4.1 */', 'https://app.example.org/a.js');
  assert.ok(s.items.some((f) => f.kind === 'code'));
  const jq = s.items.find((f) => f.kind === 'tech' && f.name === 'jQuery');
  assert.ok(jq.advisories.some((a) => a.id === 'CVE-2020-11022'));
  assert.ok(jq.risk >= 2);
});

const risk = (t, type) => codeFindings(t, 'a.js').filter((f) => f.type === type).map((f) => f.risk);
test('A5: строгая и слабая проверка origin', () => {
  const h = (c) => 'addEventListener("message", e => { if (' + c + ') run(e.data) })';
  assert.deepEqual(risk(h('e.origin.indexOf("https://a.com") !== -1'), 'postmessage'), [2]);
  assert.deepEqual(risk(h('e.origin.endsWith("a.com")'), 'postmessage'), [2]);
  assert.deepEqual(risk(h('e.origin === "https://a.com"'), 'postmessage'), [0]);
  assert.deepEqual(risk(h('/https:\\/\\/a.com/.test(e.origin)'), 'postmessage'), [2]);
  assert.deepEqual(risk(h('/^https:\\/\\/a\\.com$/.test(e.origin)'), 'postmessage'), [0]);
  assert.deepEqual(risk(h('e.origin === "null"'), 'postmessage'), [2]);
  assert.deepEqual(risk(h('e.isTrusted'), 'postmessage'), [2]);
});
test('A5: postMessage на *, прототипное загрязнение, CSPT', () => {
  assert.deepEqual(risk('w.postMessage({token: t}, "*")', 'postmessage'), [2]);
  assert.deepEqual(risk('w.postMessage(data, "*")', 'postmessage'), [1]);
  assert.deepEqual(risk('w.postMessage(data, "https://a.com")', 'postmessage'), []);
  const merge = 'function merge(t,s){for(const k in s){ if(typeof s[k]==="object"){ merge(t[k]??={}, s[k]) } else t[k]=s[k] }}';
  assert.deepEqual(risk(merge, 'proto'), [1]);
  assert.deepEqual(risk(merge + ' JSON.parse(x)', 'proto'), [2]);
  assert.deepEqual(risk(merge.replace('{for', '{for(;;)break;for').replace('if(typeof', 'if(k==="__proto__"||k==="constructor")continue; if(typeof'), 'proto'), []);
  assert.deepEqual(risk('s.replace("__proto__","")', 'proto'), [2]);
  assert.deepEqual(risk('const id = location.hash.slice(1); fetch(`/api/users/${id}`)', 'cspt'), [2]);
  assert.deepEqual(risk('const id = location.hash.slice(1); fetch(`/api/users/${encodeURIComponent(id)}`)', 'cspt'), []);
  assert.deepEqual(risk('const id = location.hash.slice(1); fetch(`/api/u/${id}`, {method:"POST"})', 'cspt'), [3]);
  assert.deepEqual(risk('fetch(`/api/users/${id}`)', 'cspt'), []);
});
test('A5: обходы доверия, JSONP, перенаправления', () => {
  assert.deepEqual(risk('this.s.bypassSecurityTrustHtml(html)', 'trust'), [2]);
  assert.deepEqual(risk('bypassSecurityTrustUrl("https://x")', 'trust'), []);
  assert.deepEqual(risk('<div v-html="content">', 'trust'), [2]);
  assert.deepEqual(risk('<div v-html="\'<b>x</b>\'">', 'trust'), []);
  assert.deepEqual(codeFindings('<div dangerouslySetInnerHTML={{__html: location.hash}} />', 'a.js').map((f) => f.type), ['trust']);
  assert.deepEqual(risk('dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(x)}}', 'trust'), [0]);
  assert.deepEqual(risk('dangerouslySetInnerHTML={{__html: "<b>x</b>"}}', 'trust'), []);
  assert.deepEqual(risk('trustedTypes.createPolicy("p", {createHTML: (s) => s})', 'trust'), [1]);
  assert.deepEqual(risk('trustedTypes.createPolicy("p", {createHTML: (s) => DOMPurify.sanitize(s)})', 'trust'), []);
  assert.deepEqual(risk('src="/api?callback=" + name', 'jsonp'), [2]);
  assert.deepEqual(risk('src="/api?callback=cb"', 'jsonp'), []);
  const next = 'const next = new URLSearchParams(location.search).get("next"); ';
  assert.deepEqual(risk(next + 'location.href = next', 'redirect'), [2]);
  assert.deepEqual(risk(next + 'if (new URL(next).origin === location.origin) location.href = next', 'redirect'), []);
  assert.deepEqual(risk('if (location.href === x) y()', 'redirect'), []);
  assert.deepEqual(codeFindings('a'.repeat(1e6), 'a.js'), []);
});

test('H1: таблица 2026 — Next.js, Angular, DOMPurify, Nuxt', () => {
  const ids = (n, v) => matchAdvisories(n, v).map((a) => a.id);
  assert.ok(ids('Next.js', '16.2.11').includes('GHSA-2464-fhr4-w9xw'));
  assert.equal(ids('Next.js', '16.4.6').length, 0);
  assert.ok(ids('Angular', '20.3.17').includes('CVE-2026-32635'));
  assert.ok(ids('DOMPurify', '3.4.16').includes('CVE-2026-116803'));
  assert.equal(ids('DOMPurify', '3.4.17').length, 0);
  assert.ok(ids('Nuxt', '4.4.6').includes('CVE-2026-56317'));
  assert.equal(C.techFromText('<app-root ng-version="20.3.17">').find((t) => t.name === 'Angular').version, '20.3.17');
});

test('B3/F1: флаги, отладка, обход, лимиты, цены', () => {
  const r = (t, ty) => codeFindings(t, 'a.js').filter((f) => f.type === ty).map((f) => f.title + ':' + f.risk);
  assert.deepEqual(r('if (useFlag("new-checkout")) x()', 'flag'), ['Feature flag: new-checkout:0']);
  assert.deepEqual(r('const debugMode = true', 'debug-flag'), ['Debug switch in client code: debugMode:1']);
  assert.deepEqual(r('// debugMode docs', 'debug-flag'), []);
  assert.deepEqual(r('if (cfg.bypassAuth) next()', 'bypass'), ['Auth bypass switch in client code: bypassAuth:2']);
  assert.deepEqual(r('const MAX_LOGIN_ATTEMPTS = 5', 'biz-limit'), ['Limit in client code: MAX_LOGIN_ATTEMPTS = 5:1']);
  assert.deepEqual(r('const total = price * qty', 'biz-calc'), []);
  assert.deepEqual(r('const total = price * qty; api.post("/checkout", {total})', 'biz-calc'), ['Price or discount calculated in client code:1']);
});

test('D6: персональные данные с контрольными суммами', async () => {
  const { piiFindings, innOk, ibanOk, luhn } = await import('../src/core/pii.js');
  assert.ok(luhn('4539578763621486') && ibanOk('DE89370400440532013000') && innOk('7707083893'));
  const ty = (t, src) => piiFindings(t, src || 'a.js').map((f) => f.type + ':' + f.risk);
  assert.deepEqual(ty('card: "4539 5787 6362 1486"'), ['card:2']);
  assert.deepEqual(ty('id 4539578763621486 x'), []);
  assert.deepEqual(ty('n="4111111111111111" card'), ['card:0']);
  assert.deepEqual(ty('IBAN DE89 3704 0044 0532 0130 00'), ['iban:2']);
  assert.deepEqual(ty('ИНН 7707083893'), ['inn:1']);
  assert.deepEqual(ty('x 7707083893'), []);
  assert.deepEqual(ty('mail ivan.petrov@corp-mail.ru'), ['email:0']);
  const f = piiFindings('card 4539 5787 6362 1486', 'a.js')[0];
  assert.equal(f.masked, '453957…1486 (16)');
  const s = new C.Store('https://a.example/');
  C.analyzeInto(s, 'var c = "card 4539 5787 6362 1486"', 'https://a.example/a.js');
  const p = s.items.find((x) => x.kind === 'pii');
  assert.ok(p && !p.snippet.includes('6362') && !p.id.includes('4539'));
});

test('F2/F3: dev-сборки и утечки окружения сборки', async () => {
  const { devbuildText, devtoolsFromRuntime } = await import('../src/core/devbuild.js');
  const t = (x, f) => devbuildText(x, f || 'a.js').map((d) => d.type + ':' + d.risk + ':' + d.title);
  assert.deepEqual(t('const e={"NEXT_PUBLIC_API_SECRET":"x","VITE_STRIPE_PUBLISHABLE_KEY":"pk","REACT_APP_FEATURE":"1"}'), ['buildenv:3:Secret-named build variable in client code: NEXT_PUBLIC_API_SECRET', 'buildenv:1:Build variable in client code: REACT_APP_FEATURE']);
  assert.ok(t('src="/Users/ivan/project/src/a.js"')[0].startsWith("buildenv:1:Author's build path in code: /Users/ivan/"));
  assert.deepEqual(t('fetch("https://nexus.corp.example/x")').length, 1);
  assert.deepEqual(t('x.__VUE_PROD_DEVTOOLS__ = true'), ['devbuild:2:Vue DevTools enabled in production']);
  assert.deepEqual(t('require("react-dom.development")', 'm.map#src/x.js'), ['devbuild:0:React development build referenced']);
  assert.deepEqual(devtoolsFromRuntime({ SwaggerUIBundle() {}, ng: { getComponent() {} } }).map((d) => d.risk), [2, 2]);
});

test('F4: обфускация, распаковка и расшифровка без выполнения', async () => {
  const O = await import('../src/core/obfuscation.js');
  const { readFileSync } = await import('node:fs');
  assert.ok(!/\beval\s*\(|new\s+Function|setTimeout\s*\(\s*['"`]/.test(readFileSync(new URL('../src/core/obfuscation.js', import.meta.url), 'utf8').replace(/PACKED = .*|eval\\\(function.*|\/\/.*$/gm, '')));
  assert.deepEqual(O.unpackPacked("eval(function(p,a,c,k,e,d){return p}('0 1=2;',10,3,'var|x|y'.split('|'),0,{}))"), { text: 'var x=y;', depth: 1 });
  assert.equal(O.unpackPacked('var a=1'), null);
  assert.equal(O.obfuscationScore("eval(function(p,a,c,k,e,d){return p}('0',10,1,'a'.split('|'),0,{}))").level, 'obfuscated');
  assert.equal(O.obfuscationScore('!function(e){var t={};function n(r){return t[r]}}([])').level, null);
  const ids = Array.from({ length: 12 }, (_, i) => '_0x' + (0x1a2b + i).toString(16)).join('+');
  assert.equal(O.obfuscationScore('var x=' + ids).level, 'possible');
  assert.equal(O.decodeEscapes('\\x41\\u0042\\\\x43'), 'AB\\\\x43');
  assert.equal(O.decodeB64('aGVsbG8='), 'hello');
  assert.deepEqual(O.decodeLiterals('a="\\x68\\x69";\nb=atob("aGk=")').map((d) => d.line + ':' + d.decoded), ['1:hi', '2:hi']);
  const s = new C.Store('https://a.example/');
  s.addText('https://a.example/x.js', "eval(function(p,a,c,k,e,d){return p}('0',10,1,'a'.split('|'),0,{}))");
  assert.ok(s.obf.get('https://a.example/x.js') && s.items.some((f) => f.kind === 'obfuscation'));
});

test('хеш пароля: пара ключ-значение, константы, энтропия, криптоконтекст, источник, объединение', async () => {
  const { piiFindings } = await import('../src/core/pii.js');
  const H = '5f4dcc3b5aa765d61d8327deb882cf99', H2 = '9b74c9897bac770ffc029102a200c5de';
  const hs = (t, src) => piiFindings(t, src || 'app.js').filter((f) => f.type === 'hash').map((f) => f.risk + ':' + f.confidence);
  assert.deepEqual(hs('user={password:"' + H + '"}'), ['2:medium']);
  assert.deepEqual(hs('// password policy\nconst x = "' + H + '"'), [], 'слово рядом без пары ключ-значение');
  assert.deepEqual(hs('{password:"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'), [], 'хеш пустой строки');
  assert.deepEqual(hs('{password:"' + '6'.repeat(32) + '"}'), [], 'низкая энтропия');
  assert.deepEqual(hs('const curve = elliptic; {password:"' + H + '"}'), [], 'криптографический контекст');
  assert.deepEqual(hs('{password:"' + H + '"}', 'https://a/static/js/vendors~main.chunk.js'), ['1:low'], 'vendor-бандл понижает');
  assert.deepEqual(hs('{"password":"' + H + '"}', 'localStorage: user'), ['2:medium']);
  assert.deepEqual(hs('{hash:"' + H2 + '"}'), ['1:low'], 'ключ hash сам по себе слабее');
  const s = new C.Store('https://a.example/');
  for (let i = 0; i < 6; i++) C.analyzeInto(s, 'x={password:"' + H + '"}', 'https://a.example/f' + i + '.js');
  const f = s.items.filter((x) => x.kind === 'pii' && x.type === 'hash');
  assert.equal(f.length, 1); assert.equal(f[0].sources.length, 6); assert.equal(f[0].risk, 0);
});

test('QA Wave 3: вредные входы обрабатываются быстро, токены по-прежнему находятся', async () => {
  const { graphqlFindings } = await import('../src/core/graphql.js');
  const { auditHtml } = await import('../src/core/html.js');
  const fast = (f) => { const t = Date.now(); f(); return Date.now() - t < 1500; };
  assert.ok(fast(() => C.scanSecrets('-eyJ'.repeat(50000), 'a.js')));
  assert.ok(fast(() => C.scanSecrets('xpk.eyJ'.repeat(30000), 'a.js')));
  assert.ok(fast(() => graphqlFindings('\nquery' + ' '.repeat(200000) + 'x')));
  assert.ok(fast(() => codeFindings('*' + ' '.repeat(1e6) + 'x checkout', 'a.js')));
  assert.ok(fast(() => auditHtml('<svg ' + 'a'.repeat(200000), 'https://a/')));
  assert.ok(fast(() => C.analyze('{a:"abcdef"' + ' '.repeat(200000) + 'x', 'https://a/a.js')));
  assert.deepEqual(C.scanSecrets('x="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig"', 'a.js').map((s) => s.type), ['jwt']);
  assert.deepEqual(C.scanSecrets('t="pk.eyJ1IjoiZXhhbXBsZSJ9.Qx7mZp2LkR9vTbYs1Nd"', 'a.js').map((s) => s.type), ['mapbox-pub']);
  assert.ok(C.analyze('x="https://my-bucket.s3.amazonaws.com/a"', 'https://a/a.js').clouds.length === 1);
});

test('QA Wave 4: эндпоинты с базой, web3, код, HTML, заголовки, секреты, стек', async () => {
  const { web3Findings } = await import('../src/core/web3.js');
  const { auditHtml } = await import('../src/core/html.js');
  const { speculationFindings } = await import('../src/core/browser.js');
  const hits = (t) => C.analyze(t, 'http://localhost:3000/a.js').hits.map((h) => h.method + ' ' + h.raw);
  assert.ok(hits("class S { host = '/api/Items'; get(id) { return this.http.get(`${this.host}/${id}`); } }").includes('GET /api/Items/${id}'));
  assert.ok(hits("class S { host = '/api/Items'; a() { return this.http.post(this.host + '/', { x: 1 }); } }").includes('POST /api/Items/'));
  const adm = new C.Store('https://a.example/'); C.analyzeInto(adm, 'host = this.hostServer + `/rest/admin`; fetch("/rest/admin/application-version")', 'https://a.example/a.js');
  assert.notEqual(adm.items.find((f) => f.path === '/rest/admin').kind, 'debug');
  assert.deepEqual(web3Findings('chainId: 1, chainId: 3, a="0x0000000000000000000000000000000000000000" contract', 'x.js'), []);
  assert.equal(web3Findings('x=`0x41427790c94E7a592B17ad694eD9c06A02bb9C39`; ethereum.request({method:"wallet_switchEthereumChain", params:[{chainId:`0xaa36a7`}]})', 'https://testnet.example/app.js').length, 2);
  const ty = (t) => codeFindings(t, 'a.js').map((f) => f.type + ':' + f.risk);
  assert.deepEqual(ty('this.ws.onmessage = e => this.onData(e.data)'), []);
  assert.ok(ty('window.addEventListener("message", e => { if (e.origin !== window.location.origin) return; run(e.data) })').includes('postmessage:0'));
  assert.deepEqual(ty('bypassSecurityTrustHtml(t){return Id(t)}'), []);
  assert.deepEqual(ty('localStorage.setItem("author", n)'), []);
  assert.ok(ty('const v = location.hash; el.innerHTML = v;').includes('sink:2'));
  assert.ok(auditHtml('<a href="javascript:void(0)">x</a><a href="javascript:alert(1)">y</a>', 'https://a/').some((f) => /javascript: URLs/.test(f.title)));
  assert.equal(speculationFindings('<script type="speculationrules">{"prerender":[{"urls":["/logout"]}]}</script>')[0].risk, 2);
  const h = (x) => C.headerFindings(x, true).map((f) => f.title);
  assert.ok(h({ 'content-security-policy': "img-src 'self'" }).includes('CSP does not restrict scripts'));
  assert.ok(!h({ 'content-security-policy': "script-src 'self' 'unsafe-inline' 'nonce-abc'" }).includes('CSP allows unsafe-inline or unsafe-eval'));
  assert.ok(!h(C.parseHeaders("Content-Security-Policy: script-src 'self'\nContent-Security-Policy: default-src *")).includes('CSP allows scripts from any host'));
  assert.ok(h({ 'referrer-policy': 'strict-origin, unsafe-url' }).some((t) => /Referrer-Policy/.test(t)));
  assert.ok(h({ 'access-control-allow-origin': 'null', 'access-control-allow-credentials': 'true' }).includes('CORS: null origin with credentials'));
  const sec = (t) => C.scanSecrets(t, 'a.js').map((s) => s.type);
  assert.deepEqual(sec('x={passwordComponent:`passwordComponent`}'), []);
  assert.deepEqual(sec('if (s.includes("-----BEGIN RSA PRIVATE KEY-----")) x()'), []);
  assert.deepEqual(sec('h={Authorization:"Bearer YOUR_ACCESS_TOKEN_GOES_HERE"}'), []);
  assert.deepEqual(sec('t="dop_v1_' + 'a'.repeat(32) + 'b'.repeat(32) + '"'), ['digitalocean']);
  assert.equal(C.jwtInfo(Buffer.from('{"alg":"HS256"}').toString('base64url') + '.' + Buffer.from('{"exp":1e20}').toString('base64url') + '.s').why.includes('exp not a valid time'), true);
  assert.ok(C.techFromText('ethers/5.8.0').some((t) => t.name === 'ethers' && t.version === '5.8.0'));
});
