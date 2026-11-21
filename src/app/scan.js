// Драйвер скана во вкладке: снимок страницы → Store → обход служебных файлов через сборщик → OSV → история.
import { analyzeInto, crawl, makeScope, scanSecrets, mask, auditHtml, cookieTech } from '../core.js';
import { deniedPath } from '../core/scope.js';
import { auditCookie } from '../core/cookies.js';
import { hostFindings } from '../core/supply.js';
import { ghostRoutes } from '../core/ghost.js';
import { storageFindings } from '../core/tokens.js';
import { piiFindings, maskEmails } from '../core/pii.js';
import { trackerFindings } from '../core/trackers.js';
import { pageDataHints, viteSignature } from '../core/frameworks.js';
import { WELL_KNOWN } from '../core/wellknown.js';
import { infraFromHeaders } from '../core/infra.js';
import { historyKey, historyEntry, compareRuns, compareFiles } from '../core/session.js';

function seeds(page, wellKnown, allowHosts) {
  const out = [], add = (u, via, force) => { try { out.push({ url: new URL(u, page.url).href, depth: 1, via, force }); } catch (e) { /* битый адрес */ } };
  page.scripts.concat(...(page.frames || []).map((f) => f.scripts || [])).forEach((s) => add(s, 'script-src'));
  page.links.forEach((l) => add(l.href, 'link', /manifest/.test(l.rel)));
  // Только реально загруженные скрипты; запросы fetch/XHR страницы никогда не повторяются
  page.resources.forEach((r) => { if ((r.initiator === 'script' || r.initiator === 'link') && /\.m?js(?:$|\?)/i.test(String(r.url).split('#')[0])) add(r.url, 'resource'); });
  // Next.js: манифест сборки со списком страниц (обычный JS-файл сайта)
  const bid = /_next\//.test(page.html) && /"buildId"\s*:\s*"([\w.-]{4,64})"/.exec(page.html);
  if (bid) add('/_next/static/' + bid[1] + '/_buildManifest.js', 'next');
  (page.sw || []).forEach((w) => { if (w.script) add(w.script, 'service-worker'); }); // скрипт service worker — обычный JS сайта
  if (viteSignature(page.html)) add('/.vite/manifest.json', 'vite-manifest');
  if (wellKnown) {
    WELL_KNOWN.forEach((p) => add(p, 'well-known', true));
    // Discovery на чужом хосте — только для хостов, которые пользователь сам добавил в скоуп
    (allowHosts || []).forEach((h) => add('https://' + h + '/.well-known/openid-configuration', 'well-known', true));
  }
  return out;
}

export function addTraffic(store, entries) {
  entries.forEach((e) => store.addHit({ raw: e.url, file: '(page traffic)', line: 1, col: 1, via: 'observed', confidence: 'high', snippet: e.initiator + (e.status ? ' ' + e.status : '') }));
}
export function addCookies(store, cookies, isHttps) {
  for (const c of cookies) {
    const a = auditCookie(c, isHttps);
    if (a.risk) store.addSimple('cookie', { title: 'Cookie ' + c.name, risk: a.risk, why: a.why, file: 'cookies' });
    scanSecrets(String(c.value || ''), 'cookie: ' + c.name).forEach((s) => store.addSecret(s));
  }
}

export async function runScan({ store, snapshot: page, fetchText, settings = {}, isStopped = () => false, osv, npm, history }) {
  store.rules = Array.isArray(settings.rules) && settings.rules.length ? settings.rules : null;
  store.status = 'scanning'; store.notify();
  // Адрес страницы без #: на SPA с hash-роутингом (#/login) иначе страница выглядит как исходник из source map
  const doc = page.url.split('#')[0];
  store.addText(doc, page.html, page.contentType);
  analyzeInto(store, page.html, doc);
  auditHtml(page.html, page.url).forEach((f) => store.addSimple('dom', Object.assign({ file: doc }, f)));
  // Разметка — только текущего экрана: в SPA другие маршруты (#/login) не отрисованы и не проверены
  store.addSimple('dom', { title: 'HTML checked for the current view only: ' + page.url, risk: 0, why: ['Other routes of a single-page app are not rendered; open them and run Routelark again to check their forms'], file: doc });
  pageDataHints(page.html, page.url).forEach((x) => store.addHit({ raw: x.hit, method: x.method, file: doc, line: 1, col: 1, via: x.via, confidence: x.confidence, snippet: x.why }));
  // Хосты подключённых файлов: захваченные CDN, подменённые скрипты поставщиков, похожие на CDN домены
  const integ = new Set(); for (const m of String(page.html).matchAll(/<(?:script|link)\b[^>]*\b(?:src|href)\s*=\s*["']([^"']+)["'][^>]*\bintegrity\s*=/gi)) { try { integ.add(new URL(m[1], page.url).href); } catch (e) { /* битый адрес */ } }
  hostFindings((page.resources || []).map((r) => ({ url: r.url, script: r.initiator === 'script' || /\.m?js(?:$|\?)/.test(String(r.url)), sri: integ.has(r.url) })), store.pageHost).forEach((f) => store.addSimple('custom', Object.assign({ file: doc }, f)));
  for (const f of page.frames || []) {
    const u = String(f.url).split('#')[0];
    if (!/^https?:/.test(u) || u === doc) continue; // about:blank и сама страница
    store.addText(u, f.html, 'text/html'); analyzeInto(store, f.html, u);
    auditHtml(f.html, f.url).forEach((x) => store.addSimple('dom', Object.assign({ file: u }, x)));
  }
  cookieTech((page.cookies || []).map((c) => c.name)).forEach((name) => store.addTech({ name }, 'cookies'));
  page.globals.forEach((t) => store.addTech(t, '(page)'));
  (page.devGlobals || []).forEach((d) => store.addCode({ type: 'devtools', title: d.title, risk: d.risk, why: d.why, file: doc, line: 1, col: 1, snippet: '' }));
  if (page.ngVersion) store.addTech({ name: 'Angular', version: page.ngVersion }, '(page)');
  for (const [kind, list] of [['localStorage', page.storage.local], ['sessionStorage', page.storage.session]]) for (const [k, v] of list) {
    const sec = scanSecrets(v, kind + ': ' + k); sec.forEach((s) => store.addSecret(s));
    // Фрагмент находки с персональными данными не должен показывать секрет из того же значения
    const pii = piiFindings(v, kind + ': ' + k);
    pii.forEach((p) => { p.snippet = maskEmails(pii.reduce((x, q) => (q.raw ? x.split(q.raw).join(q.masked) : x), sec.reduce((x, s) => (s.noMask ? x : x.split(s.raw).join(mask(s.raw))), p.snippetRaw))); store.addPii(p); });
  }
  for (const w of page.sw || []) store.addSimple('storage', { title: 'Service worker: ' + (w.script || w.scope), risk: 0, why: ['Scope ' + w.scope + (w.push ? ', push subscription at ' + w.push : '') + '. A service worker sees every request in its scope: read its script in Files'], file: doc });
  if ((page.caches || []).length) store.addSimple('storage', { title: 'Cache Storage: ' + page.caches.length + ' caches', risk: 0, why: [page.caches.slice(0, 20).join(', '), 'Only the names are read; cached responses may hold personal data, check them in DevTools'], file: doc });
  storageFindings(page.storage.local, page.storage.session, page.idb).forEach((f) => store.addSimple('storage', Object.assign({ file: doc }, f)));
  const https = /^https:/.test(page.url);
  addCookies(store, page.cookies, https);
  addTraffic(store, page.resources.filter((r) => /fetch|xmlhttprequest|beacon/.test(r.initiator)));
  store.notify();
  if (!settings.noRequests) {
    if (page.contentType === 'text/html' && !deniedPath(new URL(page.url).pathname + new URL(page.url).search)) {
      const r = await fetchText(page.url, { doc: true });
      if (r.ok && r.headers) store.replaceHeaders(r.headers, https);
    }
    await crawl({ store, seeds: seeds(page, settings.wellKnown !== false, settings.allowHosts), fetchText, isStopped, conc: 1, maxFiles: 2000, maxDepth: settings.depth || 3, guessMaps: !!settings.guessMaps, scope: makeScope({ pageUrl: page.url, allowHosts: settings.allowHosts || [] }) });
  }
  if (osv && settings.osv !== false) {
    // По три запроса к OSV параллельно, а не по одному
    const techs = store.items.filter((x) => x.kind === 'tech' && x.version);
    for (let i = 0; i < techs.length && !isStopped(); i += 3) await Promise.all(techs.slice(i, i + 3).map(async (f) => { try { let vulns = await osv(f.name, f.version) || []; if (f.name === 'Angular') vulns = vulns.concat(await osv('@angular/compiler', f.version) || []); /* часть CVE Angular объявлена только для compiler */ if (vulns.length) store.addOsv(f.name, vulns); } catch (e) { /* OSV недоступен: остаётся сверенная таблица */ } }));
  }
  // Зависимости с версией (из путей pnpm и баннеров) тоже сверяются с OSV: записи MAL- — известные вредоносные версии
  if (osv && settings.osv !== false) {
    const deps = Array.from(store.deps.values()).filter((d) => d.version).slice(0, 60);
    for (let i = 0; i < deps.length && !isStopped(); i += 3) await Promise.all(deps.slice(i, i + 3).map(async (d) => { try { const v = await osv(d.name, d.version); for (const x of v || []) if (/^MAL-/.test(x.id) || /malicious|malware/i.test(x.summary || '')) store.addSimple('custom', { title: 'Known-bad release: ' + d.name + '@' + d.version, risk: 3, why: [x.id + ': ' + String(x.summary || 'malicious package').slice(0, 140), 'The version is visible on the page; that alone does not prove it is installed'], file: '(source map)' }); } catch (e) { /* OSV недоступен */ } }));
  }
  // Пакеты со scope из source map: если такого имени нет на npm, его может занять кто угодно (dependency confusion)
  if (npm) {
    for (const d of Array.from(store.deps.values()).filter((x) => x.scoped).slice(0, 20)) {
      if (isStopped()) break;
      try { if (await npm(d.name) === 404) store.addSimple('custom', { title: 'Package ' + d.name + ' is not on npm', risk: 2, why: ['Scoped package is not found on npm: check who owns the scope, dependency confusion is possible if it is free'], file: 'source map' }); } catch (e) { /* npm недоступен */ }
    }
  }
  ghostRoutes(store, page.anchors);
  infraFromHeaders(store.docHeaders, page.html, store.pageHost).forEach((f) => store.addSimple('infra', Object.assign({ file: doc }, f)));
  const refPol = ((store.docHeaders || {})['referrer-policy'] || (/<meta\b[^>]*name\s*=\s*["']referrer["'][^>]*content\s*=\s*["']([^"']+)/i.exec(page.html) || [])[1] || '').trim();
  trackerFindings({ urls: (page.resources || []).map((r) => r.url).concat(page.scripts || []), pageHost: store.pageHost, html: page.html, cookies: page.cookies, consent: page.consent, referrer: refPol }).forEach((f) => store.addSimple(f.kind, Object.assign({ file: doc }, f)));
  let diff = null, prevLabels = {}, fileDiff = null;
  if (history) {
    const key = historyKey(new URL(page.url).origin), prev = history.get(key);
    if (prev) { diff = compareRuns(prev.ids, store); prevLabels = prev.labels || {}; if (prev.files && Object.keys(prev.files).length) fileDiff = compareFiles(prev.files, store); }
    // Остановленный скан неполный: не сравниваем с ним и не делаем его базой следующего
    if (isStopped()) { diff = null; fileDiff = null; } else history.set(key, historyEntry(store));
  }
  store.status = isStopped() ? 'stopped' : 'done'; store.notify();
  return { diff, prevLabels, fileDiff };
}
