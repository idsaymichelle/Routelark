// Сборщик: выполняется на странице из закладки. Собирает данные, качает служебные файлы по запросу вкладки
// и сам проверяет каждый запрос. Страницу не меняет: ни стилей, ни DOM, ни подмен API.
import { makeScope, blockedReason, clampSettings, deniedPath, siteOf } from './core/scope.js';
import { writeString, deleteString, parseCookieHeader, cookieVariants, badCookieValue } from './core/cookies.js';
import { techFromRuntime } from './core/tech.js';
import { devtoolsFromRuntime } from './core/devbuild.js';

// Редиректы не проходим (redirect: 'error'): иначе разрешённый файл мог бы увести запрос на /logout, API или чужой хост
const VERSION = 2, MAX_BYTES = 25e6, MAX_TIME = 3e5;
// Свои запросы Routelark (OSV, npm) идут из окна страницы: в её ресурсы и трафик их не включаем
const OWN_HOSTS = /^https:\/\/(?:api\.osv\.dev|registry\.npmjs\.org)\//;

// Прямой канал между сборщиком и интерфейсом во вкладке. Обе стороны работают в окне страницы, поэтому postMessage
// браузера не отличил бы отправителя. Доставка асинхронная. Скрипты самого сайта работают в том же окне и могут
// дотянуться до вкладки: это ограничение схемы «всё в закладке», см. SECURITY.md
export function channel(win, tab) {
  const toTab = [], toPage = [], origin = win.location.origin;
  // Страница ушла (перезагрузка, переход): вкладка узнаёт об этом и пишет «страница закрыта», а не ждёт ответа
  let gone = false;
  if (win.addEventListener) win.addEventListener('pagehide', () => { gone = true; });
  const timer = tab.setTimeout ? tab : win; // таймеры вкладки живут, даже когда страница уже выгружена
  const deliver = (list, data, source) => timer.setTimeout(() => list.forEach((fn) => fn({ data, origin, source })), 0);
  const tabEnd = { get closed() { return !!tab.closed; }, postMessage: (data) => deliver(toTab, data, pageEnd) };
  const pageEnd = { get closed() { return gone; }, postMessage: (data) => { if (!gone) deliver(toPage, data, tabEnd); } };
  return { port: { opener: pageEnd, listen: (fn) => toTab.push(fn) }, collector: { win, tab: tabEnd, listen: (fn) => toPage.push(fn) } };
}

// tab — вкладка Routelark, которую открыла закладка (about:blank того же origin, что и страница)
// listen — канал, по которому приходят сообщения вкладки (по умолчанию message окна)
export function createCollector({ win, tab, listen = (fn) => win.addEventListener('message', fn), sleep = (ms) => new Promise((r) => win.setTimeout(r, ms)) }) {
  const doc = win.document, appOrigin = win.location.origin, page = win.location.href, app = tab;
  let policy = clampSettings({}), queue = [], used = 0, bytes = 0, started = 0, last = 0, connected = false, lastCookie = null;
  const stopped = new Set();
  // Свои запросы помнятся в окне страницы между нажатиями закладки: буфер ресурсов браузера живёт дольше одного запуска
  const OWN = win[Symbol.for('routelark.own')] || (win[Symbol.for('routelark.own')] = new Set());
  let work = Promise.resolve();
  const later = (fn) => { work = work.then(fn).catch((e) => post({ type: 'error', error: String(e && e.message || e) })); return work; };
  const safe = (fn) => { try { return fn(); } catch (e) { return []; } };
  const post = (m) => { if (app && !app.closed) app.postMessage(Object.assign({ rl: VERSION }, m), appOrigin); };

  async function readCookies() {
    const list = parseCookieHeader(doc.cookie);
    if (win.cookieStore) try {
      const full = await win.cookieStore.getAll();
      for (const c of list) { const f = full.find((x) => x.name === c.name); if (f) Object.assign(c, { domain: f.domain, path: f.path || '/', secure: f.secure, sameSite: f.sameSite, expires: f.expires, hostOnly: !f.domain, attrsKnown: true }); }
    } catch (e) { /* cookieStore запрещён политикой */ }
    return list;
  }
  const entries = (st) => { const out = []; try { for (let i = 0; i < st.length && i < 300; i++) { const k = st.key(i); out.push([k, String(st.getItem(k) || '').slice(0, 2e4)]); } } catch (e) { /* storage закрыт */ } return out; };
  const res = (e) => ({ url: e.name, initiator: e.initiatorType, status: e.responseStatus || 0, duration: Math.round(e.duration || 0), size: e.transferSize || 0, t: Math.round((win.performance.timeOrigin || 0) + e.startTime) });
  // Фреймы своего origin: их HTML и скрипты. Чужие фреймы браузер не отдаёт, и это правильно
  const frames = () => Array.from(doc.querySelectorAll('iframe,frame'), (f) => { try { const d = f.contentDocument; return d && d.documentElement ? { url: d.location.href, html: d.documentElement.outerHTML.slice(0, 2e6), scripts: Array.from(d.querySelectorAll('script[src]'), (s) => s.src) } : null; } catch (e) { return null; } }).filter(Boolean).slice(0, 10);
  // E3: только чтение — регистрации service worker, push-подписка, имена кешей и баз IndexedDB.
  // caches.open не вызывается: он создаёт кеш, если его нет. Содержимое кешей и баз не читается
  const withTimeout = (p, ms) => Promise.race([p, sleep(ms).then(() => null)]);
  async function workers() {
    const out = { sw: [], caches: [], idb: [] };
    try {
      const regs = (await withTimeout(win.navigator.serviceWorker && win.navigator.serviceWorker.getRegistrations(), 2000)) || [];
      for (const r of regs.slice(0, 10)) {
        const w = r.active || r.waiting || r.installing; let push = null;
        try { const sub = await withTimeout(r.pushManager && r.pushManager.getSubscription(), 1000); if (sub) { const u = new URL(sub.endpoint); push = u.host + u.pathname.slice(0, 12) + '…'; } } catch (e) { /* push недоступен */ }
        out.sw.push({ scope: r.scope, script: w ? w.scriptURL : '', state: w ? w.state : '', push });
      }
    } catch (e) { /* нет service worker */ }
    try { out.caches = ((await withTimeout(win.caches && win.caches.keys(), 2000)) || []).slice(0, 100); } catch (e) { /* нет Cache Storage */ }
    try { out.idb = ((await withTimeout(win.indexedDB && win.indexedDB.databases && win.indexedDB.databases(), 2000)) || []).slice(0, 100).map((d) => ({ name: d.name, version: d.version })); } catch (e) { /* нет списка баз */ }
    return out;
  }
  async function snapshot() {
    const wk = await workers();
    const ng = doc.querySelector('[ng-version]');
    return {
      url: page, contentType: doc.contentType, html: doc.documentElement.outerHTML.slice(0, 5e6),
      scripts: Array.from(doc.querySelectorAll('script[src]'), (s) => s.src),
      links: Array.from(doc.querySelectorAll('link[rel~=modulepreload],link[rel~=preload][as=script],link[rel~=manifest]'), (l) => ({ href: l.href, rel: l.rel })),
      resources: win.performance.getEntriesByType('resource').filter((e) => !OWN.has(e.name) && !OWN_HOSTS.test(e.name)).map(res),
      globals: techFromRuntime(win), devGlobals: devtoolsFromRuntime(win), ngVersion: ng ? ng.getAttribute('ng-version') : null,
      storage: { local: safe(() => entries(win.localStorage)), session: safe(() => entries(win.sessionStorage)) }, // хранилище может быть запрещено браузером
      cookies: await readCookies(), cookieStore: !!win.cookieStore, frames: frames(),
      consent: { onetrust: typeof win.OneTrust, cookiebot: typeof win.Cookiebot, tcf: typeof win.__tcfapi, didomi: typeof win.Didomi, uc: typeof win.UC_UI },
      sw: wk.sw, caches: wk.caches, idb: wk.idb,
      anchors: Array.from(doc.querySelectorAll('a[href]'), (a) => a.getAttribute('href')).filter(Boolean).slice(0, 2000)
    };
  }

  async function get(url, force, docOnly) {
    const scope = makeScope({ pageUrl: page, allowHosts: policy.allowHosts }), host = new URL(url, page).host;
    // Документ страницы — один GET за заголовками, только для HTML и не для путей вроде /logout
    const chk = docOnly ? (url === page && doc.contentType === 'text/html' && !deniedPath(win.location.pathname + win.location.search) ? { ok: true } : { ok: false, reason: 'not-doc' }) : scope.check(url, force);
    if (!chk.ok) return { ok: false, error: chk.reason };
    if (stopped.has(host)) return { ok: false, error: 'blocked' };
    if (used >= policy.budget) return { ok: false, error: 'budget' };
    if (bytes > MAX_BYTES || (started && Date.now() - started > MAX_TIME)) return { ok: false, error: 'limit' };
    started = started || Date.now();
    const wait = policy.delay * (0.7 + Math.random() * 0.6) - (Date.now() - last);
    if (used) await sleep(Math.max(wait, policy.delay * 0.7));
    used++; OWN.add(url);
    try {
      const sameOrigin = new URL(url).origin === win.location.origin;
      const r = await win.fetch(url, { credentials: policy.cookies && sameOrigin ? 'include' : 'omit', redirect: 'error', signal: win.AbortSignal && win.AbortSignal.timeout ? win.AbortSignal.timeout(15000) : undefined });
      const headers = {}; r.headers.forEach((v, k) => { headers[k] = v; });
      // Ответ, который превысит общий предел, не читается целиком
      const len = +r.headers.get('content-length') || 0;
      if (len && bytes + len > MAX_BYTES) { last = Date.now(); return { ok: false, status: r.status, error: 'too-large' }; }
      // Читаем частями: без Content-Length (сжатый ответ частями) r.text() затянул бы в память весь файл до проверки предела
      let text = '', got = 0;
      if (r.body && r.body.getReader) {
        const rd = r.body.getReader(), dec = new (win.TextDecoder || TextDecoder)();
        for (;;) { const { value, done } = await rd.read(); if (done) break; got += value.byteLength; text += dec.decode(value, { stream: true }); if (bytes + got > MAX_BYTES) /* настоящие байты, как в Content-Length */ { rd.cancel().catch(() => {}); last = Date.now(); return { ok: false, status: r.status, error: 'too-large' }; } }
        text += dec.decode();
      } else { text = await r.text(); got = text.length; }
      bytes += got; last = Date.now(); // пауза считается от конца прошлого ответа
      const out = { ok: r.ok, status: r.status, headers, text };
      const why = blockedReason(out);
      if (why) { stopped.add(host); return { ok: false, status: r.status, headers, blocked: why, text: '' }; }
      return out;
    } catch (e) { return { ok: false, status: 0, error: String(e && e.message || e) }; }
  }
  function pump() {
    return later(async () => {
      while (queue.length) { const q = queue.shift(); const r = await get(q.url, q.force, q.doc); post(Object.assign({ type: 'fetched', id: q.id }, r)); }
    });
  }

  // Живой трафик и изменения cookies, пока вкладка открыта
  function watch() {
    let po = null, iv = null;
    if (win.PerformanceObserver) try {
      po = new win.PerformanceObserver((l) => { const e = l.getEntries().filter((x) => !OWN.has(x.name) && !OWN_HOSTS.test(x.name) && /fetch|xmlhttprequest|beacon/.test(x.initiatorType)).map(res); if (e.length) post({ type: 'traffic', entries: e }); });
      po.observe({ type: 'resource' });
    } catch (e) { /* нет PerformanceObserver */ }
    lastCookie = doc.cookie;
    // Вкладку закрыли: наблюдатель и таймер на странице сайта больше не нужны
    iv = win.setInterval && win.setInterval(async () => { if (app && app.closed) { if (po && po.disconnect) po.disconnect(); if (win.clearInterval) win.clearInterval(iv); return; } if (connected && doc.cookie !== lastCookie) { lastCookie = doc.cookie; post({ type: 'cookies', cookies: await readCookies() }); } }, 2000);
  }



  // Удаляет cookie по очереди во всех возможных местах, пока её не станет видно, и возвращает место, где она была:
  // «Удалить» на этом и заканчивается, а запись кладёт новое значение туда же, сохраняя домен cookie
  function locate(c) {
    const has = () => parseCookieHeader(doc.cookie).some((x) => x.name === c.name);
    let found = { hostOnly: true };
    if (!has()) return found;
    for (const v of cookieVariants(win.location.host, siteOf(win.location.host))) {
      doc.cookie = deleteString(Object.assign({}, c, v));
      if (!has()) { found = v; break; }
    }
    return found;
  }
  const handlers = {
    hello: () => { connected = true; return later(async () => post({ type: 'snapshot', version: VERSION, page: await snapshot() })); },
    settings: (m) => { policy = clampSettings(m); used = 0; bytes = 0; started = 0; stopped.clear(); },
    fetch: (m) => { queue.push({ id: m.id, url: String(m.url), force: !!m.force, doc: !!m.doc }); return pump(); },
    // ok — только если браузер действительно принял запись: он может молча отказать
    // Запись и удаление: если домен cookie неизвестен, сначала находим, где она лежит, чтобы не создать вторую с тем же именем
    'cookie-set': (m) => later(async () => {
      // Недопустимое значение проверяется до locate(): иначе оригинал удалится, а новая запись не пройдёт
      if (badCookieValue(m.cookie.value) || badCookieValue(m.cookie.name)) return post({ type: 'cookie-result', id: m.id, ok: false, cookies: await readCookies() });
      const c = Object.assign({}, m.cookie, m.cookie.attrsKnown ? {} : locate(m.cookie));
      doc.cookie = writeString(c);
      const cookies = await readCookies(), same = cookies.filter((x) => x.name === c.name);
      post({ type: 'cookie-result', id: m.id, ok: same.length === 1 && same[0].value === String(c.value), duplicate: same.length > 1, cookies });
    }),
    'cookie-delete': (m) => later(async () => { if (m.cookie.attrsKnown) doc.cookie = deleteString(m.cookie); else locate(m.cookie); const cookies = await readCookies(); post({ type: 'cookie-result', id: m.id, ok: !cookies.some((c) => c.name === m.cookie.name), cookies }); }),
    'cookie-read': (m) => later(async () => post({ type: 'cookie-result', id: m.id, ok: true, cookies: await readCookies() })),
    stop: () => { queue = []; },
    bye: () => { queue = []; connected = false; }
  };
  function handle(e) {
    if (e.origin !== appOrigin || (app && e.source !== app) || !e.data || e.data.rl !== VERSION) return;
    const h = handlers[e.data.type]; if (h) h(e.data);
  }

  return {
    start() { listen(handle); watch(); },
    idle: () => work
  };
}
