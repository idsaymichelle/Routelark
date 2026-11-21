// Collector: runs on the page from the bookmarklet. Gathers data, fetches service files on tab request
// and checks every request itself. Does not modify the page: no styles, DOM or API patches.
import { makeScope, blockedReason, clampSettings, deniedPath, siteOf } from './core/scope.js';
import { writeString, deleteString, parseCookieHeader, cookieVariants, badCookieValue } from './core/cookies.js';
import { techFromRuntime } from './core/tech.js';
import { devtoolsFromRuntime } from './core/devbuild.js';

// Redirects are not followed (redirect: 'error'): otherwise an allowed file could bounce the request to /logout, an API or a foreign host
const VERSION = 2, MAX_BYTES = 25e6, MAX_TIME = 3e5;
// Routelark's own requests (OSV, npm) go from the page window: keep them out of its resources and traffic
const OWN_HOSTS = /^https:\/\/(?:api\.osv\.dev|registry\.npmjs\.org)\//;

// Direct channel between the collector and the tab UI. Both run in the page window, so browser postMessage
// could not tell the sender. Delivery is asynchronous. Site scripts run in the same window and can
// reach the tab: a limit of the all-in-bookmarklet design, see SECURITY.md
export function channel(win, tab) {
  const toTab = [], toPage = [], origin = win.location.origin;
  // Page went away (reload, navigation): the tab learns of it and says "page closed" instead of waiting for a reply
  let gone = false;
  if (win.addEventListener) win.addEventListener('pagehide', () => { gone = true; });
  const timer = tab.setTimeout ? tab : win; // tab timers survive even after the page is unloaded
  const deliver = (list, data, source) => timer.setTimeout(() => list.forEach((fn) => fn({ data, origin, source })), 0);
  const tabEnd = { get closed() { return !!tab.closed; }, postMessage: (data) => deliver(toTab, data, pageEnd) };
  const pageEnd = { get closed() { return gone; }, postMessage: (data) => { if (!gone) deliver(toPage, data, tabEnd); } };
  return { port: { opener: pageEnd, listen: (fn) => toTab.push(fn) }, collector: { win, tab: tabEnd, listen: (fn) => toPage.push(fn) } };
}

// tab: the Routelark tab opened by the bookmarklet (same-origin about:blank as the page)
// listen: channel for tab messages (window message by default)
export function createCollector({ win, tab, listen = (fn) => win.addEventListener('message', fn), sleep = (ms) => new Promise((r) => win.setTimeout(r, ms)) }) {
  const doc = win.document, appOrigin = win.location.origin, page = win.location.href, app = tab;
  let policy = clampSettings({}), queue = [], used = 0, bytes = 0, started = 0, last = 0, connected = false, lastCookie = null;
  const stopped = new Set();
  // Own requests are remembered in the page window between bookmarklet clicks: the browser resource buffer outlives one run
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
    } catch (e) { /* cookieStore blocked by policy */ }
    return list;
  }
  const entries = (st) => { const out = []; try { for (let i = 0; i < st.length && i < 300; i++) { const k = st.key(i); out.push([k, String(st.getItem(k) || '').slice(0, 2e4)]); } } catch (e) { /* storage closed */ } return out; };
  const res = (e) => ({ url: e.name, initiator: e.initiatorType, status: e.responseStatus || 0, duration: Math.round(e.duration || 0), size: e.transferSize || 0, t: Math.round((win.performance.timeOrigin || 0) + e.startTime) });
  // Same-origin frames: their HTML and scripts. The browser does not expose foreign frames, and that is right
  const frames = () => Array.from(doc.querySelectorAll('iframe,frame'), (f) => { try { const d = f.contentDocument; return d && d.documentElement ? { url: d.location.href, html: d.documentElement.outerHTML.slice(0, 2e6), scripts: Array.from(d.querySelectorAll('script[src]'), (s) => s.src) } : null; } catch (e) { return null; } }).filter(Boolean).slice(0, 10);
  // Read-only: service worker registrations, push subscription, cache and IndexedDB names.
  // caches.open is not called: it creates the cache if missing. Cache and database contents are not read
  const withTimeout = (p, ms) => Promise.race([p, sleep(ms).then(() => null)]);
  async function workers() {
    const out = { sw: [], caches: [], idb: [] };
    try {
      const regs = (await withTimeout(win.navigator.serviceWorker && win.navigator.serviceWorker.getRegistrations(), 2000)) || [];
      for (const r of regs.slice(0, 10)) {
        const w = r.active || r.waiting || r.installing; let push = null;
        try { const sub = await withTimeout(r.pushManager && r.pushManager.getSubscription(), 1000); if (sub) { const u = new URL(sub.endpoint); push = u.host + u.pathname.slice(0, 12) + '…'; } } catch (e) { /* push unavailable */ }
        out.sw.push({ scope: r.scope, script: w ? w.scriptURL : '', state: w ? w.state : '', push });
      }
    } catch (e) { /* no service worker */ }
    try { out.caches = ((await withTimeout(win.caches && win.caches.keys(), 2000)) || []).slice(0, 100); } catch (e) { /* no Cache Storage */ }
    try { out.idb = ((await withTimeout(win.indexedDB && win.indexedDB.databases && win.indexedDB.databases(), 2000)) || []).slice(0, 100).map((d) => ({ name: d.name, version: d.version })); } catch (e) { /* no database list */ }
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
      storage: { local: safe(() => entries(win.localStorage)), session: safe(() => entries(win.sessionStorage)) }, // storage may be blocked by the browser
      cookies: await readCookies(), cookieStore: !!win.cookieStore, frames: frames(),
      consent: { onetrust: typeof win.OneTrust, cookiebot: typeof win.Cookiebot, tcf: typeof win.__tcfapi, didomi: typeof win.Didomi, uc: typeof win.UC_UI },
      sw: wk.sw, caches: wk.caches, idb: wk.idb,
      anchors: Array.from(doc.querySelectorAll('a[href]'), (a) => a.getAttribute('href')).filter(Boolean).slice(0, 2000)
    };
  }

  async function get(url, force, docOnly) {
    const scope = makeScope({ pageUrl: page, allowHosts: policy.allowHosts }), host = new URL(url, page).host;
    // Page document: one GET for headers, HTML only and not for paths like /logout
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
      // A response that would exceed the total limit is not read in full
      const len = +r.headers.get('content-length') || 0;
      if (len && bytes + len > MAX_BYTES) { last = Date.now(); return { ok: false, status: r.status, error: 'too-large' }; }
      // Read in chunks: without Content-Length (compressed, chunked) r.text() would pull the whole file into memory before the limit check
      let text = '', got = 0;
      if (r.body && r.body.getReader) {
        const rd = r.body.getReader(), dec = new (win.TextDecoder || TextDecoder)();
        for (;;) { const { value, done } = await rd.read(); if (done) break; got += value.byteLength; text += dec.decode(value, { stream: true }); if (bytes + got > MAX_BYTES) /* real bytes, as in Content-Length */ { rd.cancel().catch(() => {}); last = Date.now(); return { ok: false, status: r.status, error: 'too-large' }; } }
        text += dec.decode();
      } else { text = await r.text(); got = text.length; }
      bytes += got; last = Date.now(); // pause counts from the end of the previous response
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

  // Live traffic and cookie changes while the tab is open
  function watch() {
    let po = null, iv = null;
    if (win.PerformanceObserver) try {
      po = new win.PerformanceObserver((l) => { const e = l.getEntries().filter((x) => !OWN.has(x.name) && !OWN_HOSTS.test(x.name) && /fetch|xmlhttprequest|beacon/.test(x.initiatorType)).map(res); if (e.length) post({ type: 'traffic', entries: e }); });
      po.observe({ type: 'resource' });
    } catch (e) { /* no PerformanceObserver */ }
    lastCookie = doc.cookie;
    // Tab closed: the observer and timer on the site page are no longer needed
    iv = win.setInterval && win.setInterval(async () => { if (app && app.closed) { if (po && po.disconnect) po.disconnect(); if (win.clearInterval) win.clearInterval(iv); return; } if (connected && doc.cookie !== lastCookie) { lastCookie = doc.cookie; post({ type: 'cookies', cookies: await readCookies() }); } }, 2000);
  }



  // Deletes the cookie one by one in all possible places until it is no longer visible, and returns where it was:
  // "delete" ends there, while a write puts the new value in the same place, keeping the cookie domain
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
    // ok only if the browser really accepted the write: it may silently refuse
    // Write and delete: if the cookie domain is unknown, first find where it lives so as not to create a second one with the same name
    'cookie-set': (m) => later(async () => {
      // An invalid value is checked before locate(): otherwise the original would be deleted and the new write would fail
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
