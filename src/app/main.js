// Routelark tab. Opened by the bookmarklet: shows page results; opened directly: install and offline analysis.
import { Store, osvQuery } from '../core.js';
import { connect } from './link.js';
import { runScan, addTraffic, addCookies } from './scan.js';
import { h, iconButton, plural, langButton } from './ui/dom.js';
import { t, setLang, getLang, PL } from '../i18n.js';
import { renderFindings, KINDS } from './ui/findings.js';
import { renderOverview } from './ui/overview.js';
import { renderCompliance } from './ui/compliance.js';
import { renderMap } from './ui/map.js';
import { complianceRows } from '../core/compliance.js';
import { faviconHash } from '../core/favicon.js';
import { makeScope } from '../core/scope.js';
import { isShown } from './visible.js';
import { renderCookies } from './ui/cookies.js';
import { renderStorage } from './ui/storage.js';
import { renderHeaders } from './ui/headers.js';
import { renderReport } from './ui/report.js';
import { renderSettings, loadSettings, saveSettings } from './ui/settings.js';
import { renderHome } from './ui/home.js';
import { renderFiles, fileCount } from './ui/files.js';
import { modeCache, settingsFor, scanChanged } from './modes.js';

// Tab storage (in-memory in the bookmarklet): settings and last scan while the tab is open
const local = {
  get: (k) => { try { return JSON.parse(localStorage.getItem(k)); } catch (e) { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* storage unavailable */ } }
};

const app = {
  link: null, page: null, store: null, settings: loadSettings(local), running: false, stopped: false,
  tab: 'overview', sel: null, q: '', level: '', reveal: true, diff: null, prevLabels: {}, traffic: [], cookies: [], offline: false, local,
  showHidden: false,
  // Every launch starts in quiet mode: no own requests to the site, OSV or npm. Full scan only by choice
  mode: 'quiet',
  // Each mode's result is kept while the tab is open: switching shows it instead of rescanning
  modes: modeCache(), runMode: null
};
document.documentElement.dataset.theme = app.settings.theme;
// Language: one place that updates i18n state, the lang attribute and the saved setting
function applyLang(l) { setLang(l); app.settings.lang = getLang(); document.documentElement.lang = getLang(); }
applyLang(app.settings.lang);

// 10 s timeout; AbortSignal.timeout needs Safari 16, without it the request has no timeout
const tmo = () => (typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined);
async function osv(name, version) {
  const q = osvQuery(name, version); if (!q) return [];
  const r = await fetch(q.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(q.body), referrerPolicy: 'no-referrer', signal: tmo() }); // no Referer; the browser sends Origin itself
  return r.ok ? ((await r.json()).vulns || []) : [];
}

// Status code only: 404 means the name is not on npm
const npm = (name) => fetch('https://registry.npmjs.org/' + name.replace('/', '%2F'), { method: 'HEAD', referrerPolicy: 'no-referrer', signal: tmo() }).then((r) => r.status);

const actions = {
  render: () => schedule(),
  setTab: (t) => { app.tab = t; app.sel = null; try { history.replaceState(null, '', '#' + t); } catch (e) { /* cannot change the URL */ } if (app.cookieUi) app.cookieUi.draft = null; render(); },
  select: (id) => { app.sel = id; render(); },
  // Open a file at a line: "Where found" lines are counted on the source text, so no formatting
  setProgram: (p) => { app.program = p; actions.render(); },
  setShowHidden: (v) => { app.showHidden = v; actions.render(); },
  // Favicon hash: one GET of the icon the page declares (or /favicon.ico), no retries
  faviconHash: async () => {
    const html = app.page ? app.page.html : '', m = /<link\b[^>]*rel=["'][^"']*\bicon\b[^"']*["'][^>]*href=["']([^"']+)["']|<link\b[^>]*href=["']([^"']+)["'][^>]*rel=["'][^"']*\bicon\b/i.exec(html);
    try {
      const url = new URL(m ? m[1] || m[2] : '/favicon.ico', app.store.pageUrl).href;
      // Same scope rules as other requests: a foreign host is not fetched
      const chk = makeScope({ pageUrl: app.store.pageUrl, allowHosts: app.settings.allowHosts || [] }).check(url, true);
      if (!chk.ok && chk.reason !== 'not-js') throw new Error('out of scope: ' + new URL(url).host);
      const r = await fetch(url, { credentials: 'same-origin', redirect: 'error', signal: tmo() });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      app.favicon = { hash: faviconHash(new Uint8Array(await r.arrayBuffer())), url };
    } catch (e) { app.favicon = { error: String(e && e.message || e) }; }
    actions.render();
  },
  openFile: (url, line, col) => { app.fx = Object.assign(app.fx || {}, { sel: url, line: line || 0, col: col || 0, len: 0, raw: false, start: null, jump: true, results: null, err: null }); actions.setTab('files'); },
  rescan: () => { drop(app.mode); scan(); },
  // Switching does not stop a running scan: it finishes in the background, the screen shows the selected mode
  setMode: (m) => { if (m === app.mode) return; app.mode = m; showMode(); },
  stop: () => { if (!app.runMode) return; app.stopped = true; if (app.link) app.link.stop(); },
  saveSettings: (s) => {
    // Scan settings changed: saved results were built with the old ones, so the mode rescans on next visit
    if (scanChanged(s, app.settings)) drop();
    app.settings = s; applyLang(s.lang); persist(); document.documentElement.dataset.theme = s.theme; render(); },
  setLang: (l) => { applyLang(l); persist(); render(); },
  addScope: (host) => { app.settings.allowHosts = Array.from(new Set(app.settings.allowHosts.concat(host))); persist(); drop(); scan(); }, // a new scope host changes the results of both modes
  // Offline: a file analysis result is shown like a normal scan
  showStore: (store, page, cookies) => { app.store = store; app.page = page || null; app.cookies = cookies || []; app.offline = true; app.tab = 'overview'; bind(store); render(); }
};

// Scope hosts are stored per site: one target's list does not leak to another page
const scopeKey = () => (app.page ? 'rl:scope:' + new URL(app.page.url).origin : null);
function persist() { saveSettings(local, Object.assign({}, app.settings, { allowHosts: [] })); if (scopeKey()) local.set(scopeKey(), app.settings.allowHosts); }
function bind(store) { store.on(schedule); }
// Compare-with-previous history is per mode: a quiet scan cannot be compared with a full one
const modeHistory = (mode) => ({ get: (k) => local.get(k + '|' + mode), set: (k, v) => local.set(k + '|' + mode, v) });
// Drop saved results of a mode (or both). A running scan of a dropped mode is stale: stop it, the mode reruns later
function drop(mode) { if (app.modes.drop(mode).includes(app.runMode)) { app.again = true; actions.stop(); } }
function placeholder() { app.store = new Store(app.page.url); app.store.status = 'waiting for the other scan to finish'; app.diff = null; app.fileDiff = null; app.sel = null; }
// app.running: a scan of the shown mode is running (Stop / "Scan running" button); app.runMode: mode of the running scan
const sync = () => { app.running = !!app.runMode && app.runMode === app.mode; };
// All finding sets of the tab: page traffic and cookies are appended to saved results too
const stores = () => Array.from(new Set([app.store].concat(app.modes.stores()).filter(Boolean)));
function showMode() {
  const c = app.modes.get(app.mode);
  if (c) Object.assign(app, { store: c.store, diff: c.diff, prevLabels: c.prevLabels, fileDiff: c.fileDiff });
  else if (app.runMode) { app.again = true; placeholder(); }
  else return scan();
  app.sel = null; sync(); render();
}
async function scan() {
  if (!app.link || !app.page) return;
  // One scan at a time: same mode - stop and restart, other mode - wait for the end
  if (app.runMode) { app.again = true; if (app.runMode === app.mode) actions.stop(); else if (!app.modes.get(app.mode)) { placeholder(); render(); } return; }
  const mode = app.mode, store = new Store(app.page.url);
  let entry = { store, diff: null, prevLabels: {}, fileDiff: null }, ok = true;
  const token = app.modes.start(mode, entry);
  app.runMode = mode; app.stopped = false; app.diff = null; app.fileDiff = null;
  app.store = store; bind(store); sync();
  try {
    // Preparation is inside try too: a failure before start must not leave running = true (Rescan would stop working)
    const set = settingsFor(mode, app.settings);
    app.link.sendSettings({ delay: app.settings.delay, budget: app.settings.budget, depth: app.settings.depth, cookies: app.settings.cookies, allowHosts: app.settings.allowHosts });
    const page = Object.assign({}, app.page, { cookies: app.cookies, resources: app.page.resources.concat(app.traffic) });
    render();
    const r = await runScan({ store, snapshot: page, fetchText: app.link.fetchText, settings: set, isStopped: () => app.stopped, osv: set.osv ? osv : null, npm: set.npmCheck ? npm : null, history: modeHistory(mode) });
    entry = { store, diff: r.diff, prevLabels: r.prevLabels, fileDiff: r.fileDiff };
    if (app.store === store) Object.assign(app, { diff: r.diff, prevLabels: r.prevLabels, fileDiff: r.fileDiff });
  } catch (e) { store.status = 'error: ' + (e && e.message || e); ok = false; } // error is not saved: the mode retries on return
  app.modes.finish(mode, token, entry, ok);
  app.runMode = null; sync(); render();
  if (app.again) { app.again = false; showMode(); }
}

let timer = null;
// While the user types in a form (except search), background updates do not redraw: the text would be lost
function schedule() {
  if (timer) return;
  timer = setTimeout(() => { timer = null; const a = document.activeElement; if (a && /^(?:INPUT|TEXTAREA)$/.test(a.tagName) && !/^(?:search|checkbox)$/.test(a.type)) schedule(); else render(); }, 150);
}

const SECTIONS = [
  ['overview', 'Overview'], ['api', 'API'], ['debug', 'Admin and docs'], ['secret', 'Secrets'], ['pii', 'Personal data'], ['cloud', 'Cloud'], ['tech', 'Stack'], ['code', 'Code'], ['html', 'HTML'],
  ['cookies', 'Cookies'], ['privacy', 'Privacy'], ['storage', 'Storage'], ['headers', 'Headers'], ['page', 'Pages'], ['external', 'External'], ['params', 'Parameters'], ['files', 'Files'], ['map', 'Map'], ['report', 'Report'], ['compliance', 'Compliance']
];
function sectionCount(id, c) {
  if (KINDS[id]) return KINDS[id].reduce((n, k) => n + (c.shown[k] || 0), 0);
  if (id === 'params') return app.store.paramStats().length;
  if (id === 'files') return fileCount(app, app.store);
  if (id === 'cookies') return app.cookies.length;
  if (id === 'map') return null;
  if (id === 'compliance') return complianceRows(app.store, app).filter((r) => r.status === 'fail').length || null;
  if (id === 'storage') return app.page ? app.page.storage.local.length + app.page.storage.session.length : 0;
  if (id === 'headers') return c.kinds.config || null; // issue count, not header count; the section stays visible without headers (they can be pasted)
  return null;
}
// The live region is created once: a new node on every redraw would be re-announced by the screen reader
const liveStatus = h('span', { class: 'status', 'aria-live': 'polite' });
const statusEl = (text) => { if (liveStatus.textContent !== text) liveStatus.textContent = text; return liveStatus; };
function header() {
  const s = app.store, c = s.counts(), pr = s.progress, host = s.pageHost || t('file');
  const status = [t(s.status), plural(c.total, PL.finding), pr.total ? t('files {done}/{total}', pr) : ''].filter(Boolean).join(', ');
  return h('header', { class: 'top' },
    // Title and host share a baseline; clicking the title opens Overview without a page reload
    h('span', { class: 'id' }, h('button', { class: 'brand', type: 'button', onclick: () => actions.setTab('overview') }, 'Routelark'), h('span', { class: 'target', text: app.settings.demo ? '•••' : host })),
    statusEl(status),
    app.link && app.page ? h('div', { class: 'seg', role: 'group', 'aria-label': t('Scan mode'), title: t('Quiet: only what the page already loaded, no requests. Full: downloads JS, maps and service files by the settings') },
      [['quiet', 'Quiet'], ['full', 'Full scan']].map(([v, name]) => h('button', { type: 'button', 'aria-pressed': String(app.mode === v), onclick: () => actions.setMode(v) }, t(name)))) : null,
    langButton(actions),
    app.link && app.page ? (app.runMode ? iconButton('stop', t('Stop scan'), actions.stop) : iconButton('rescan', t('Rescan'), actions.rescan)) : null,
    iconButton('gear', t('Settings'), () => actions.setTab('settings'))
  );
}
function nav() {
  // Visible findings by kind are counted once per redraw, not per tab
  const c = app.store.counts(); c.shown = {};
  for (const f of app.store.items) if (isShown(f, app)) c.shown[f.kind] = (c.shown[f.kind] || 0) + 1;
  const n = h('nav', { class: 'tabs', 'aria-label': t('Sections') });
  for (const [id, label] of SECTIONS) {
    const cnt = sectionCount(id, c);
    if (cnt === 0 && app.tab !== id) continue;
    n.append(h('button', { class: 'tab', type: 'button', 'aria-label': t(label) + (cnt != null ? ', ' + cnt : ''), 'aria-current': app.tab === id ? 'page' : null, onclick: () => actions.setTab(id) }, t(label), cnt != null ? h('i', { text: cnt }) : null));
  }
  return n;
}
const root = document.getElementById('app');
// Background scan updates redraw the screen: column scroll is kept while the same screen is open
// The left list remembers scroll within a section, the right pane while the same item is open. Focus and caret in inputs are kept too
const scrollKey = (el, i) => app.tab + '|' + i + '|' + (el.classList.contains('list') ? (app.fx && app.fx.results ? 'r' : '') : app.sel + '|' + (app.fx ? [app.fx.sel, app.fx.start, app.fx.raw].join('|') : ''));
let scrolls = new Map();
const pathOf = (el) => { const p = []; while (el && el !== root) { p.unshift(Array.prototype.indexOf.call(el.parentNode.children, el)); el = el.parentNode; } return p; };
const byPath = (p) => p.reduce((el, i) => (el && el.children[i]) || null, root);
function render() {
  root.querySelectorAll('.col,.page').forEach((el, i) => scrolls.set(scrollKey(el, i), el.scrollTop));
  // Focus returns to the same element after redraw: by index path from the root (the tag must match)
  const a = document.activeElement, focus = a && a !== document.body && root.contains(a) ? { path: pathOf(a), tag: a.tagName, label: a.getAttribute('aria-label'), s: a.selectionStart, e: a.selectionEnd } : null;
  root.textContent = '';
  if (!app.store) { root.append(renderHome({ app, actions })); return; }
  const ctx = { app, store: app.store, actions }, main = h('main', { class: 'main' });
  const view = { files: renderFiles, overview: renderOverview, cookies: renderCookies, storage: renderStorage, headers: renderHeaders, report: renderReport, compliance: renderCompliance, map: renderMap, settings: renderSettings }[app.tab];
  main.append(view ? view(ctx) : renderFindings(ctx, app.tab));
  main.id = 'main';
  if (!main.querySelector('h1')) main.prepend(h('h1', { class: 'sr-only', text: t((SECTIONS.find((x) => x[0] === app.tab) || [0, 'Findings'])[1]) })); // one h1 per screen for the screen reader
  root.append(h('a', { class: 'skip', href: '#main', text: t('Skip to content') }), header(), nav(), main);
  root.querySelectorAll('.col,.page').forEach((el, i) => { const v = scrolls.get(scrollKey(el, i)); if (v) el.scrollTop = v; });
  if (focus) { let el = (focus.label && Array.from(root.querySelectorAll('input,textarea,select')).find((x) => x.getAttribute('aria-label') === focus.label)) || byPath(focus.path); if (el && el.tagName === focus.tag) { el.focus(); try { if (focus.s != null) el.setSelectionRange(focus.s, focus.e); } catch (e) { /* field without selection */ } } }
}

// Section in the URL: #api, #report. Reload and links open the same section
const fromHash = () => { const id = location.hash.slice(1); if (/^[a-z]+$/.test(id) && (id === 'settings' || SECTIONS.some((s) => s[0] === id))) app.tab = id; };
fromHash();
window.addEventListener('hashchange', () => { fromHash(); app.sel = null; render(); });
function start(link) {
  app.link = link;
  app.store = new Store(''); app.store.status = 'waiting for page data'; render();
  // Without a page reply the screen must not hang on "waiting" forever
  const fail = (why) => { if (app.store.status === 'waiting for page data') { app.store.status = why; render(); } };
  app.link.onError((e) => fail('page data unavailable: ' + e));
  setTimeout(() => fail('no response from the page: reload it and click the bookmarklet again'), 30000);
  app.link.onTraffic((entries) => { app.traffic.push(...entries); if (app.traffic.length > 2000) app.traffic.splice(0, app.traffic.length - 2000); /* cap: memory does not grow all session */  stores().forEach((s) => addTraffic(s, entries)); });
  app.link.onCookies((cookies) => { app.cookies = cookies; if (app.page) stores().forEach((s) => addCookies(s, cookies, /^https:/.test(app.page.url))); schedule(); });
  app.link.ready.then((page) => {
    // The demo sits at the same address as the tab: Routelark's own keys do not become findings
    page.storage.local = page.storage.local.filter(([k]) => !/^rl[:.]/.test(k));
    app.page = page; app.settings.allowHosts = local.get(scopeKey()) || []; app.cookies = page.cookies; document.title = 'Routelark — ' + new URL(page.url).host; scan(); });
}
const opened = connect({ win: window });
if (opened) start(opened);
else render(); // opened standalone (routelark.html file): home page
