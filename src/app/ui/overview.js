// Overview: target, what was done, what changed since the last run, what to check first.
import { h, plural, dot, LV, button, copyIcon } from './dom.js';
import { row, KINDS } from './findings.js';
import { isShown } from '../visible.js';
import { t, PL } from '../../i18n.js';

const tabOf = (f) => Object.keys(KINDS).find((t) => KINDS[t].includes(f.kind)) || (f.kind === 'cookie' ? 'cookies' : f.kind === 'config' ? 'headers' : 'overview');

// Short collector codes -> readable text
const LEVELS = ['critical', 'high', 'medium', 'low', 'info'], LEVELS_BY_RISK = ['info', 'low', 'medium', 'high', 'critical'];
const NAMES = { api: 'API', debug: 'Admin and docs', secret: 'Secrets', pii: 'Personal data', privacy: 'Privacy', cloud: 'Cloud', tech: 'Stack', code: 'Code', html: 'HTML', page: 'Pages', external: 'External', cookies: 'Cookies', headers: 'Headers' };
// Findings per section and the highest risk in each
function sections(store, app) {
  const out = {};
  for (const f of store.items) { const k = tabOf(f); if (k === 'overview' || !isShown(f, app)) continue; const x = out[k] || (out[k] = { id: k, name: NAMES[k] || k, n: 0, risk: 0 }); x.n++; x.risk = Math.max(x.risk, f.risk || 0); }
  // Numbers as in the menu: cookies - all visible cookies
  if (out.cookies) out.cookies.n = app.cookies.length;
  return Object.values(out).sort((a, b) => b.risk - a.risk || b.n - a.n);
}
const ERR = { budget: 'request budget used up', limit: 'size or time limit reached', blocked: 'host stopped' };

export function renderOverview(ctx) {
  const { app, store, actions } = ctx, c = store.counts(), page = h('div', { class: 'page ov' });
  const open = (f) => () => { actions.setTab(tabOf(f)); actions.select(f.id); };
  const facts = [plural(store.files.length, PL.file), plural(c.total, PL.finding)];
  if (app.offline) facts.push(t('offline analysis, no network'));
  page.append(h('div', { class: 'ovhead' }, h('h1', { text: app.settings.demo ? t('Site') : (store.pageHost || t('File')) }), h('span', { class: 'muted', text: facts.join(', ') })));
  // Level tiles: big number, level color as a top stripe; empty levels are muted
  page.append(h('div', { class: 'tiles' }, LEVELS.map((l) => h('div', { class: 'tile ' + l + (c.levels[l] ? '' : ' zero') }, h('b', { text: c.levels[l] || 0 }), h('span', {}, dot(l), ' ' + t(LV[l]))))));

  store.blocked.forEach((b) => page.append(h('p', { class: 'note', text: t('Scan of {host} stopped: {reason}. Routelark does not bypass protection', { host: b.host, reason: t(b.reason) }) })));
  if (store.errors.length) page.append(h('div', { class: 'note' }, h('strong', { text: t('Files failed to load: {n}', { n: store.errors.length }) }),
    h('ul', { class: 'errs' }, store.errors.slice(0, 8).map((e) => h('li', {}, h('span', { class: 'mono', text: String(e.url).replace(/^https?:\/\/[^/]+/, '') }), ' — ' + (t(ERR[e.error] || e.error || '') || 'HTTP ' + e.status)))),
    store.errors.length > 8 ? h('p', { class: 'muted', text: t('and {n} more', { n: store.errors.length - 8 }) }) : null));

  const left = h('div', {}), right = h('aside', {});
  page.append(h('div', { class: 'ovcols' }, left, right));
  const out = left; // left: "Check first" and changes since the last run; right: sections and packages
  const pri = store.list().filter((f) => f.priority && isShown(f, app));
  out.append(h('h2', { text: t('Check first') }));
  if (!pri.length) out.append(h('p', { class: 'muted', text: app.running ? t('Scan in progress') : t('No priority findings') }));
  else { const l = h('div', { class: 'rows' }); pri.slice(0, 40).forEach((f) => l.append(row(f, app, open(f)))); out.append(l); }

  // The block appears only when something changed since the last run
  if (app.diff && (app.diff.added.length || app.diff.removed.length)) {
    const { added, removed } = app.diff;
    out.append(h('h2', { text: t('Since the last run') }));
    if (added.length) { out.append(h('h3', { text: t('Added: {n}', { n: added.length }) })); const l = h('div', { class: 'rows' }); added.slice(0, 30).forEach((f) => l.append(row(f, app, open(f)))); out.append(l); }
    if (removed.length) out.append(h('h3', { text: t('Removed: {n}', { n: removed.length }) }), h('ul', { class: 'mono muted' }, removed.slice(0, 30).map((id) => h('li', { text: app.prevLabels[id] || id }))));
  }
  // JS files changed since the last run: new findings in them are what the deploy brought
  const fd = app.fileDiff;
  if (fd && (fd.added.length || fd.changed.length || fd.removed.length)) {
    out.append(h('h3', { text: t('Files: {changed} changed, {added} new, {removed} gone', { changed: fd.changed.length, added: fd.added.length, removed: fd.removed.length }) }));
    const l = h('ul', { class: 'mono' });
    fd.changed.concat(fd.added).slice(0, 30).forEach((url) => {
      const fresh = app.diff ? app.diff.added.filter((f) => f.sources.some((s) => s.file === url)).length : 0;
      l.append(h('li', {}, h('button', { class: 'link', type: 'button', onclick: () => actions.openFile(url, 0) }, url.replace(/^https?:\/\/[^/]+/, '')), ' ' + (fd.added.includes(url) ? t('new') : t('changed')) + (fresh ? ', ' + t('new findings: {n}', { n: fresh }) : '')));
    });
    out.append(l);
  }

  // Sections sorted by their most dangerous level: where to go next
  const secs = sections(store, app);
  if (secs.length) right.append(h('h2', { text: t('Sections') }), h('div', { class: 'rows' }, secs.map((x) => h('button', { class: 'row secrow', type: 'button', onclick: () => actions.setTab(x.id) },
    h('span', { class: 'l1' }, dot(LEVELS_BY_RISK[x.risk]), h('span', { class: 'grow', text: t(x.name) }), h('span', { class: 'num', text: x.n }))))));
  // Links for manual recon. Opened only on user click; Routelark does not request them
  const host = store.pageHost || '';
  if (/^[a-z0-9.-]+$/i.test(host) && !/^\d+\.\d+\.\d+\.\d+$|^localhost$/.test(host)) {
    const q = encodeURIComponent(host), link = (href, text) => h('li', {}, h('a', { href, target: '_blank', rel: 'noopener noreferrer', text: t(text) }));
    const fav = app.favicon || {};
    right.append(h('h2', { text: t('Links') }), h('ul', {},
      link('https://crt.sh/?q=%25.' + q, 'Certificates (crt.sh)'),
      link('https://www.google.com/search?q=site%3A' + q + '+ext%3Aenv+OR+ext%3Asql+OR+ext%3Alog', 'Google: exposed files'),
      link('https://github.com/search?q=%22' + q + '%22&type=code', 'GitHub code search'),
      link('https://web.archive.org/web/*/' + q + '/*', 'Wayback Machine archive'),
      link(store.pageOrigin + '/.well-known/change-password', 'Change-password page')),
      h('div', { class: 'bar' }, button(t('Favicon hash'), () => actions.faviconHash(), null, t('Reads the favicon the page already uses (one request) and computes the Shodan hash')),
        fav.hash != null ? h('span', { class: 'mono' }, 'http.favicon.hash:' + fav.hash, ' ', copyIcon('http.favicon.hash:' + fav.hash)) : fav.error ? h('span', { class: 'muted', text: t('Could not read the favicon: {error}', { error: fav.error }) }) : null));
  }
  const scoped = Array.from(store.deps.values()).filter((d) => d.scoped);
  // Scoped package from site sources: if the scope is free on npm it can be claimed (dependency confusion)
  if (scoped.length) right.append(h('h2', { text: t('Private npm packages in the source code') }),
    h('p', { class: 'muted small', text: t('The source maps show packages with an npm scope (@name/…). If nobody owns that scope on public npm, anyone can register it and publish a package with the same name (dependency confusion). "Not found" on npm means the scope may be free') }),
    h('ul', { class: 'mono' }, scoped.map((d) => h('li', {}, h('a', { href: 'https://www.npmjs.com/package/' + d.name, target: '_blank', rel: 'noopener noreferrer', text: d.name })))));
  return page;
}
