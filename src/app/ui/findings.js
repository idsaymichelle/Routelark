// Разделы с находками: список слева, подробности справа.
import { mapping, TOP10_2025 } from '../../core/mapping.js';
import { isShown, hiddenReason } from '../visible.js';
import { h, button, route, copy, copyIcon, download, dot, kv, LV, CONF_LABEL } from './dom.js';
import { t, tLabel } from '../../i18n.js';
import { wordlist } from '../../core.js';

export const KINDS = { api: ['api', 'ws', 'auth', 'graphql', 'realtime'], debug: ['debug', 'docs'], secret: ['secret'], pii: ['pii'], privacy: ['privacy', 'tracker'], cloud: ['cloud', 'identity', 'ai', 'mobile', 'wellknown', 'infra'], tech: ['tech'], code: ['code', 'custom', 'storage', 'obfuscation', 'browser', 'web3'], html: ['dom'], page: ['page'], external: ['external'] };
const OWASP = { API1: 'Broken Object Level Authorization', API2: 'Broken Authentication', API3: 'Broken Object Property Level Authorization', API5: 'Broken Function Level Authorization', API7: 'Server Side Request Forgery', API8: 'Security Misconfiguration', API9: 'Improper Inventory Management' };
import { ROUTE_KINDS } from '../../core/scope.js';

const maskHost = (app, text) => (app.settings.demo && text ? String(text).replace(/\/\/[^/\s]+/g, '//•••') : text);
export function mainText(f, app) {
  if (f.kind === 'secret' || f.kind === 'pii') return t(f.url) + ': ' + (f.raw ? (app.reveal ? f.raw : f.secret) : t(f.why[0]));
  if (f.host && f.pageHost && f.host !== f.pageHost && f.resolved && f.kind !== 'cloud') return maskHost(app, f.resolved);
  return ROUTE_KINDS.has(f.kind) ? f.url : t(f.url);
}
// Поиск: обычный текст или регулярка в слешах со спецсимволами, например /^\/api\/v\d/. Путь вида /api/users/ остаётся текстом
// Длина проверяемой строки ограничена: тяжёлая регулярка не подвесит вкладку на длинном значении
function matcher(q) {
  const m = /^\/(.+)\/$/.exec(q);
  if (m && /[\\^$*+?()[\]|{}]/.test(m[1])) { try { const re = new RegExp(m[1], 'i'); return (s) => re.test(s.slice(0, 2000)); } catch (e) { /* недописанная регулярка — ищем как текст */ } }
  return (s) => s.toLowerCase().includes(q.toLowerCase());
}
function visible(app, list) {
  const test = app.q ? matcher(app.q) : null;
  return list.filter((f) => {
    if (!isShown(f, app)) return false;
    if (app.level === 'pri' && !f.priority) return false;
    if ((app.level === 'medium' && f.risk < 2) || (app.level === 'high' && f.risk < 3)) return false;
    return !test || [f.method, f.url, f.resolved, f.host, (f.params || []).join(' '), (f.why || []).concat((f.why || []).map((w) => t(w))).join(' '), (f.owasp || []).join(' ')].some((s) => s && test(String(s)));
  });
}
const srcOf = (f) => { const s = f.sources[0]; return s ? String(tLabel(s.file)).replace(/^.*\//, '').split('#').pop() + ':' + s.line : ''; };
// B7: новая или уже была в прошлом скане; Set строится один раз на сравнение, а не перебором на каждую строку
const ADDED = new WeakMap();
const isNewOf = (app, f) => { if (!app.diff) return false; if (!ADDED.has(app.diff)) ADDED.set(app.diff, new Set(app.diff.added)); return ADDED.get(app.diff).has(f); };
export function row(f, app, onclick, selected) {
  const isNew = isNewOf(app, f);
  return h('button', { class: 'row', type: 'button', 'aria-current': selected ? 'true' : null, onclick },
    h('span', { class: 'l1' }, dot(f.level),
      f.method && f.method !== '-' && f.method !== '?' ? h('span', { class: 'm', text: f.method }) : null,
      ROUTE_KINDS.has(f.kind) ? route(mainText(f, app)) : h('span', { class: 'route', text: mainText(f, app) }),
      isNew ? h('span', { class: 'new', text: t('new') }) : null,
      h('span', { class: 'lv' + (f.priority ? ' pr' : ''), text: t(LV[f.level]) })),
    h('span', { class: 'sub', text: [(f.why || [])[0] && t(f.why[0]), srcOf(f)].filter(Boolean).join(', ') }));
}
export function details(f, ctx) {
  const { app, actions } = ctx, d = h('section', { class: 'detail', 'aria-label': t('Details') });
  const value = f.kind === 'secret' || f.kind === 'pii' ? (app.reveal ? f.raw : f.secret) : f.resolved && f.kind !== 'tech' ? f.resolved : f.url;
  d.append(h('div', { class: 'titlebar' }, h('h2', {}, dot(f.level), ' ', f.method && f.method !== '-' && f.method !== '?' ? f.method + ' ' : '', ROUTE_KINDS.has(f.kind) ? route(mainText(f, app)) : mainText(f, app)), copyIcon(value)));
  const risky = (f.params || []).map((p) => p).join(', ');
  d.append(kv([
    [t('Address'), f.kind !== 'tech' ? maskHost(app, f.resolved) : null], [t('Level'), t(LV[f.level]) + (f.priority ? ', ' + t('check first') : '') + (f.publicKey ? ', ' + t('public by design') : '')], [t('Confidence'), t(CONF_LABEL[f.confidence])],
    [t('Parameters'), risky], [t('Authorization'), (f.auth || []).join(', ')], ['OWASP', (f.owasp || []).map((o) => o + (OWASP[o] ? ' — ' + t(OWASP[o]) : '')).join('; ')],
    ...((mp) => [['OWASP Top 10 2025', mp.top10.map((x) => x + ' — ' + t(TOP10_2025[x])).concat(mp.llm).join('; ')], ['ASVS / WSTG', mp.asvs.concat(mp.wstg).join(', ')], ['CWE', mp.cwe.join(', ')]])(mapping(f)),
    [t('In traffic'), f.observed ? t('the page called this address') : null],
    [t('Previous scan'), app.diff ? (isNewOf(app, f) ? t('new in this scan') : t('seen before')) : null]
  ]));
  if ((f.why || []).length) d.append(h('h3', { text: t('Why') }), h('ul', {}, f.why.map((w) => h('li', { text: t(w) }))));
  if (f.kind === 'tech') {
    if ((f.advisories || []).length) d.append(h('h3', { text: t('Vulnerabilities') }), h('ul', {}, f.advisories.map((a) => h('li', {}, h('a', { href: 'https://osv.dev/vulnerability/' + encodeURIComponent(a.id), target: '_blank', rel: 'noopener noreferrer', text: a.id }), ' ' + t(a.summary) + (a.fixed ? ', ' + t('fixed in {version}', { version: a.fixed }) : '')))));
    if (/^https:\/\/osv\.dev\//.test(f.resolved || '')) d.append(h('p', {}, h('a', { href: f.resolved, target: '_blank', rel: 'noopener noreferrer', text: t('All package vulnerabilities on osv.dev') })));
  }
  const snip = app.reveal && f.snippetRaw ? f.snippetRaw : f.snippet;
  if (snip) d.append(h('h3', { text: t('Snippet') }), h('div', { class: 'copybox' }, h('pre', { text: snip }), copyIcon(snip)));
  // Файл, текст которого сохранён, открывается в «Файлах» на нужной строке
  if (f.sources.length) d.append(h('h3', { text: t('Where found') }), h('ul', { class: 'mono' }, f.sources.slice(0, 10).map((s) => {
    const label = maskHost(app, tLabel(s.file)) + ':' + s.line + ':' + s.col + (s.via ? ' (' + s.via + ')' : '');
    return h('li', {}, ctx.store.texts && ctx.store.texts.has(s.file) ? h('button', { class: 'link', type: 'button', title: t('Open in Files'), onclick: () => actions.openFile(s.file, s.line, s.col) }, label) : label);
  })));
  // Как у значков копирования: на секунду подпись меняется на «Copied»
  const cp = button(t('Copy'), () => { copy(value); cp.textContent = t('Copied'); setTimeout(() => { cp.textContent = t('Copy'); }, 1200); });
  const acts = h('div', { class: 'acts' }, cp);
  if (f.kind === 'external' && f.host && app.link) acts.append(button(t('Add {host} to scope and rescan', { host: f.host }), () => actions.addScope(f.host), 'pri'));
  d.append(acts);
  return d;
}
function toolbar(ctx, total, shown, hidden) {
  const { app, actions } = ctx;
  const sh = hidden || app.showHidden ? h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: !!app.showHidden, onchange: (e) => actions.setShowHidden(e.target.checked) }), t('Show hidden') + (hidden ? ' (' + hidden + ')' : '')) : null;
  const q = h('input', { class: 'in', type: 'search', placeholder: t('Search or /regex/'), 'aria-label': t('Search'), value: app.q, oninput: (e) => { app.q = e.target.value; actions.render(); } });
  const lv = h('select', { class: 'in', 'aria-label': t('Level'), onchange: (e) => { app.level = e.target.value; actions.render(); } }, [['', 'Any level'], ['medium', 'Medium and above'], ['high', 'High and above'], ['pri', 'Check first']].map(([v, name]) => h('option', { value: v, text: t(name), selected: app.level === v })));
  const gr = h('input', { type: 'checkbox', checked: !!app.group, onchange: (e) => { app.group = e.target.checked; actions.render(); } });
  return h('div', { class: 'bar' }, q, lv, h('label', { class: 'chk' }, gr, t('Group by path')), sh, h('span', { class: 'muted', text: shown === total ? String(total) : t('{shown} of {total}', { shown, total }) }));
}
export function renderFindings(ctx, tab) {
  const { app, store, actions } = ctx;
  if (tab === 'params') return renderParams(ctx);
  const all = store.list().filter((f) => (KINDS[tab] || []).includes(f.kind)), list = visible(app, all);
  // Выбранная находка показывается, даже если её скрыл фильтр (например, при переходе из «Обзора»)
  let sel = all.find((f) => f.id === app.sel);
  const left = h('div', { class: 'col list' }, toolbar(ctx, all.length, list.length, app.showHidden ? 0 : all.filter((f) => hiddenReason(f, app)).length));
  if (!list.length) left.append(h('p', { class: 'empty', text: all.length ? t('Nothing matches the filter') : t('Nothing here yet') }));
  // Группировка: находки с путём собираются под заголовком из первых двух сегментов (/api/v2)
  const prefix = (f) => (f.path ? (f.host && f.host !== f.pageHost ? f.host : '') + '/' + f.path.split('/').filter(Boolean).slice(0, 2).join('/') : t('Other'));
  const shown = app.group ? list.slice(0, 600).sort((a, b) => (prefix(a) < prefix(b) ? -1 : prefix(a) > prefix(b) ? 1 : 0)) : list.slice(0, 600);
  let last = null;
  if (!sel) sel = shown[0];
  const counts = new Map(); if (app.group) shown.forEach((f) => counts.set(prefix(f), (counts.get(prefix(f)) || 0) + 1));
  shown.forEach((f) => { if (app.group && prefix(f) !== last) { last = prefix(f); left.append(h('p', { class: 'group mono', text: last + '  ' + counts.get(last) })); } left.append(row(f, app, () => actions.select(f.id), f === sel)); });
  if (list.length > 600) left.append(h('p', { class: 'empty', text: t('Showing 600 of {n}, refine the search', { n: list.length }) }));
  return h('div', { class: 'split' }, left, h('div', { class: 'col' }, sel ? details(sel, ctx) : null));
}
function renderParams(ctx) {
  const ps = ctx.store.paramStats(), box = h('div', { class: 'page' }, h('h1', { text: t('Parameters') }), h('p', { class: 'muted', text: t('All parameter names from URLs and request bodies. Risky names are flagged') }));
  const tbl = h('table', { class: 'table' }, h('thead', {}, h('tr', {}, h('th', { text: t('Parameter') }), h('th', { text: t('Risk') }), h('th', { text: t('Count') }), h('th', { text: t('Where') }))));
  const tb = h('tbody'); ps.slice(0, 500).forEach((p) => tb.append(h('tr', {}, h('td', { class: 'mono', text: p.name }), h('td', { class: 'rk' }, p.risky ? h('span', {}, dot('medium'), ' ' + p.risky) : ''), h('td', { class: 'num', text: p.count }), h('td', { class: 'mono muted', text: p.urls.join('  ') }))));
  tbl.append(tb); box.append(tbl);
  // Словарь цели: слова со страницы и из путей, имена полей форм и ключи JSON. Для своего фаззинга в разрешённом скоупе
  // Словарь пересчитывается, только когда появились новые находки или файлы
  const st = ctx.store, wkey = st.items.length + '|' + st.texts.size;
  if (!st._wl || st._wlKey !== wkey) { st._wl = wordlist(st); st._wlKey = wkey; }
  const wl = st._wl, host = (ctx.store.pageHost || 'site').replace(/[^\w.-]/g, '_');
  box.append(h('h2', { text: t('Target wordlist') }), h('p', { class: 'muted', text: t('Words from the page text, comments, attributes and paths, plus field names from forms, URLs and JSON files. Nothing is requested to build it') }));
  for (const [name, list, file] of [[t('Parameters and fields: {n}', { n: wl.params.length }), wl.params, host + '-params.txt'], [t('Words: {n}', { n: wl.words.length }), wl.words, host + '-words.txt']]) {
    box.append(h('h3', { text: name }), h('div', { class: 'copybox' }, h('pre', { class: 'words', text: list.slice(0, 400).join('  ') + (list.length > 400 ? '  …' : '') }), copyIcon(list.join('\n'))),
      h('div', { class: 'acts' }, button(t('Download'), () => download(file, list.join('\n')))));
  }
  return box;
}
