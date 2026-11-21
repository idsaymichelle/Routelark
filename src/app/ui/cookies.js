// Page cookies: list, decoding, editor, import and export. The collector on the page does the writing.
import { h, button, copy, copyIcon, download, dot, kv } from './dom.js';
import { decodeValue, auditCookie, parseCookieInput, exportCookies, isSensitiveCookie, badCookieValue } from '../../core/cookies.js';
import { t } from '../../i18n.js';

const DAY = 864e5;
const keyOf = (c) => c.name + '|' + (c.path || '/');
const LEVELS = ['info', 'low', 'medium', 'high'];

export function renderCookies(ctx) {
  const { app, actions } = ctx, list = app.cookies, https = app.page ? /^https:/.test(app.page.url) : true, canWrite = !!app.link && !app.link.closed;
  const ui = app.cookieUi || (app.cookieUi = { draft: null, undo: null, importText: '', preview: null, note: '' });
  const sel = app.sel === '+new' ? null : list.find((c) => keyOf(c) === app.sel) || (app.sel === '+import' ? null : list[0]);
  // note is stored in English, t() is applied on output
  const apply = (p, note) => p.then((r) => { if (r && r.cookies) app.cookies = r.cookies; ui.draft = null; ui.note = r && r.ok ? note : r && r.duplicate ? 'Saved, but the site has another cookie with this name (for another path or domain). The browser keeps both, and the site may read the other one' : (r && r.cookies ? 'Failed: the browser did not accept the change' : 'Failed: the site page did not respond'); actions.render(); });
  const guard = (c) => !isSensitiveCookie(c.name) || window.confirm(t('"{name}" looks like a session cookie. Changing it may log you out of the site. Continue?', { name: c.name }));
  function write(c, before, note) {
    if (!guard(c)) return;
    // Undo: restore the previous cookie or delete the created one
    // If the path or domain changed, the new cookie is separate: delete it too on undo
    ui.undo = before ? async () => { if (before.path !== c.path || before.domain !== c.domain) await app.link.deleteCookie(c); return apply(app.link.setCookie(before), 'Undone'); } : () => apply(app.link.deleteCookie(c), 'Undone');
    apply(app.link.setCookie(c), note);
  }

  const left = h('div', { class: 'col list' }, h('div', { class: 'bar' },
    canWrite ? button(t('New'), () => { ui.draft = null; actions.select('+new'); }) : null,
    canWrite ? button(t('Import'), () => actions.select('+import')) : null,
    button('JSON', () => download('cookies.json', exportCookies(list, 'json'), 'application/json')),
    button('Netscape', () => download('cookies.txt', exportCookies(list, 'netscape', app.page ? new URL(app.page.url).hostname : ''))),
    // "Cookie: a=1; b=2" line to paste into curl, Burp or Postman; without feedback the button seemed broken
    button(t('Copy Cookie header'), () => { copy('Cookie: ' + exportCookies(list, 'header')); ui.note = 'Cookie header copied'; actions.render(); }),
    ui.undo && canWrite ? button(t('Undo last'), () => { const u = ui.undo; ui.undo = null; u(); }) : null));
  left.append(h('p', { class: 'hint', text: t('HttpOnly cookies are hidden from the page by the browser and are not listed here. In Safari, cookies written from JS live no longer than 7 days') + (ui.note ? '. ' + t(ui.note) : '') }));
  if (!list.length) left.append(h('p', { class: 'empty', text: t('No visible cookies') }));
  list.forEach((c) => {
    const a = auditCookie(c, https);
    left.append(h('button', { class: 'row', type: 'button', 'aria-current': c === sel ? 'true' : null, onclick: () => { ui.draft = null; actions.select(keyOf(c)); } },
      h('span', { class: 'l1' }, dot(LEVELS[a.risk]), h('span', { class: 'route', text: c.name }), h('span', { class: 'lv', text: c.expires && isFinite(c.expires) ? t('until {date}', { date: new Date(c.expires).toISOString().slice(0, 10) }) : t('session') })),
      h('span', { class: 'sub', text: [c.value.slice(0, 80), a.why[0] && t(a.why[0])].filter(Boolean).join(', ') })));
  });

  const right = h('div', { class: 'col' });
  if (app.sel === '+import') right.append(importPane());
  else if (sel || app.sel === '+new') right.append(editor(sel));
  return h('div', { class: 'split' }, left, right);

  function editor(c) {
    const d = ui.draft || (ui.draft = c ? Object.assign({}, c, { days: c.expires ? Math.max(1, Math.round((c.expires - Date.now()) / DAY)) : '' }) : { name: '', value: '', path: '/', days: 30, secure: https, sameSite: 'Lax', hostOnly: true });
    const box = h('section', { class: 'detail' }, h('div', { class: 'titlebar' }, h('h2', { text: c ? c.name : t('New cookie') }), c ? copyIcon(c.name) : null));
    if (c) {
      const a = auditCookie(c, https);
      box.append(kv([[t('Domain'), c.domain || (c.attrsKnown ? t('this host only') : t('not reported by the browser'))], [t('Attributes'), c.attrsKnown ? [c.secure ? 'Secure' : t('no Secure'), 'SameSite=' + (c.sameSite || t('not set'))].join(', ') : t('not reported by the browser')], [t('Size'), t('{n} chars', { n: c.name.length + c.value.length })]]), h('h3', { text: t('Value') }), h('div', { class: 'copybox' }, h('pre', { text: c.value }), copyIcon(c.value)));
      if (a.why.length) box.append(h('h3', { text: t('Notes') }), h('ul', {}, a.why.map((w) => h('li', { text: t(w) }))));
      decodeValue(c.value).forEach((x) => box.append(h('h3', { text: t(x.label) }), h('div', { class: 'copybox' }, h('pre', { text: x.text }), copyIcon(x.text))));
    }
    if (!canWrite) { box.append(h('p', { class: 'muted', text: t('Editing is unavailable: no link to the site page') })); return box; }
    const field = (label, el) => h('label', { class: 'field' }, h('span', { text: label }), el);
    const text = (key, attrs) => h('input', Object.assign({ class: 'in', value: d[key] == null ? '' : d[key], oninput: (e) => { d[key] = e.target.value; } }, attrs));
    box.append(h('h3', { text: c ? t('Edit') : t('Create') }), h('div', { class: 'fields' },
      c ? null : field(t('Name'), text('name')),
      h('label', { class: 'field wide' }, h('span', { text: t('Value') }), h('textarea', { class: 'in', rows: 3, oninput: (e) => { d.value = e.target.value; } }, d.value)),
      field(t('Path'), text('path')),
      field(t('Days to keep (empty: until the browser closes)'), text('days', { type: 'number', min: 1, max: 400 })),
      field('SameSite', h('select', { class: 'in', onchange: (e) => { d.sameSite = e.target.value || null; } }, ['', 'Lax', 'Strict', 'None'].map((v) => h('option', { value: v, text: v || t('not set'), selected: (d.sameSite || '').toLowerCase() === v.toLowerCase() }))))),
      h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: !!d.secure, onchange: (e) => { d.secure = e.target.checked; } }), 'Secure'));
    const built = () => Object.assign({}, d, { name: String(d.name).trim(), path: d.path || '/', expires: +d.days > 0 ? Date.now() + Math.min(400, +d.days) * DAY : undefined });
    const acts = h('div', { class: 'acts' }, button(c ? t('Save') : t('Create'), () => { const n = built(); if (!n.name) { ui.note = 'Name is required'; return actions.render(); } if (badCookieValue(n.value) || badCookieValue(n.name)) { ui.note = 'Value cannot contain ";" or line breaks'; return actions.render(); } write(n, c, c ? 'Saved' : 'Created'); app.sel = keyOf(n); }, 'pri'));
    if (c) acts.append(
      button(t('Extend by 30 days'), () => write(Object.assign({}, c, { expires: Date.now() + 30 * DAY }), c, 'Extended')),
      button(t('Duplicate'), () => { const n = Object.assign({}, c, { name: c.name + '_copy' }); write(n, null, 'Copy created'); app.sel = keyOf(n); }),
      button(t('Delete'), () => { if (!guard(c)) return; ui.undo = () => apply(app.link.setCookie(c), 'Restored'); apply(app.link.deleteCookie(c), 'Deleted'); }));
    box.append(acts);
    return box;
  }
  function importPane() {
    const box = h('section', { class: 'detail' }, h('h2', { text: t('Import cookies') }), h('p', { class: 'muted', text: t('JSON, Netscape format, Set-Cookie lines or a Cookie header. They are written to this site only') }));
    box.append(h('textarea', { class: 'in', rows: 8, placeholder: 'sid=abc; theme=dark', oninput: (e) => { ui.importText = e.target.value; ui.preview = null; } }, ui.importText));
    box.append(h('div', { class: 'acts' }, button(t('Check'), () => { ui.preview = parseCookieInput(ui.importText); actions.render(); })));
    if (ui.preview) {
      const have = new Set(list.map((c) => c.name)), over = ui.preview.filter((c) => have.has(c.name)).length;
      box.append(h('p', { text: ui.preview.length ? t('Add {add}, overwrite {over}', { add: ui.preview.length - over, over }) : t('Could not parse the text') }));
      if (ui.preview.length) box.append(h('div', { class: 'acts' }, button(t('Apply'), async () => {
        const todo = ui.preview, before = list.slice();
        if (todo.some((c) => isSensitiveCookie(c.name)) && !window.confirm(t('The import contains session cookies. Your current session on the site may change. Continue?'))) return;
        const written = todo.map((c) => Object.assign({}, c, { hostOnly: true, domain: undefined })); // write to this host only
        const results = []; for (const c of written) results.push(await app.link.setCookie(c));
        const failed = written.filter((c, i) => !(results[i] && results[i].ok)).map((c) => c.name), last = results[results.length - 1];
        ui.undo = async () => { let r; for (const c of written) r = await (before.find((b) => b.name === c.name) ? app.link.setCookie(before.find((b) => b.name === c.name)) : app.link.deleteCookie(c)); apply(Promise.resolve(r), 'Import undone'); };
        ui.preview = null; ui.importText = ''; apply(Promise.resolve(Object.assign({}, last, { ok: true })), 'Imported: ' + (todo.length - failed.length) + (failed.length ? '. Rejected by the browser: ' + failed.join(', ') : ''));
      }, 'pri')));
    }
    return box;
  }
}
