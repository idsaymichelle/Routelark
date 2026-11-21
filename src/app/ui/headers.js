// Document response headers: issues and the full table.
import { h, dot, button } from './dom.js';
import { parseHeaders } from '../../core.js';
import { row, details } from './findings.js';
import { t } from '../../i18n.js';

export function renderHeaders(ctx) {
  const { app, store, actions } = ctx, list = store.list().filter((f) => f.kind === 'config');
  const sel = list.find((f) => f.id === app.sel);
  const left = h('div', { class: 'col list' });
  if (!list.length) left.append(h('p', { class: 'empty', text: store.docHeaders ? t('No header issues found') : t('Headers were not read: no-requests mode is on or this is not an HTML page') }));
  list.forEach((f) => left.append(row(f, app, () => actions.select(f.id), f === sel)));
  const right = h('div', { class: 'col' });
  if (sel) right.append(details(sel, ctx));
  // If the tab could not read headers (COOP, no-request mode, capture file), they can be pasted manually
  if (!store.docHeaders || store.headersPasted) {
    const st = app.hdr || (app.hdr = { text: '', note: '' });
    right.append(h('section', { class: 'detail' }, h('h2', { text: t('Paste response headers') }),
      h('p', { class: 'muted', text: t('Copy the response headers of the page from DevTools (Network, the document request) or from Burp and paste them here. Routelark grades them without any request') }),
      h('textarea', { class: 'in', rows: 8, 'aria-label': t('Paste response headers'), placeholder: 'content-security-policy: default-src \'self\'\nstrict-transport-security: max-age=31536000', oninput: (e) => { st.text = e.target.value; } }, st.text),
      h('div', { class: 'acts' }, button(t('Check headers'), () => {
        const hd = parseHeaders(st.text);
        if (!Object.keys(hd).length) { st.note = 'No headers found in the text'; return actions.render(); }
        store.headersPasted = true; st.note = '';
        store.replaceHeaders(hd, /^https:/.test(store.pageUrl), '(pasted headers)');
        actions.render();
      }, 'pri'), st.note ? h('span', { class: 'muted', text: t(st.note) }) : null)));
  }
  if (store.docHeaders) {
    const tbl = h('table', { class: 'table' }, h('thead', {}, h('tr', {}, h('th', { text: t('Header') }), h('th', { text: t('Value') }))));
    const tb = h('tbody');
    Object.keys(store.docHeaders).sort().forEach((k) => tb.append(h('tr', {}, h('td', { class: 'mono', text: k }), h('td', { class: 'mono', text: store.docHeaders[k] }))));
    tbl.append(tb);
    right.append(h('section', { class: 'detail' }, h('h2', {}, dot('info'), ' ' + t('All document headers')), tbl));
  }
  return h('div', { class: 'split' }, left, right);
}
