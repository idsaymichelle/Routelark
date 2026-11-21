// Page localStorage and sessionStorage: keys, value decoding.
import { h, kv, copyIcon } from './dom.js';
import { decodeValue } from '../../core/cookies.js';
import { t } from '../../i18n.js';

export function renderStorage(ctx) {
  const { app, actions } = ctx, st = app.page ? app.page.storage : { local: [], session: [] };
  const items = st.local.map(([k, v]) => ({ id: 'l:' + k, kind: 'localStorage', k, v })).concat(st.session.map(([k, v]) => ({ id: 's:' + k, kind: 'sessionStorage', k, v })));
  const sel = items.find((i) => i.id === app.sel) || items[0];
  const left = h('div', { class: 'col list' });
  if (!items.length) left.append(h('p', { class: 'empty', text: t('Storage is empty') }));
  items.forEach((i) => left.append(h('button', { class: 'row', type: 'button', 'aria-current': i === sel ? 'true' : null, onclick: () => actions.select(i.id) },
    h('span', { class: 'l1' }, h('span', { class: 'route', text: i.k }), h('span', { class: 'lv', text: i.kind === 'localStorage' ? 'local' : 'session' })),
    h('span', { class: 'sub', text: t('{n} chars', { n: i.v.length }) }))));
  const right = h('div', { class: 'col' });
  if (sel) {
    const decoded = decodeValue(sel.v);
    const d = h('section', { class: 'detail' }, h('div', { class: 'titlebar' }, h('h2', { text: sel.k }), copyIcon(sel.k)), kv([[t('Where'), sel.kind], [t('Size'), t('{n} chars', { n: sel.v.length })]]),
      h('h3', { text: t('Value') }), h('div', { class: 'copybox' }, h('pre', { text: sel.v.slice(0, 20000) }), copyIcon(sel.v)));
    decoded.forEach((x) => d.append(h('h3', { text: t(x.label) }), h('div', { class: 'copybox' }, h('pre', { text: x.text }), copyIcon(x.text))));
    right.append(d);
  }
  return h('div', { class: 'split' }, left, right);
}
