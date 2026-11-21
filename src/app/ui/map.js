// "Map" tab: attack surface tree colored by the highest risk, and a per-host authorization map.
import { h, dot } from './dom.js';
import { t } from '../../i18n.js';
import { surfaceTree, authMap } from '../../core/map.js';
import { KINDS } from './findings.js';
const LV = ['info', 'low', 'medium', 'high', 'critical'];
export function renderMap(ctx) {
  const { store, actions } = ctx, tree = surfaceTree(store), auth = authMap(store);
  // A host node has no ids of its own: take the id of the first descendant
  const first = (n) => n.ids[0] || n.kids.reduce((id, k) => id || first(k), null);
  const node = (x, depth) => h('li', {}, h('button', { class: 'link mapnode', type: 'button', onclick: () => { const id = first(x), f = id && store.items.find((i) => i.id === id); if (f) { actions.setTab(Object.keys(KINDS).find((k) => KINDS[k].includes(f.kind)) || 'api'); actions.select(f.id); } } }, dot(LV[x.risk]), ' ', h('span', { class: 'mono', text: (depth ? '/' : '') + x.name }), h('span', { class: 'muted', text: ' ' + x.n })),
    x.kids.length && depth < 3 ? h('ul', { class: 'tree' }, x.kids.map((k) => node(k, depth + 1))) : null);
  return h('div', { class: 'page' },
    h('h1', { text: t('Attack surface map') }),
    h('p', { class: 'muted', text: t('Endpoints grouped by host and path. The dot shows the highest level inside; the number is the count of addresses') }),
    tree.length ? h('ul', { class: 'tree' }, tree.map((x) => node(x, 0))) : h('p', { class: 'empty', text: t('Nothing here yet') }),
    h('h2', { text: t('Authorization by host') }),
    h('p', { class: 'muted', text: t('Which hosts receive authorization headers, cookies or CSRF tokens, and where login, logout and token refresh live. Header values are never shown') }),
    auth.length ? h('table', { class: 'table' }, h('thead', {}, h('tr', {}, [t('Host'), t('Endpoints'), t('Sent with'), t('Auth endpoints')].map((x) => h('th', { text: x })))),
      h('tbody', {}, auth.map((r) => h('tr', { class: r.crossAuth ? 'st-fail' : '' }, h('td', { class: 'mono', text: r.host || t('this site') }), h('td', { text: String(r.endpoints) }), h('td', { text: r.auth.map((a) => t(a)).join(', ') + (r.crossAuth ? ' — ' + t('Authorization header sent to another host') : '') }), h('td', { text: r.roles.join(', ') }))))) : null);
}
