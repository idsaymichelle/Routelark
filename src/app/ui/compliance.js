// Compliance tab: ASVS 5.0 V3 requirements and WSTG v4.2 tests from browser data. Hints, not an audit.
import { h } from './dom.js';
import { t } from '../../i18n.js';
import { complianceRows } from '../../core/compliance.js';
const LABEL = { pass: 'Pass', fail: 'Lead found', check: 'Check by hand', na: 'Not checkable' };
export function renderCompliance(ctx) {
  const { app, store } = ctx, rows = complianceRows(store, app);
  const table = (group, title, note) => h('section', { class: 'card' }, h('h2', { text: t(title) }), h('p', { class: 'muted', text: t(note) }),
    h('table', { class: 'table' }, h('thead', {}, h('tr', {}, [t('ID'), t('Requirement'), t('Status'), t('Why')].map((x) => h('th', { text: x })))),
      h('tbody', {}, rows.filter((r) => r.group === group).map((r) => h('tr', { class: 'st-' + r.status }, h('td', { class: 'mono code', text: r.id }), h('td', { text: t(r.name) }), h('td', { text: t(LABEL[r.status]) }), h('td', { class: 'muted', text: r.reason ? t(r.reason) : '' }))))));
  return h('div', { class: 'page' }, h('p', { class: 'note', text: t('Leads from passive data, not an audit result: every status needs a human to confirm it') }),
    table('asvs', 'OWASP ASVS 5.0, chapter V3 (web frontend)', 'Requirements a browser can partly observe'),
    table('wstg', 'OWASP WSTG v4.2: client-side and information gathering', 'Test areas: a lead means a human should run the test'));
}
