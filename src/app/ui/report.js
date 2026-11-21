// Report: pick a format, preview on the page, then download, copy or open in a separate tab.
import { h, button, copy, download, openInTab } from './dom.js';
import { FORMATS } from '../../core/export.js';
import { sessionFile, readSession, compareRuns } from '../../core/session.js';
import { t, getLang } from '../../i18n.js';
import { analyzeFiles } from '../offline.js';
import { isShown } from '../visible.js';

export function renderReport(ctx) {
  const { app, store, actions } = ctx, st = app.report || (app.report = { fmt: 'md', secrets: false, note: '' });
  const fmt = FORMATS.find((f) => f.id === st.fmt) || FORMATS[0];
  // The screen redraws often during a scan: the report is rebuilt only when data or selection changed
  const key = [fmt.id, st.secrets, store.rev, store.status, (app.traffic || []).length, getLang(), fmt.scope ? app.sel : '', st.ai, app.program ? app.program.rules.length : 0, !!app.showHidden].join('|');
  // Reports exclude out-of-scope findings by default ("Show hidden" toggle in settings)
  const chosen = fmt.scope === 'finding' ? store.list().filter((f) => f.id === app.sel) : store.list().filter((f) => isShown(f, app));
  let text = st.cacheKey === key && st.cacheStore === store ? st.cache : '';
  if (st.cacheKey !== key || st.cacheStore !== store) try { text = fmt.build(store, chosen, { ai: st.ai, reveal: st.secrets, target: store.pageUrl, traffic: (app.page ? app.page.resources : []).concat(app.traffic) }); } catch (e) { text = t('Could not build: {error}', { error: e && e.message || e }); }
  st.cache = text; st.cacheKey = key; st.cacheStore = store;
  const name = 'routelark-' + (store.pageHost || 'report').replace(/[^\w.-]/g, '_') + '-' + (fmt.scope && app.sel ? app.sel : fmt.id) + '.' + fmt.ext;

  const left = h('div', { class: 'col list' });
  for (const group of Array.from(new Set(FORMATS.map((f) => f.group)))) {
    left.append(h('p', { class: 'group', text: t(group) }));
    FORMATS.filter((f) => f.group === group).forEach((f) => left.append(h('button', { class: 'row', type: 'button', 'aria-current': f === fmt ? 'true' : null, onclick: () => { st.fmt = f.id; actions.render(); } }, h('span', { class: 'l1' }, h('span', { text: t(f.label) }), h('span', { class: 'lv', text: '.' + f.ext })))));
  }
  const file = h('input', { type: 'file', accept: '.json', hidden: true, onchange: async (e) => {
    try { const j = readSession(await e.target.files[0].text()); app.diff = compareRuns(j.findings.map((f) => f.id), store); app.prevLabels = Object.fromEntries(j.findings.map((f) => [f.id, (f.method && f.method.length > 1 ? f.method + ' ' : '') + f.url])); st.note = 'Comparison ready: ' + app.diff.added.length + ' added, ' + app.diff.removed.length + ' removed. Details are in Overview' + (j.origin && j.origin !== store.pageOrigin ? '. Warning: the file is from a different site (' + j.origin + ')' : ''); }
    catch (x) { st.note = x.message; } // the message is translated on output
    actions.render();
  } });
  // Open a saved session or file: the result is shown instead of the current scan
  const open = h('input', { type: 'file', multiple: true, hidden: true, onchange: async (e) => {
    try { const r = await analyzeFiles(Array.from(e.target.files), '', app.settings); if (!r.store.items.length && !(r.cookies || []).length) st.note = 'No findings in this data'; else return actions.showStore(r.store, r.page, r.cookies); }
    catch (x) { st.note = 'Could not parse: ' + (x && x.message || x); }
    actions.render();
  } });
  left.append(h('p', { class: 'group', text: t('Session') }), h('div', { class: 'bar' }, button(t('Save session'), () => download('routelark-' + (store.pageHost || 'session') + '.routelark.json', JSON.stringify(sessionFile(store, app.program), null, 2), 'application/json')), button(t('Compare with file'), () => file.click()), file, button(t('Open session or file'), () => open.click(), null, t('A saved session, HAR, an export from Burp, ZAP or Caido, or a JS/map file')), open));
  if (st.note) left.append(h('p', { class: 'hint', text: t(st.note) }));

  const head = h('div', { class: 'bar' },
    h('strong', { text: t(fmt.label) }),
    h('span', { class: 'muted', text: t('{n} lines', { n: text.split('\n').length }) }),
    fmt.group === 'Platforms' ? h('label', { class: 'chk', title: t('Check the programme rules: some programmes ask for disclosure, some ban AI submissions. Routelark does not know them') }, t('AI tools helped write or analyse this report') + ': ', h('select', { onchange: (e) => { st.ai = e.target.value; actions.render(); } }, [['unset', 'not set'], ['yes', 'yes'], ['no', 'no']].map(([v, l]) => h('option', { value: v, selected: (st.ai || 'unset') === v, text: t(l) })))) : null,
    h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: st.secrets, onchange: (e) => { st.secrets = e.target.checked; actions.render(); } }), t('With secrets')),
    h('span', { class: 'grow' }),
    button(t('Open in tab'), () => openInTab(text, fmt.id === 'html' ? 'text/html' : 'text/plain')),
    button(t('Copy'), () => copy(text)),
    button(t('Download'), () => download(name, text, fmt.mime), 'pri'));
  // The HTML report is shown in an isolated frame: scripts in it do not run
  const preview = fmt.id === 'html' ? h('iframe', { class: 'frame', sandbox: '', srcdoc: text, title: t('Report preview') }) : h('pre', { class: 'preview', text: text || t('Empty') });
  return h('div', { class: 'split report' }, left, h('div', { class: 'col' }, head, preview));
}
