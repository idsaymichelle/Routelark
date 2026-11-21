// Настройки скана и вкладки. Живут в памяти, пока открыта вкладка Routelark; в хранилище сайта не пишутся.
import { parseProgram } from '../../core/program.js';
import { h, button, download } from './dom.js';
import { t } from '../../i18n.js';

const DEFAULTS = { delay: 500, budget: 400, depth: 3, allowHosts: [], cookies: false, wellKnown: true, guessMaps: false, osv: true, npmCheck: false, noRequests: false, demo: false, theme: 'auto', lang: typeof navigator !== 'undefined' && /^ru\b/i.test(navigator.language || '') ? 'ru' : 'en', rules: [] };
export const loadSettings = (local) => Object.assign({}, DEFAULTS, local.get('rl:settings') || {});
export const saveSettings = (local, s) => local.set('rl:settings', s);

export function renderSettings(ctx) {
  const { app, actions } = ctx, s = Object.assign({}, app.settings);
  const save = () => actions.saveSettings(s);
  const check = (key, text, hint) => h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: s[key], onchange: (e) => { s[key] = e.target.checked; save(); } }), h('span', {}, text, hint ? h('small', { text: hint }) : null));
  const num = (key, label, min, max, step) => h('label', { class: 'field' }, h('span', { text: label }), h('input', { class: 'in', type: 'number', min, max, step: step || 1, value: s[key], onchange: (e) => { const v = +e.target.value; s[key] = Math.min(max, Math.max(min, Number.isFinite(v) ? v : DEFAULTS[key])); save(); } }));
  const hosts = h('input', { class: 'in', value: s.allowHosts.join(', '), placeholder: 'cdn.example.com, *.example.net', onchange: (e) => { s.allowHosts = e.target.value.split(/[\s,]+/).filter(Boolean); save(); } });
  const theme = h('select', { class: 'in', onchange: (e) => { s.theme = e.target.value; save(); } }, [['auto', 'System'], ['light', 'Light'], ['dark', 'Dark']].map(([v, name]) => h('option', { value: v, text: t(name), selected: s.theme === v })));
  const file = h('input', { type: 'file', accept: '.json', hidden: true, onchange: async (e) => {
    try { const j = JSON.parse(await e.target.files[0].text()); if (!Array.isArray(j.rules)) throw new Error('no rules list'); j.rules.forEach((r) => new RegExp(r.regex, r.flags || '')); s.rules = j.rules.slice(0, 50); save(); }
    catch (x) { rulesNote.textContent = t('Rules file rejected: {error}', { error: t(x.message) }); }
  } });
  const rulesNote = h('p', { class: 'muted', text: s.rules.length ? t('Rules loaded: {n}', { n: s.rules.length }) : t('JSON file like {"rules":[{"id","title","regex","flags","risk"}]}. Rules look for matches in every file that was read') });
  const scopeBox = h('textarea', { class: 'in', rows: 5, 'aria-label': t('Program scope'), placeholder: '*.example.com\napi.example.org\n!blog.example.com', value: app.program ? app.program.text : '' });
  const scopeNote = h('p', { class: 'muted', text: app.program ? t('Scope: {n} rules ({format}), {ignored} ignored', { n: app.program.rules.length, format: app.program.format, ignored: app.program.ignored }) + (app.program.rules.some((r) => !r.out) ? '' : '. ' + t('Scope has no in-scope entries, nothing is hidden')) : '' });
  const lang = h('select', { class: 'in', onchange: (e) => { s.lang = e.target.value; save(); } }, [['en', 'English'], ['ru', 'Русский']].map(([v, name]) => h('option', { value: v, text: name, selected: s.lang === v })));
  return h('div', { class: 'page' },
    h('h1', { text: t('Settings') }),
    h('h2', { text: t('Scan') }),
    h('p', { class: 'muted', text: t('Routelark downloads only JS, source maps, robots, sitemap, manifest and OpenAPI files. GET only, one request at a time. It never calls API endpoints') }),
    h('p', { class: 'muted', text: t('These settings apply to the Full scan mode. Every launch starts in Quiet mode: switch the mode in the header') }),
    h('div', { class: 'fields' }, num('delay', t('Delay between requests, ms'), 300, 2000, 50), num('budget', t('Request limit'), 1, 2000), num('depth', t('Depth'), 1, 4)),
    h('label', { class: 'field wide' }, h('span', { text: t('Other in-scope hosts. Subdomains of the site are included anyway') }), hosts),
    check('wellKnown', t('Read robots.txt, sitemap, security.txt and manifest')),
    check('guessMaps', t('Try .map next to every script'), t('Extra requests if there are no maps')),
    check('cookies', t('Send cookies when downloading files'), t('Own origin only')),
    check('osv', t('Check library versions on OSV.dev'), t('Only the package name and version are sent')),
    check('npmCheck', t('Check scoped packages on npm'), t('Names of scoped packages from source maps are sent to registry.npmjs.org')),
    h('h2', { text: t('Program scope') }),
    h('p', { class: 'muted', text: t('Paste the scope from HackerOne or Bugcrowd (JSON), or one host per line: *.example.com, ! for out of scope. Findings outside it are hidden and left out of reports. Scanning rules do not change') }),
    scopeBox, h('div', { class: 'acts' }, button(t('Apply scope'), () => { try { const p = parseProgram(scopeBox.value); actions.setProgram(p.rules.length ? Object.assign(p, { text: scopeBox.value }) : null); } catch (x) { scopeNote.textContent = t(x.message); } }), app.program ? button(t('Clear scope'), () => actions.setProgram(null)) : null),
    scopeNote,
    h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: !!app.showHidden, onchange: (e) => actions.setShowHidden(e.target.checked) }), h('span', {}, t('Show hidden'), h('small', { text: t('Findings outside the program scope') }))),
    h('h2', { text: t('Appearance') }),
    h('label', { class: 'field' }, h('span', { text: t('Language') }), lang),
    h('label', { class: 'field' }, h('span', { text: t('Theme') }), theme),
    check('demo', t('Hide hosts'), t('For screenshots and demos')),
    h('h2', { text: t('Custom rules') }), rulesNote, file,
    h('div', { class: 'acts' }, button(t('Load rules'), () => file.click()), button(t('Download current'), () => download('routelark-rules.json', JSON.stringify({ rules: s.rules }, null, 2), 'application/json')), s.rules.length ? button(t('Remove rules'), () => { s.rules = []; save(); }) : null),
  );
}
