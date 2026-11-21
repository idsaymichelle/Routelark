// D3: черновики отчётов для HackerOne, Bugcrowd и Intigriti. Одна корневая причина — один отчёт со всеми местами.
// Вектор CVSS 4.0 предлагается только для секретов и без числовой оценки (калькулятор не сверен с эталоном FIRST); влияние пишет человек.
import { mapping } from './mapping.js';
import { fnv } from '../core.js';
const NEEDS = (f) => !(f.observed && f.confidence === 'high');
const reason = (rule) => (/^secret/.test(rule) ? 'secret pattern, validity not checked' : rule === 'tech.cve' ? 'version match only' : /^cloud/.test(rule) ? 'cloud record, owner not checked' : 'static data');
export function groupFindings(list) {
  const groups = new Map();
  for (const f of list) {
    if (!(f.risk > 0)) continue;
    const m = mapping(f), rule = m.rule || f.kind;
    const key = /^secret/.test(rule) ? rule + '|' + fnv(String(f.raw || f.secret)) : /^(?:hdr|cookie)/.test(rule) ? rule : /^(?:html|code)/.test(rule) ? rule + '|' + ((f.sources[0] || {}).file || '') : /^(?:path|param)/.test(rule) ? rule + '|' + (f.path || f.url) : rule + '|' + f.url;
    if (!groups.has(key)) groups.set(key, { key, rule, m, members: [], risk: 0, priority: false, needsManual: false });
    const g = groups.get(key); g.members.push(f); g.risk = Math.max(g.risk, f.risk); g.priority = g.priority || f.priority; g.needsManual = g.needsManual || NEEDS(f);
  }
  return Array.from(groups.values()).sort((a, b) => (b.priority - a.priority) || (b.risk - a.risk) || (b.members.length - a.members.length));
}
const STEPS = {
  hdr: ['Open {url}.', 'Check the document response headers (DevTools → Network).'],
  html: ['Open {url}.', 'Search the page source for the snippet below.'],
  code: ['Open {file}.', 'Go to line {line}.'],
  secret: ['Open {file}.', 'Go to line {line}.', 'Check the key owner and permissions in your own account only.'],
  path: ['Find the URL in the page traffic or source.', 'Note the method and parameters; test it by hand with your own accounts.'],
  cookie: ['Open DevTools → Application → Cookies.', 'Read the flags of the cookie.'],
  tech: ['Open {file}.', 'Check the library version in the source and compare it with the advisory.'],
  other: ['Open {url}.', 'Find the place named in the finding and check it by hand.']
};
// Строки с сайта не должны ломать разметку отчёта: переводы строк схлопываются, обратные кавычки и начало строки экранируются
const md = (x) => String(x == null ? '' : x).replace(/[\r\n]+/g, ' ').replace(/`/g, "'").replace(/^\s*([#>*+\-\[])/, '\\$1');
export function bountyReport(store, list, o) {
  const plat = o.platform, all = groupFindings(list), groups = all.slice(0, 30), L = [];
  const host = store.pageHost || '';
  for (const g of groups) {
    const f = g.members[0], src = f.sources[0] || {}, fam = (g.rule.match(/^(\w+)/) || [])[1];
    const label = md(f.kind === 'secret' ? 'Disclosure of ' + f.url : f.url);
    L.push('## ' + (label + ' on ' + host).slice(0, 120), '');
    L.push('**Summary.** Routelark found ' + g.members.length + ' place(s) with: ' + md(f.why[0] || f.url) + '. This is a lead from static data and has not been confirmed by a request.', '');
    if (g.needsManual) L.push('> Needs manual validation: ' + reason(g.rule) + '.', '');
    L.push('**Affected locations**', '');
    g.members.slice(0, 20).forEach((x) => { const s = x.sources[0] || {}; L.push('- ' + md(x.resolved || x.url) + (s.file ? ' (' + md(s.file.replace(/^.*\//, '')) + ':' + s.line + ')' : '')); });
    if (g.members.length > 20) L.push('- and ' + (g.members.length - 20) + ' more');
    L.push('', '**Steps to reproduce**', '');
    (STEPS[fam] || STEPS[f.kind] || (/^(?:api|page|auth|debug|docs|ws|external)$/.test(f.kind) ? STEPS.path : STEPS.other)).forEach((s, i) => L.push((i + 1) + '. ' + s.replace('{url}', () => store.pageUrl).replace('{file}', () => src.file || store.pageUrl).replace('{line}', () => String(src.line || 1))));
    if (f.snippet && fam !== 'secret' && f.kind !== 'pii') L.push('', '```', String(o.reveal && f.snippetRaw ? f.snippetRaw : f.snippet).slice(0, 300).replace(/```/g, "'''"), '```');
    L.push('', '**Impact**', '', '_Describe who can do what, with which access. Routelark does not write this part._', '');
    if (fam === 'secret') L.push('**Suggested CVSS 4.0 vector** (edit to the real impact; no score is computed): `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`', '');
    const refs = [g.m.top10.length ? 'OWASP Top 10 2025: ' + g.m.top10.join(', ') : '', g.m.cwe.length ? g.m.cwe.join(', ') : '', g.m.asvs.length ? 'ASVS ' + g.m.asvs.join(', ') : '', g.m.wstg.length ? 'WSTG ' + g.m.wstg.join(', ') : ''].filter(Boolean);
    if (refs.length) L.push('**References:** ' + refs.join('; '), '');
    if (o.ai && o.ai !== 'unset') L.push('**AI tools helped write or analyse this report:** ' + o.ai, '');
    L.push('---', '');
  }
  if (all.length > 30) L.push('_' + (all.length - 30) + ' more groups not shown._', '');
  const foot = { h1: 'HackerOne sections: title, steps, expected and actual behaviour, impact, supporting material.', bugcrowd: 'Bugcrowd: pick the VRT category from the CWE and OWASP references; field list not verified.', intigriti: 'Intigriti: CVSS 3.0 is the default; a 4.0 vector may not be accepted by the form. Field list not verified.' }[plat] || '';
  return (groups.length ? L.join('\n') : 'No findings above info level.\n') + '\n<!-- ' + foot + ' Check the programme rules before submitting: scope, duplicates and AI-use policy. -->\n';
}
