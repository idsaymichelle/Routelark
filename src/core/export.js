// All export formats. Secrets reach the file only with opt.reveal.
import { VERSION, LEVELS } from '../core.js';
import { npmName } from './advisories.js';
import { wordlist } from './words.js';
import { siteOf, DEFAULT_DENY, ROUTE_KINDS } from './scope.js';
import { sdlDraft } from './graphql.js';
import { mapping } from './mapping.js';
import { bountyReport } from './reportdraft.js';
import { t, getLang, tLabel } from '../i18n.js';

const uniq = (a) => Array.from(new Set(a));
export function view(f, reveal) {
  const o = { id: f.id, kind: f.kind, url: f.url, resolved: f.resolved, method: f.method, host: f.host, params: f.params, auth: f.auth, level: f.level, risk: f.risk, priority: f.priority, confidence: f.confidence, owasp: f.owasp, why: f.why, observed: !!f.observed, sources: f.sources, snippet: reveal && f.snippetRaw ? f.snippetRaw : f.snippet };
  const mp = mapping(f); if (mp.rule) { o.rule = mp.rule; o.top10 = mp.top10; o.cwe = mp.cwe; if (mp.llm.length) o.llm = mp.llm; }
  if (f.kind === 'pii') o.secret = reveal ? f.raw : f.secret;
  if (f.kind === 'secret') { o.secret = reveal ? f.raw : f.secret; if (f.publicKey) o.publicKey = true; }
  if (f.kind === 'tech') { o.name = f.name; o.version = f.version; o.advisories = f.advisories; }
  return o;
}
function csvCell(v) {
  v = v == null ? '' : String(v);
  if (/^\s*[=+\-@]|^[\t\r]/.test(v) && v !== '-') v = "'" + v; // Excel formula guard; a lone "-" (no method) is not a formula
  return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}
const srcLabel = (f) => { const s = f.sources[0]; return s ? s.file.replace(/^.*\//, '') + ':' + s.line : ''; };
const ROUTES = ROUTE_KINDS;
const routes = (list) => list.filter((f) => ROUTES.has(f.kind));
// Lists for scanners (httpx, Nuclei, Burp, Postman, ffuf): target site and its subdomains only, foreign hosts must not be scanned
const portOf = (h) => (/:(\d+)$/.exec(h) || [])[1] || '';
const onSite = (s) => { const site = s && s.pageHost ? siteOf(s.pageHost.replace(/:\d+$/, '')) : ''; return (f) => { if (!site) return true; const h = String(f.host || s.pageHost); return siteOf(h.replace(/:\d+$/, '')) === site && portOf(h) === portOf(s.pageHost); }; };
const fullUrls = (list, s) => uniq(routes(list).filter(onSite(s)).filter((f) => f.resolved && !f.resolved.includes('{') && /^https?:/.test(f.resolved)).map((f) => f.resolved.split('?')[0]));
const methodOf = (f) => (f.method && f.method !== '?' && f.method !== '-' ? f.method : 'GET');
const esc = (s) => String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/`/g, "'").replace(/[\r\n]+/g, ' ').replace(/[<>\[\]]/g, '\\$&'); // raw HTML and links from foreign code must not come alive in .md
// Inside `...` Markdown shows text as is and a backslash would be visible: < > [ ] are not escaped there
const escC = (s) => String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/`/g, "'").replace(/[\r\n]+/g, ' ');
const escHtml = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// tr: translate the heading (text reports only; machine formats stay English)
const title = (f, v, tr) => { const T = tr ? t : (s) => s; return f.kind === 'secret' ? T(f.url) + ': ' + v.secret : (f.method && f.method !== '?' && f.method !== '-' ? f.method + ' ' : '') + (ROUTES.has(f.kind) ? f.url : T(f.url)); };
const whyOf = (v, tr) => (tr ? v.why.map((w) => t(w)) : v.why).join('; ');
const srcT = (f) => { const s = f.sources[0]; return s ? tLabel(s.file).replace(/^.*\//, '') + ':' + s.line : ''; };
const originOf = (u) => { try { return new URL(u).origin; } catch (e) { return ''; } };

// Name kept from the Russian version; values are English, translated via t() on output
export const KIND_LABEL = { api: 'API', debug: 'Admin and debug', docs: 'Documentation', auth: 'Auth', ws: 'WebSocket', page: 'Pages', external: 'External', secret: 'Secrets', pii: 'Personal data', cloud: 'Cloud', tech: 'Stack', code: 'Code', cookie: 'Cookies', storage: 'Storage', config: 'Headers', graphql: 'GraphQL', dom: 'HTML', custom: 'Custom rules and checks', static: 'Static', identity: 'Identity', ai: 'AI', privacy: 'Privacy', tracker: 'Trackers', realtime: 'Realtime channels', mobile: 'Mobile apps', wellknown: 'Service files', infra: 'Infrastructure', browser: 'Browser features', web3: 'Web3', obfuscation: 'Obfuscation' };

export function toJSON(list, o) {
  return JSON.stringify({ tool: 'routelark', version: VERSION, generatedAt: new Date().toISOString(), target: o.target || '', secretsRevealed: !!o.reveal, findings: list.map((f) => view(f, o.reveal)) }, null, 2);
}
export function toCSV(list, o) {
  const head = ['priority', 'level', 'kind', 'method', 'url', 'resolved', 'host', 'params', 'owasp', 'confidence', 'source', 'why', 'secret'];
  return [head.join(',')].concat(list.map((f) => { const v = view(f, o.reveal); return [v.priority ? 'yes' : '', v.level, v.kind, v.method, v.url, v.resolved, v.host, v.params.join(' '), v.owasp.join(' '), v.confidence, srcLabel(f), v.why.join('; '), v.secret || ''].map(csvCell).join(','); })).join('\r\n');
}
export const toURLs = (list, s) => fullUrls(list, s).join('\n');
export const toPaths = (list, s) => uniq(routes(list).filter(onSite(s)).map((f) => f.url.split('?')[0].replace(/\{[^}]*\}/g, 'FUZZ'))).join('\n');

export function toMarkdown(store, o, list) {
  list = list || store.list();
  const c = store.counts(), L = [];
  L.push('# ' + t('Routelark: report'), '', t('Target') + ': `' + escC(o.target || store.pageUrl || '—') + '`  ', t('Generated') + ': ' + new Date().toISOString() + '  ', o.reveal ? t('**Secrets shown in full**') : t('Secrets masked'), '');
  L.push('## ' + t('Summary'), '', t('Findings: **{total}**, priority: **{pri}**, files scanned: {files}', { total: list.length, pri: list.filter((f) => f.priority).length, files: store.files.length }) + (store.errors.length ? t(', load errors: {n}', { n: store.errors.length }) : '') + '.', '');
  LEVELS.slice().reverse().forEach((l) => { if (c.levels[l]) L.push('- ' + l + ': ' + c.levels[l]); });
  store.blocked.forEach((b) => L.push('', t('Scan of host `{host}` stopped: {reason}.', { host: esc(b.host), reason: esc(t(b.reason)) })));
  const pr = list.filter((f) => f.priority);
  L.push('', '## ' + t('Check first'), '');
  if (!pr.length) L.push(t('No priority findings') + '.');
  else { L.push('| ' + [t('Level'), t('Finding'), t('Why'), 'OWASP', t('Source')].join(' | ') + ' |', '| --- | --- | --- | --- | --- |'); pr.slice(0, 100).forEach((f) => { const v = view(f, o.reveal); L.push('| ' + v.level + ' | `' + esc(title(f, v, true)) + '` | ' + esc(whyOf(v, true)) + ' | ' + esc(v.owasp.join(' ')) + ' | ' + esc(srcT(f)) + ' |'); }); }
  const nst = list.filter((f) => f.kind === 'static').length;
  if (nst) L.push('', t('{n} static findings are not listed in this report', { n: nst }));
  for (const k of Object.keys(KIND_LABEL)) {
    const items = list.filter((f) => f.kind === k && !f.priority);
    if (!items.length || k === 'static') continue;
    L.push('', '## ' + t(KIND_LABEL[k]) + ' (' + items.length + ')', '');
    items.slice(0, 150).forEach((f) => { const v = view(f, o.reveal); L.push('- `' + escC(title(f, v, true)) + '` [' + v.level + (v.params.length ? ', ' + t('params') + ': ' + esc(v.params.join(', ')) : '') + (v.why.length && k !== 'secret' ? ', ' + esc(whyOf(v, true)) : '') + '] ' + esc(srcT(f))); });
    if (items.length > 150) L.push('- ' + t('… and {n} more', { n: items.length - 150 }));
  }
  const deps = Array.from(store.deps.values()), scoped = deps.filter((d) => d.scoped);
  if (deps.length) {
    L.push('', '## ' + t('Dependencies (source maps and banners)') + ' (' + deps.length + ')', '');
    if (scoped.length) L.push(t('Scoped packages: make sure the scope is registered to the site owner (dependency confusion).') + ' ' + scoped.map((d) => '`' + escC(d.name) + '`').join(', '), '');
    L.push(deps.filter((d) => !d.scoped).slice(0, 80).map((d) => '`' + escC(d.name) + '`').join(', '));
  }
  const ps = store.paramStats().slice(0, 60);
  if (ps.length) L.push('', '## ' + t('Parameters'), '', ps.map((p) => '`' + escC(p.name) + '`' + (p.risky ? ' (' + p.risky + ')' : '')).join(', '));
  return L.join('\n') + '\n';
}
function toHTML(store, list, o) {
  const rows = (items) => items.map((f) => { const v = view(f, o.reveal); return '<tr><td>' + escHtml(v.level) + '</td><td><code>' + escHtml(title(f, v, true)) + '</code></td><td>' + escHtml(whyOf(v, true)) + '</td><td>' + escHtml(srcT(f)) + '</td></tr>'; }).join('');
  let body = '<h1>' + escHtml(t('Routelark: report')) + '</h1><p>' + escHtml(t('Target')) + ': <code>' + escHtml(o.target || store.pageUrl) + '</code>, ' + escHtml(new Date().toISOString()) + ', ' + escHtml(t('findings')) + ' ' + list.length + ', ' + escHtml(t('files')) + ' ' + store.files.length + '</p>';
  const nst = list.filter((f) => f.kind === 'static').length;
  if (nst) body += '<p>' + escHtml(t('{n} static findings are not listed in this report', { n: nst })) + '</p>';
  for (const k of Object.keys(KIND_LABEL)) {
    const items = list.filter((f) => f.kind === k); if (!items.length || k === 'static') continue;
    body += '<h2>' + escHtml(t(KIND_LABEL[k])) + ' (' + items.length + ')</h2><table><tr><th>' + escHtml(t('Level')) + '</th><th>' + escHtml(t('Finding')) + '</th><th>' + escHtml(t('Why')) + '</th><th>' + escHtml(t('Source')) + '</th></tr>' + rows(items) + '</table>';
  }
  return '<!doctype html><html lang="' + getLang() + '"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>' + escHtml(t('Routelark: report')) + '</title><style>body{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 16px;color:#171717}table{border-collapse:collapse;width:100%;margin-bottom:24px}td,th{border-bottom:1px solid #e5e5e5;padding:6px 8px;text-align:left;vertical-align:top}code{font:12px ui-monospace,Menlo,monospace;word-break:break-all}h2{font-size:16px;font-weight:500;margin-top:32px}</style></head><body>' + body + '</body></html>';
}
function toOpenAPI(store, list, o) {
  const paths = {};
  routes(list).filter((f) => f.path && f.path[0] === '/' && (!f.host || f.host === store.pageHost)).forEach((f) => {
    const p = f.path, m = methodOf(f).toLowerCase(); if (m === 'ws') return;
    const params = Array.from(new Set(p.match(/\{[^}]+\}/g) || [])).map((x) => ({ name: x.slice(1, -1), in: 'path', required: true, schema: { type: 'string' } }))
      .concat((f.query || []).map((n) => ({ name: n, in: 'query', schema: { type: 'string' } })));
    (paths[p] = paths[p] || {})[m] = { summary: f.why[0] || p, parameters: params, responses: { default: { description: 'not verified' } } };
  });
  return JSON.stringify({ openapi: '3.0.3', info: { title: 'Routelark: draft for ' + (store.pageHost || 'site'), version: VERSION, description: 'Collected from client code. Verify before use.' }, servers: [{ url: store.pageOrigin || originOf(o.target) }], paths }, null, 2);
}
function toPostman(store, list) {
  const item = routes(list).filter(onSite(store)).filter((f) => f.resolved && !/^wss?:/.test(f.resolved)).map((f) => ({ name: methodOf(f) + ' ' + f.url, request: { method: methodOf(f), header: [], url: { raw: f.resolved.replace(/\{([^}]+)\}/g, ':$1') } } }));
  return JSON.stringify({ info: { name: 'Routelark: ' + (store.pageHost || 'site'), schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' }, item }, null, 2);
}
// Traffic without a fetch override: URL, time, status. Method comes from code if the URL is found there.
function toHAR(store, list, o) {
  const known = new Map(routes(list).filter((f) => f.resolved).map((f) => [f.resolved.split('?')[0], f.method]));
  const entries = (o.traffic || []).map((t) => {
    const u = String(t.url).split('?')[0], m = known.get(u) || known.get(u.replace(/\/\d+(?=\/|$)/g, '/{id}'));
    return { startedDateTime: new Date(t.t || Date.now()).toISOString(), time: t.duration || 0, request: { method: m && m !== '?' ? m : 'GET', url: o.reveal ? t.url : String(t.url).replace(/([?&][^=&#]+=)[^&#]*/g, '$1…'), httpVersion: '', headers: [], queryString: [], cookies: [], headersSize: -1, bodySize: -1 }, response: { status: t.status || 0, statusText: '', httpVersion: '', headers: [], cookies: [], content: { size: t.size || 0, mimeType: '' }, redirectURL: '', headersSize: -1, bodySize: -1 }, cache: {}, timings: { send: 0, wait: t.duration || 0, receive: 0 }, comment: m && m !== '?' ? 'method taken from code' : 'method unknown: the browser does not report it without patching fetch (' + (t.initiator || '') + ')' };
  });
  return JSON.stringify({ log: { version: '1.2', creator: { name: 'Routelark', version: VERSION }, comment: 'Observed page traffic: only URLs, timings and statuses', entries } }, null, 2);
}
function toSARIF(store, list, o) {
  const results = list.filter((f) => f.risk > 0).map((f) => { const v = view(f, o.reveal), s = f.sources[0] || {}; return { ruleId: 'routelark/' + f.kind, level: f.risk >= 3 ? 'error' : f.risk === 2 ? 'warning' : 'note', message: { text: title(f, v) + (v.why.length ? ' — ' + v.why.join('; ') : '') }, locations: [{ physicalLocation: { artifactLocation: { uri: s.file || store.pageUrl }, region: { startLine: s.line || 1, startColumn: s.col || 1 } } }] }; });
  const rules = uniq(results.map((r) => r.ruleId)).map((id) => ({ id, name: KIND_LABEL[id.split('/')[1]] || id }));
  return JSON.stringify({ version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{ tool: { driver: { name: 'Routelark', version: VERSION, rules } }, results }] }, null, 2);
}
function toCycloneDX(store, list) {
  const techs = list.filter((f) => f.kind === 'tech' && f.name !== 'Build ID');
  const components = techs.map((f) => { const n = npmName(f.name); return { type: 'library', 'bom-ref': f.id, name: n || f.name, version: f.version || undefined, purl: n && f.version ? 'pkg:npm/' + n.replace('@', '%40') + '@' + f.version : undefined }; });
  const vulnerabilities = techs.flatMap((f) => (f.advisories || []).map((a) => ({ id: a.id, description: a.summary, affects: [{ ref: f.id }] })));
  return JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, metadata: { timestamp: new Date().toISOString(), tools: { components: [{ type: 'application', name: 'Routelark', version: VERSION }] } }, components, vulnerabilities }, null, 2);
}
function issue(store, list, o, jira) {
  const top = list.filter((f) => f.risk > 0).slice(0, 25), L = [];
  if (jira) { L.push('h1. ' + t('Routelark: findings for {host}', { host: store.pageHost || o.target }), '', '||' + [t('Level'), t('Finding'), t('Why'), t('Source')].join('||') + '||'); top.forEach((f) => { const v = view(f, o.reveal); L.push('|' + v.level + '|{{' + title(f, v, true).replace(/[{}|\r\n]/g, ' ') + '}}|' + whyOf(v, true).replace(/[|![\]]/g, '/').replace(/[\r\n]+/g, ' ') + '|' + srcT(f).replace(/[\r\n|]/g, ' ') + '|'); }); }
  else { L.push('# ' + t('Routelark: findings for {host}', { host: store.pageHost || o.target }), '', t('Found {total}, {n} above info level listed below.', { total: list.length, n: top.length }), ''); top.forEach((f) => { const v = view(f, o.reveal); L.push('- [ ] **' + v.level + '** `' + esc(title(f, v, true)) + '` — ' + esc(whyOf(v, true)) + (srcT(f) ? ' (' + esc(srcT(f)) + ')' : '')); }); }
  return L.join('\n') + '\n';
}


// Formats for Caido, ZAP, Katana, DefectDojo, Faraday, Bruno and Nuclei. Caido, Bruno, DefectDojo and Faraday were checked against docs, not a live import
const SEV = ['Info', 'Low', 'Medium', 'High', 'Critical'];
const reEsc = (x) => x.replace(/[.^$*+?()[\]{}|/\\]/g, '\\$&');
const hostRe = (site) => 'https?://([a-z0-9-]+\\.)*' + reEsc(site) + '(:[0-9]+)?';
const xmlEsc = (x) => String(x).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
const slug = (x) => String(x).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
function toCaido(s) { const site = siteOf(s.pageHost || ''); return JSON.stringify({ name: 'Routelark: ' + site, allowlist: uniq([s.pageHost !== site ? s.pageHost : null, '*.' + site, site].filter(Boolean)), denylist: [] }, null, 2); }
function toZap(s) {
  const site = siteOf(s.pageHost || ''), re = hostRe(site);
  return '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n<configuration>\n    <context>\n        <name>' + xmlEsc('Routelark: ' + site) + '</name>\n        <desc/>\n        <inscope>true</inscope>\n        <incregexes>' + xmlEsc(re + '/.*') + '</incregexes>\n        <excregexes>' + xmlEsc('(?i)' + re + '/.*(?:' + DEFAULT_DENY.source + ').*') + '</excregexes>\n    </context>\n</configuration>\n';
}
const toKatana = (s) => '^' + hostRe(siteOf(s.pageHost || '')) + '(/|$)\n';
function toDojo(s, list) {
  return JSON.stringify({ type: 'Routelark', findings: list.map((f) => { const v = view(f, false), src = f.sources[0]; return Object.assign({ title: title(f, v) + ' - Routelark lead', severity: SEV[f.risk] || 'Info', description: ['Level: ' + v.level, 'Why: ' + whyOf(v), f.resolved ? 'URL: ' + f.resolved : '', f.params && f.params.length ? 'Parameters: ' + f.params.join(', ') : '', src ? 'Source: ' + srcLabel(f) : ''].filter(Boolean).join('\n'), mitigation: '', impact: '', unique_id_from_tool: f.id, active: true, verified: false, false_p: false, tags: ['routelark'].concat(f.priority ? ['priority'] : []) }, src ? { file_path: src.file.replace(/^.*\//, ''), line: src.line } : {}); }) }, null, 2);
}
function toFaraday(s, list) {
  return ['target,name,desc,severity,refs,website,path,method,params,tags'].concat(list.filter((f) => f.risk > 0).map((f) => { const v = view(f, false); return [f.host || s.pageHost, title(f, v), whyOf(v).replace(/\n/g, ' '), LEVELS[f.risk], '', s.pageOrigin, f.path || '', methodOf(f), (f.params || []).join(' '), 'routelark'].map(csvCell).join(','); })).join('\n') + '\n';
}
const VERBS = /^(?:get|post|put|patch|delete|options|head)$/i;
function toBruno(s, list) {
  const f = list[0]; if (!f || !ROUTES.has(f.kind)) return t('Select an endpoint finding first');
  const known = VERBS.test(f.method || ''), path = (f.resolved || f.url).replace(s.pageOrigin, '').split('?')[0];
  return 'meta {\n  name: ' + methodOf(f) + ' ' + path + '\n  type: http\n  seq: 1\n}\n\n' + (known ? f.method.toLowerCase() : 'get') + ' {\n  url: {{baseUrl}}' + path + '\n  body: none\n  auth: none\n}\n\ndocs {\n  Routelark lead from client code. Verify by hand before use.\n  Level: ' + f.level + '. Source: ' + srcLabel(f) + '\n' + ((f.query || []).length ? '  Parameters: ' + f.query.join(', ') + '\n' : '') + (known ? '' : '  Method unknown: GET is a guess.\n') + (/\{/.test(path) ? '  Path parameters are placeholders.\n' : '') + '}\n';
}
function toNucleiTemplate(s, list) {
  const f = list[0]; if (!f || !ROUTES.has(f.kind)) return t('Not available as a Nuclei template: select an endpoint finding');
  // The template only reads: GET even if the code sends PUT/DELETE; a mutating request must be enabled manually
  // shortcut: value 1 instead of {id} may not exist, substitute your own
  const code = VERBS.test(f.method || '') ? f.method.toUpperCase() : '', m = /^(?:GET|HEAD)$/.test(code) ? code : 'GET', path = (f.path || f.url).split('?')[0].replace(/\{[^}]+\}/g, '1');
  return 'id: routelark-' + (slug(m + '-' + path) || f.id) + '\ninfo:\n  name: ' + JSON.stringify(m + ' ' + path + ' - Routelark lead') + '\n  author: routelark\n  severity: ' + LEVELS[f.risk] + '\n  description: ' + JSON.stringify('Lead from client code. Verify by hand before use.' + (VERBS.test(f.method || '') ? '' : ' Method unknown.')) + '\n  tags: routelark,exposure\nhttp:\n  - method: ' + m + '\n    path:\n      - ' + JSON.stringify('{{BaseURL}}' + path) + (code && code !== m ? '\n    # code uses ' + code + ': change the method by hand only if you are allowed to send it' : '') + '\n    matchers-condition: and\n    matchers:\n      - type: status\n        status:\n          - 200\n    # add a word or regex matcher after checking the response by hand\n';
}
// Script inventory for PCI DSS 6.4.3: a working table, not a compliance result
function toPCI(s, list, o) {
  const card = list.some((f) => f.url === 'Card fields on the page'), rows = new Map();
  for (const r of o.traffic || []) if (/script/.test(r.initiator || '') || /\.m?js(?:$|\?)/.test(String(r.url))) rows.set(String(r.url), [r.url, (() => { try { return new URL(r.url).host; } catch (e) { return ''; } })(), 'script', '', card ? 'yes' : 'no', r.t ? new Date(r.t).toISOString() : '']);
  return ['url,host,kind,sri,on_card_page,first_seen'].concat(Array.from(rows.values(), (r) => r.map(csvCell).join(','))).join('\n') + '\n';
}
// Guesses at neighbouring routes: a list for manual review only, Routelark never requests them
const SIBLINGS = ['admin', 'internal', 'export', 'all', 'debug', 'config', 'settings', 'bulk', 'search', 'count'];
function toSiblings(list) {
  const out = new Set(), have = new Set(routes(list).map((f) => (f.path || '').split('?')[0]));
  for (const p of have) {
    if (!p.startsWith('/') || p.length > 200) continue;
    const parts = p.split('/'), base = parts.slice(0, -1).join('/') || '';
    for (const w of SIBLINGS) out.add(base + '/' + w);
    const v = p.match(/\/v(\d+)\//); if (v) { out.add(p.replace(/\/v\d+\//, '/v' + (+v[1] + 1) + '/')); if (+v[1] > 1) out.add(p.replace(/\/v\d+\//, '/v' + (+v[1] - 1) + '/')); }
  }
  for (const p of have) out.delete(p);
  return '# ' + 'Guesses next to known routes. Not requested by Routelark: check them by hand, within scope\n' + Array.from(out).slice(0, 2000).join('\n') + '\n';
}
// AI bundle: masked data only, hosts replaced, no code fragments or values
function toAI(s, list) {
  // All subdomains of the target site, not just the page host
  const site = siteOf((s.pageHost || '').replace(/:\d+$/, '')), re = site ? new RegExp('(?:[a-z0-9-]+\\.)*' + reEsc(site) + '(?::\\d+)?', 'gi') : null;
  const hide = (x) => (re ? String(x || '').replace(re, 'target.example') : String(x || ''));
  const top = list.filter((f) => f.risk > 0).slice(0, 80);
  return ['# Routelark context for an AI assistant', 'Leads from passive client-side recon. Hosts are replaced with target.example; secret values are masked; no code snippets are included.', 'Task: group these leads by root cause and suggest what to verify by hand first. Do not invent findings.', ''].concat(top.map((f) => { const v = view(f, false); return '- [' + v.level + '] ' + hide(title(f, v)) + ' — ' + hide(whyOf(v)); })).join('\n') + '\n';
}

// build(store, list, opt): list is the already filtered findings (what the UI shows)
export const FORMATS = [
  { id: 'md', label: 'Markdown report', group: 'Reports', ext: 'md', mime: 'text/markdown', build: (s, l, o) => toMarkdown(s, o, l) },
  { id: 'html', label: 'HTML report', group: 'Reports', ext: 'html', mime: 'text/html', build: (s, l, o) => toHTML(s, l, o) },
  { id: 'json', label: 'JSON', group: 'Data', ext: 'json', mime: 'application/json', build: (s, l, o) => toJSON(l, o) },
  { id: 'csv', label: 'CSV', group: 'Data', ext: 'csv', mime: 'text/csv', build: (s, l, o) => toCSV(l, o) },
  { id: 'urls', label: 'URLs for httpx', group: 'Lists', ext: 'txt', mime: 'text/plain', build: (s, l) => toURLs(l, s) },
  { id: 'paths', label: 'Paths with FUZZ for ffuf', group: 'Lists', ext: 'txt', mime: 'text/plain', build: (s, l) => toPaths(l, s) },
  { id: 'params', label: 'Parameter wordlist', group: 'Lists', ext: 'txt', mime: 'text/plain', build: (s) => wordlist(s).params.join('\n') },
  { id: 'words', label: 'Target wordlist', group: 'Lists', ext: 'txt', mime: 'text/plain', build: (s) => wordlist(s).words.join('\n') },
  { id: 'openapi', label: 'OpenAPI 3 (draft)', group: 'Tools', ext: 'json', mime: 'application/json', build: (s, l, o) => toOpenAPI(s, l, o) },
  { id: 'postman', label: 'Postman v2.1', group: 'Tools', ext: 'json', mime: 'application/json', build: (s, l) => toPostman(s, l) },
  { id: 'har', label: 'HAR (page traffic)', group: 'Tools', ext: 'har', mime: 'application/json', build: (s, l, o) => toHAR(s, l, o) },
  { id: 'sarif', label: 'SARIF 2.1.0', group: 'Tools', ext: 'sarif', mime: 'application/json', build: (s, l, o) => toSARIF(s, l, o) },
  { id: 'cyclonedx', label: 'CycloneDX 1.5 (SBOM)', group: 'Tools', ext: 'cdx.json', mime: 'application/json', build: (s, l) => toCycloneDX(s, l) },
  { id: 'burp', label: 'Burp: scope URLs', group: 'Lists', ext: 'txt', mime: 'text/plain', build: (s, l) => uniq(fullUrls(l, s).map((u) => u.replace(/[^/]*$/, ''))).join('\n') },
  { id: 'nuclei', label: 'Nuclei: targets', group: 'Lists', ext: 'txt', mime: 'text/plain', build: (s, l) => toURLs(l, s) },
  { id: 'github', label: 'GitHub issue', group: 'Reports', ext: 'md', mime: 'text/markdown', build: (s, l, o) => issue(s, l, o, false) },
  { id: 'jira', label: 'Jira', group: 'Reports', ext: 'txt', mime: 'text/plain', build: (s, l, o) => issue(s, l, o, true) },
  { id: 'ai', label: 'AI context (redacted)', group: 'Reports', ext: 'md', mime: 'text/markdown', build: (s, l) => toAI(s, l) },
  { id: 'caido', label: 'Caido scope', group: 'Tools', ext: 'json', mime: 'application/json', build: (s) => toCaido(s) },
  { id: 'zap', label: 'ZAP context', group: 'Tools', ext: 'context', mime: 'application/xml', build: (s) => toZap(s) },
  { id: 'katana', label: 'Katana scope', group: 'Lists', ext: 'txt', mime: 'text/plain', build: (s) => toKatana(s) },
  { id: 'dojo', label: 'DefectDojo (generic JSON)', group: 'Tools', ext: 'json', mime: 'application/json', build: (s, l) => toDojo(s, l) },
  { id: 'faraday', label: 'Faraday CSV', group: 'Tools', ext: 'csv', mime: 'text/csv', build: (s, l) => toFaraday(s, l) },
  { id: 'pci', label: 'Script inventory (PCI DSS 6.4.3)', group: 'Data', ext: 'csv', mime: 'text/csv', build: (s, l, o) => toPCI(s, l, o) },
  { id: 'sdl', label: 'GraphQL schema draft (SDL)', group: 'Tools', ext: 'graphql', mime: 'text/plain', build: (s, l) => sdlDraft(l.filter((f) => f.kind === 'graphql')) || '# ' + t('No GraphQL operations found') + '\n' },
  { id: 'siblings', label: 'Sibling route guesses', group: 'Lists', ext: 'txt', mime: 'text/plain', build: (s, l) => toSiblings(l) },
  { id: 'h1', label: 'HackerOne report draft', group: 'Platforms', ext: 'md', mime: 'text/markdown', build: (s, l, o) => bountyReport(s, l, Object.assign({ platform: 'h1' }, o)) },
  { id: 'bugcrowd', label: 'Bugcrowd report draft', group: 'Platforms', ext: 'md', mime: 'text/markdown', build: (s, l, o) => bountyReport(s, l, Object.assign({ platform: 'bugcrowd' }, o)) },
  { id: 'intigriti', label: 'Intigriti report draft', group: 'Platforms', ext: 'md', mime: 'text/markdown', build: (s, l, o) => bountyReport(s, l, Object.assign({ platform: 'intigriti' }, o)) },
  { id: 'bruno', label: 'Bruno request', group: 'Per finding', ext: 'bru', mime: 'text/plain', scope: 'finding', build: (s, l) => toBruno(s, l) },
  { id: 'nuclei-template', label: 'Nuclei template', group: 'Per finding', ext: 'yaml', mime: 'text/yaml', scope: 'finding', build: (s, l) => toNucleiTemplate(s, l) }
];
