// Core: pure functions without DOM; tested in node (test/*.test.mjs).
import { blockedReason } from './core/scope.js';
import { scanIdentity, scanAi } from './core/identity.js';
import { oauthLiteral } from './core/tokens.js';
import { piiFindings, maskEmails } from './core/pii.js';
import { devbuildText } from './core/devbuild.js';
import { realtimeFindings } from './core/realtime.js';
import { graphqlFindings } from './core/graphql.js';
import { frameworkHints, viteManifest } from './core/frameworks.js';
import { wellKnownFile, isWellKnown, mobileHints } from './core/wellknown.js';
import { infraFromText } from './core/infra.js';
import { extraHeaderFindings } from './core/headers2.js';
import { browserFindings } from './core/browser.js';
import { web3Findings } from './core/web3.js';
import { obfuscationScore, OBF_LABEL } from './core/obfuscation.js';
import { badMatch, pnpmPackage } from './core/supply.js';
import { codeFindings, CODE_WHY } from './core/code.js';
import { openApiEndpoints } from './core/openapi.js';
import { matchAdvisories, osvLink } from './core/advisories.js';
export { codeFindings } from './core/code.js';
export { openApiEndpoints } from './core/openapi.js';
export { matchAdvisories, osvLink, osvQuery, npmName } from './core/advisories.js';
export { DEFAULT_DENY, FETCHABLE, makeScope, blockedReason, siteOf, clampSettings } from './core/scope.js';
export const VERSION = '1.0.0';
export const LEVELS = ['info', 'low', 'medium', 'high', 'critical'];
const CONF = { low: 0, medium: 1, high: 2 };
const MAX_TEXT = 8e6;
const MAP_BUDGET = 12e6; // bytes of source-map sources to analyze per map
const TEXT_BUDGET = 25e6; // chars of file text kept for the file browser

export function fnv(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return ('0000000' + h.toString(16)).slice(-8); }
export function entropy(s) { const m = {}; let e = 0; for (const c of s) m[c] = (m[c] || 0) + 1; for (const k in m) { const p = m[k] / s.length; e -= p * Math.log2(p); } return e; }
export function hostOf(u) { try { return new URL(u).host; } catch (e) { return ''; } }
const uniq = (a) => Array.from(new Set(a));
function b64d(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
  const bin = atob(s);
  try { return decodeURIComponent(escape(bin)); } catch (e) { return bin; }
}
// A value part cut at the fragment edge (>= 6 chars) is replaced with «…»
// PEM private key body: up to the END line or the end of the fragment
const PEM_BODY = /(-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----)(?:(?!-----END)[\s\S])*(?:-----END[ A-Z0-9_-]{0,100}-----)?/g;
const PEM_TAIL = /^(?:(?!-----BEGIN)[\s\S])*?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/;
export function maskEdges(str, raws) {
  for (const v of raws) {
    for (let k = Math.min(v.length - 1, str.length); k >= 6; k--) if (str.startsWith(v.slice(-k))) { str = '…' + str.slice(k); break; }
    for (let k = Math.min(v.length - 1, str.length); k >= 6; k--) if (str.endsWith(v.slice(0, k))) { str = str.slice(0, -k) + '…'; break; }
  }
  return str;
}
export function mask(s) { return s.length <= 24 ? '**** (' + s.length + ')' : s.slice(0, 4) + '…' + s.slice(-2) + ' (' + s.length + ')'; }
function snippetAt(text, pos, len) { return text.slice(Math.max(0, pos - 70), Math.min(text.length, pos + len + 70)).replace(/\s+/g, ' ').trim(); }
export function lineIndex(text) {
  const nl = []; let i = -1;
  while ((i = text.indexOf('\n', i + 1)) !== -1) nl.push(i);
  return (pos) => {
    let lo = 0, hi = nl.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (nl[mid] < pos) lo = mid + 1; else hi = mid; }
    return { line: lo + 1, col: pos - (lo ? nl[lo - 1] + 1 : 0) + 1 };
  };
}

const RE_PATH = /(["'])((?:https?:|wss?:)?[/][/][^\s"'`<>\\]+|[/][A-Za-z0-9_.~%?&=#:@+,;{}$\-/\[\]]*)\1/g;
const RE_TPL = /`((?:(?:https?:|wss?:)?[/][/]|[/]|\$\{[^}]{1,60}\}[/])[^`\n]{0,300})`/g;
// TypeScript generics (http.get<T>(...)) and Angular httpClient count as calls too
const RE_CALL = /\b(?:fetch|axios(?:\.(get|post|put|patch|delete|head|options|request))?|(?:\$|jQuery)\.(get|post|getJSON|ajax)|(?:http|https|httpClient|api|client|request|ky|got|instance|service)\.(get|post|put|patch|delete))(?:<[^<>()\n]{0,120}>)?\(\s*(["'`])([^"'`\n]{1,400})\4/g;
const RE_REQ_FORM = /\b(?:http|https|httpClient|api|client|instance|service)\.request(?:<[^<>()\n]{0,120}>)?\(\s*(["'`])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,\s*(["'`])([^"'`\n]{1,400})\3/g;
const RE_AXIOS_OBJ = /\baxios\s*\(\s*\{/g;
// shortcut: instance names in minified bundles are renamed and not tracked; source maps help
const RE_INST = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:axios|ky|got)(?:\.create|\.extend)\(/g;
const RE_XHR = /\.open\(\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'`]\s*,\s*(["'`])([^"'`\n]{1,400})\2/gi;
const RE_URLPROP = /\burl\s*:\s*(["'`])((?:https?:|wss?:)?[/][^"'`\n]{1,400})\1/g;
const RE_WS = /new\s+(?:WebSocket|EventSource)\(\s*(["'`])([^"'`\n]+)\1/g;
const RE_IMPORT = /\bimport\(\s*(["'`])([^"'`\n]+\.m?js[^"'`\n]*)\1\s*\)/g;
const RE_FROM = /\b(?:from|import)\s*(["'])([^"'\n]+\.m?js[^"'\n]*)\1/g;
const RE_REL_JS = /(["'`])((?:\.{1,2}\/|\/)[\w@.\/~-]+\.m?js)(?:\?[\w=&.-]*)?\1/g;
const RE_STATIC_REL = /(["'`])((?:static|assets|_next|_nuxt|build|dist|js|chunks?)\/[\w@.\/~%-]+\.m?js)\1/g;
// API spec file mentioned in code: can be downloaded and parsed
const RE_OPENAPI = /(["'`])((?:\.{0,2}\/)?[\w@.\/~-]*(?:openapi|swagger|api-docs)[\w.-]*\.(?:json|ya?ml))\1/gi;
const RE_SRCMAP = /[#@]\s*sourceMappingURL\s*=\s*([^\s'"`*]+)/g;
const RE_CHUNKMAP = /\{\s*((?:["']?[\w$-]+["']?\s*:\s*["'][0-9a-f]{6,20}["']\s*(?:,\s*)?){3,})\}\s*\[\s*[\w$]+\s*\]\s*\+\s*(["'`])(\.[\w.]*js)\2/g;
const STATIC_EXT = /\.(?:png|jpe?g|gif|svg|webp|avif|ico|bmp|css|scss|less|woff2?|ttf|eot|otf|mp[34]|webm|ogg|wav|m?js|wasm)(?:$|[?#])/i;
const API_LIKE = /(?:^|[/])(?:api|rest|rpc|graphql|gql|ajax|services?|backend)(?:[/]|$)|[/]v\d+(?:[/]|$)|[.]json(?:$|[?#])/i;
const BASE_VAR = /base|url|host|origin|api|root|endpoint|server|domain|path/i;
const NOISE_HOST = /^(?:https?:)?\/\/(?:www\.)?(?:w3\.org|schema\.org|json-schema\.org|ogp\.me|xmlsoap\.org|purl\.org|reactjs\.org|fb\.me|mozilla\.org|npmjs\.com|apache\.org\/licenses|github\.com\/(?:facebook|reactjs))/i;
function isNoise(p, via) {
  if (p.length < 3 || !/[A-Za-z0-9]/.test(p)) return true;
  if (via !== 'call' && (/^[/][gimsuy]{2,}$/.test(p) || /^[/][gimsuyd]$/.test(p) && p !== '/d')) return true; // regex flags: "/gi"; for a fetch("/i") call it is a path
  if (/^(?:application|text|image|audio|video|font|multipart|model)\/[\w.+*-]+$/i.test(p)) return true;
  if (/^\d{4}-\d\d-\d\d|^\d\d?:\d\d/.test(p)) return true;
  return NOISE_HOST.test(p);
}
export function tplToPath(s) {
  // Param name is the last identifier (a.b.c -> c); expressions with operators, quotes, and short names become {param}
  return s.replace(/\$\{([^}]*)\}/g, (_, e) => { if (/[-+*/?:'"`()[\]|&<>=!]/.test(e.trim())) return '{param}'; const ids = e.match(/[A-Za-z_$][\w$]*/g), id = ids && ids[ids.length - 1]; return '{' + (id && id.length >= 2 ? id : 'param') + '}'; });
}
function argTail(text, from) {
  let d = 1, q = null; const lim = Math.min(text.length, from + 600);
  for (let i = from; i < lim; i++) {
    const c = text[i];
    if (q) { if (c === '\\') i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === '`') q = c;
    else if (c === '(' || c === '[' || c === '{') d++;
    else if (c === ')' || c === ']' || c === '}') { d--; if (d === 0) return text.slice(from, i); }
  }
  return text.slice(from, lim);
}
function expandConcat(text, end, url) {
  for (let i = 0; i < 4; i++) {
    const t = text.slice(end, end + 80);
    const a = /^\s*\+\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)(?![\w$(])/.exec(t);
    if (a) { url += '{' + a[1].split('.').pop() + '}'; end += a[0].length; continue; }
    const b = /^\s*\+\s*(["'])([^"'\n]{0,120})\1/.exec(t);
    if (b) { url += b[2]; end += b[0].length; continue; }
    break;
  }
  return url;
}
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function normSeg(s) {
  if (/^\d+$/.test(s)) return '{id}';
  if (UUID_RE.test(s)) return '{uuid}';
  if (/^[0-9a-f]{16,}$/i.test(s)) return '{hash}';
  if (/^:[A-Za-z_]\w*$/.test(s)) return '{' + s.slice(1) + '}';
  return s;
}
export function splitUrl(p) {
  p = p.replace(/#.*$/, '');
  let q = ''; const i = p.indexOf('?');
  if (i >= 0) { q = p.slice(i + 1); p = p.slice(0, i); }
  let origin = ''; const m = /^((?:https?:|wss?:)?\/\/[^\/?#]+)(.*)$/i.exec(p);
  if (m) { origin = m[1]; p = m[2] || '/'; }
  const params = [];
  q.split('&').forEach((kv) => { const n = kv.split('=')[0]; if (n && /^[A-Za-z_$][\w$.\[\]-]{0,60}$/.test(n)) params.push(n); });
  return { origin, path: p.split('/').map(normSeg).join('/'), params: uniq(params) };
}

export const RULES = [
  { re: /[/](?:api[/])?admin(?:[/][^/?#]|[?])/i, cat: 'admin', sev: 3, owasp: 'API5', why: 'Admin functions' },
  { re: /[/]actuator(?:[/]|$)/i, cat: 'debug', sev: 3, owasp: 'API8', why: 'Spring Actuator endpoint' },
  { re: /[/](?:debug|pprof|console|phpinfo)(?:[/.?]|$)/i, cat: 'debug', sev: 3, owasp: 'API8', why: 'Debug interface' },
  { re: /[.](?:env|git|bak|sql)(?:[/]|$|[?])/i, cat: 'files', sev: 3, owasp: 'API8', why: 'Config or backup file' },
  { re: /(?:swagger|openapi|api-docs|graphql|graphiql|redoc)/i, cat: 'docs', sev: 2, owasp: 'API9', why: 'API documentation' },
  { re: /[.]map(?:$|[?#])/i, cat: 'map', sev: 2, owasp: 'API8', why: 'Source map: original sources' },
  { re: /[/]internal(?:[/]|$)|[/][/](?:dev|stage|staging|internal|qa|uat)[.-]/i, cat: 'internal', sev: 2, owasp: 'API9', why: 'Internal or non-prod resource' },
  { re: /[/][{:][a-z_]*id[}]?(?:[/]|$)|[?&]id=/i, cat: 'object', sev: 2, owasp: 'API1', why: 'Object ID: check for BOLA/IDOR' },
  // v1 is deliberately not treated as old: it is usually the current version
  { re: /[/](?:v0|beta|old|legacy|deprecated)(?:[/]|$)/i, cat: 'version', sev: 1, owasp: 'API9', why: 'Old or test API version' },
  { re: /[/](?:login|oauth2?|tokens?|reset(?:-password)?|signin|signup|register|password)(?:[/?#.]|$)/i, cat: 'auth', sev: 1, owasp: 'API2', why: 'Authentication' }
];
const setOf = (s) => new Set(s.split(','));
const PARAM_SSRF = setOf('url,uri,redirect,redirecturl,redirecturi,returnurl,returnto,next,callback,callbackurl,dest,destination,file,filename,path,target,src,link,host,domain,image,imageurl,proxy');
const PARAM_PRIV = setOf('role,roles,isadmin,admin,permissions,permission,scope,price,balance,isstaff,issuperuser');
const PARAM_OBJ = setOf('userid,ownerid,accountid,orgid,tenantid,groupid,customerid');
const KIND_BY_CAT = { admin: 'debug', debug: 'debug', files: 'debug', internal: 'debug', docs: 'docs', map: 'docs', auth: 'auth' };
const paramKey = (p) => p.toLowerCase().replace(/[^a-z0-9]/g, '');
function paramRisk(p) {
  const k = paramKey(p);
  if (PARAM_SSRF.has(k)) return { owasp: 'API7', why: 'Parameter "' + p + '": SSRF, open redirect, LFI', tag: 'SSRF' };
  if (PARAM_PRIV.has(k)) return { owasp: 'API3', why: 'Parameter "' + p + '": mass assignment', tag: 'mass assignment' };
  if (PARAM_OBJ.has(k)) return { owasp: 'API1', why: 'Parameter "' + p + '": object ID, BOLA', tag: 'BOLA' };
  return null;
}
function kindOf(f, hits) {
  if (/^wss?:/i.test(f.resolved || '') || f.vias.includes('ws')) return 'ws';
  if (STATIC_EXT.test(f.url)) return 'static';
  const found = {};
  hits.forEach((h) => { const k = KIND_BY_CAT[h.cat]; if (k) found[k] = 1; });
  if (f.host && f.pageHost && f.host !== f.pageHost && !found.debug && !found.docs) return 'external';
  for (const k of ['debug', 'docs', 'auth']) if (found[k]) return k;
  if (API_LIKE.test(f.url) || f.vias.includes('call') || f.vias.includes('observed') || (f.method !== '?' && f.method !== '-')) return 'api';
  return 'page';
}
function rescore(f) {
  // Path without query goes last: rules like "(?:[/]|$)" must see the end of the path
  const test = (f.resolved || '') + ' ' + f.url + ' ' + f.path;
  const hits = RULES.filter((r) => r.re.test(test));
  f.params.forEach((p) => { const r = paramRisk(p); if (r) hits.push({ cat: 'param', sev: 2, owasp: r.owasp, why: r.why }); });
  f.kind = kindOf(f, hits);
  // Params of a foreign host are not site surface: param names do not raise risk
  if (f.kind === 'external') for (let i = hits.length - 1; i >= 0; i--) if (hits[i].cat === 'param') hits.splice(i, 1);
  let R = 0;
  hits.forEach((h) => { R = Math.max(R, h.sev); });
  const mut = /^(?:POST|PUT|PATCH|DELETE)$/.test(f.method);
  if (f.kind === 'static') { R = 0; hits.length = 0; }
  else {
    if (mut) R += 1;
    if (f.host && f.pageHost && f.host !== f.pageHost) R = Math.max(R - 1, 0);
  }
  f.risk = Math.min(R, 4); f.level = LEVELS[f.risk];
  f.why = uniq(hits.map((h) => h.why)); f.owasp = uniq(hits.map((h) => h.owasp)).sort(); f.cats = uniq(hits.map((h) => h.cat));
  f.priority = f.risk >= 3 && CONF[f.confidence] >= 1;
}

const WEAK_PH = /example|xxxx|0{8,}|1{8,}|dummy|placeholder|changeme/i;
const PH = /example|your[_-]?(?:api|key|token|secret|access)|xxxx|changeme|change[_-]me|dummy|sample|placeholder|redacted|insert[_-]|<[^>]+>|\{\{|\$\{|\*{4,}|\b(?:test|demo|fake|lorem)\b/i;
const NAME_SKIP = /(?:type|url|uri|label|placeholder|name|field|text|length|regex|pattern|header|endpoint|path|expir\w*|storage|prefix|cookie|param|input|message|error|status)$/i;
// Patterns checked against gitleaks (config/gitleaks.toml), simplified for JS.
export const SECRET_PATTERNS = [
  { id: 'aws-akid', label: 'AWS Access Key ID', re: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b/g, conf: 'high', risk: 4, why: 'AWS key: check the owner and permissions' },
  { id: 'google-api', label: 'Google API key', re: /\bAIza[\w-]{35}(?![\w-])/g, conf: 'medium', risk: 2, why: 'Google keys are often public: check the key restrictions' },
  { id: 'github', label: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, conf: 'high', risk: 4, why: 'GitHub token' },
  { id: 'github-pat', label: 'GitHub fine-grained token', re: /\bgithub_pat_\w{82}\b/g, conf: 'high', risk: 4, why: 'GitHub token' },
  { id: 'stripe', label: 'Stripe secret key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{10,99}\b/g, conf: 'high', risk: 4, why: 'Stripe secret key (live)' },
  { id: 'slack', label: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, conf: 'high', risk: 3, why: 'Slack token' },
  { id: 'slack-hook', label: 'Slack webhook', re: /\bhooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/]{43,56}/g, conf: 'high', risk: 3, why: 'Slack webhook: can post to a channel' },
  { id: 'sendgrid', label: 'SendGrid API key', re: /\bSG\.[\w-]{22}\.[\w-]{43}(?![\w-])/g, conf: 'high', risk: 3, why: 'SendGrid key' },
  { id: 'twilio', label: 'Twilio API key SID', re: /\bSK[0-9a-f]{32}\b/g, conf: 'low', risk: 1, why: 'Looks like a Twilio key, often a false positive' },
  { id: 'mailgun', label: 'Mailgun key', re: /\bkey-[0-9a-f]{32}\b/g, conf: 'medium', risk: 3, why: 'Mailgun key' },
  { id: 'npm', label: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g, conf: 'high', risk: 4, why: 'npm token: can publish packages' },
  { id: 'shopify', label: 'Shopify access token', re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g, conf: 'high', risk: 4, why: 'Shopify access token' },
  { id: 'square', label: 'Square access token', re: /\b(?:EAAA[\w-]{60}|sq0atp-[\w-]{22})\b/g, conf: 'medium', risk: 3, why: 'Square access token' },
  { id: 'anthropic', label: 'Anthropic API key', re: /\bsk-ant-(?:api|admin)\d\d-[\w-]{80,}/g, conf: 'high', risk: 4, why: 'Anthropic API key: paid API access' },
  { id: 'openai', label: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}T3BlbkFJ[A-Za-z0-9_-]{20,200}\b|\bsk-proj-[A-Za-z0-9_-]{80,}/g, conf: 'high', risk: 4, why: 'OpenAI API key: paid API access' },
  { id: 'gitlab', label: 'GitLab token', re: /\bglpat-[\w-]{20}(?![\w-])/g, conf: 'high', risk: 4, why: 'GitLab token' },
  { id: 'telegram', label: 'Telegram bot token', re: /\b\d{8,10}:AA[\w-]{33}\b/g, conf: 'high', risk: 3, why: 'Telegram bot token: full control of the bot' },
  { id: 'discord-hook', label: 'Discord webhook', re: /\bdiscord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[\w-]{60,70}/g, conf: 'high', risk: 3, why: 'Discord webhook: can post to a channel' },
  { id: 'braintree', label: 'Braintree access token', re: /\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b/g, conf: 'high', risk: 4, why: 'Braintree production token: payment API access' },
  { id: 'facebook', label: 'Facebook access token', re: /\bEAA(?:B|C|G|I)[0-9A-Za-z]{80,}\b/g, conf: 'medium', risk: 3, why: 'Facebook access token' },
  { id: 'mailchimp', label: 'Mailchimp API key', re: /\b[0-9a-f]{32}-us\d{1,2}\b/g, conf: 'high', risk: 3, why: 'Mailchimp API key' },
  { id: 'auth-header', label: 'Hardcoded Authorization header', re: /["'`](?:Basic|Bearer)\s+[A-Za-z0-9._~+/=-]{20,}["'`]/g, conf: 'medium', risk: 3, why: 'Authorization value written into the code: check whose account it is' },
  { id: 'private-key', label: 'Private key', re: /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/g, conf: 'high', risk: 4, why: 'Private key in code', noMask: true },
  { id: 'url-cred', label: 'Login and password in URL', re: /\bhttps?:\/\/[^\s:@\/"'`$]{1,64}:[^\s:@\/"'`$]{3,64}@[a-z0-9.-]+/gi, conf: 'high', risk: 3, why: 'Credentials inside a URL' },
  // Keys public by design (pub): finding stays but with low risk
  { id: 'stripe-pub', label: 'Stripe publishable key', re: /\bpk_live_[A-Za-z0-9]{10,99}\b/g, conf: 'high', risk: 1, pub: true, why: 'Public by design: check which account it belongs to' },
  { id: 'stripe-test', label: 'Stripe test secret key', re: /\b(?:sk|rk)_test_[A-Za-z0-9]{10,99}\b/g, conf: 'high', risk: 2, why: 'Stripe test-mode secret key: no real money, but test data and settings' },
  { id: 'mapbox-pub', label: 'Mapbox public token', re: /(?:^|[^\w-])(pk\.eyJ[\w-]{8,}\.[\w-]{8,}(?:\.[\w-]*)?)/g, g: 1, conf: 'high', risk: 1, pub: true, why: 'Public by design: check the allowed URLs of the token' },
  { id: 'mapbox-temp', label: 'Mapbox temporary token', re: /(?:^|[^\w-])(tk\.eyJ[\w-]{8,}\.[\w-]{8,}(?:\.[\w-]*)?)/g, g: 1, conf: 'medium', risk: 2, why: 'Mapbox temporary token: check its scopes and expiry' },
  { id: 'mapbox-secret', label: 'Mapbox secret token', re: /(?:^|[^\w-])(sk\.eyJ[\w-]{8,}\.[\w-]{8,}(?:\.[\w-]*)?)/g, g: 1, conf: 'high', risk: 4, why: 'Mapbox secret token: must never be in the browser' },
  { id: 'supabase-pub', label: 'Supabase publishable key', re: /\bsb_publishable_[A-Za-z0-9_-]{20,}/g, conf: 'high', risk: 1, pub: true, why: 'Supabase anon key: public by design, check row-level security' },
  { id: 'supabase-secret', label: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g, conf: 'high', risk: 4, why: 'Supabase service_role key: full database access, bypasses row-level security' },
  { id: 'sentry-dsn', label: 'Sentry DSN', re: /https:\/\/[0-9a-f]{32}@[\w.-]+\.sentry\.io\/\d+/g, conf: 'high', risk: 0, pub: true, noMask: true, why: 'Public by design: lets anyone send events to the project' },
  { id: 'ld-sdk', label: 'LaunchDarkly server SDK key', re: /\bsdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g, conf: 'medium', risk: 3, why: 'Server-side key: reads all flags and rules of the environment' },
  { id: 'ld-mobile', label: 'LaunchDarkly mobile key', re: /\bmob-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g, conf: 'medium', risk: 1, pub: true, why: 'Public by design: check which account it belongs to' },
  { id: 'posthog-pub', label: 'PostHog project key', re: /\bphc_[A-Za-z0-9]{32,}/g, conf: 'low', risk: 0, pub: true, why: 'Public by design: check which account it belongs to' },
  { id: 'posthog-personal', label: 'PostHog personal API key', re: /\bphx_[A-Za-z0-9]{32,}/g, conf: 'medium', risk: 4, why: 'Personal API key: reads analytics data of the owner' },
  // New formats (checked against vendor docs; Mistral, DeepSeek, Pinecone pckey_ have no source, do not add)
  { id: 'huggingface', label: 'Hugging Face token', re: /\bhf_[A-Za-z]{34}(?![A-Za-z0-9])/g, conf: 'medium', risk: 4, why: 'Hugging Face access token: can read or write repos you can access' },
  { id: 'huggingface-org', label: 'Hugging Face organization token', re: /\bapi_org_[A-Za-z0-9]{20,}\b/g, conf: 'low', risk: 3, why: 'Paid API access: check the owner' },
  { id: 'perplexity', label: 'Perplexity API key', re: /\bpplx-[A-Za-z0-9]{48}(?![A-Za-z0-9])/g, conf: 'medium', risk: 4, why: 'Paid API access: check the owner' },
  { id: 'groq', label: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}\b/g, conf: 'low', risk: 4, why: 'Paid API access: check the owner' },
  { id: 'xai', label: 'xAI API key', re: /\bxai-[A-Za-z0-9]{80}(?![A-Za-z0-9])/g, conf: 'low', risk: 4, why: 'Paid API access: check the owner' },
  { id: 'bedrock-long', label: 'AWS Bedrock long-term API key', re: /\bABSK[A-Za-z0-9+/]{109,269}={0,2}/g, conf: 'medium', risk: 4, why: 'AWS Bedrock key: tied to an IAM user, check permissions and expiry' },
  { id: 'bedrock-short', label: 'AWS Bedrock short-term API key', re: /\bbedrock-api-key-[A-Za-z0-9+/=]{20,}/g, conf: 'medium', risk: 3, why: 'AWS Bedrock key: tied to an IAM user, check permissions and expiry' },
  { id: 'pinecone', label: 'Pinecone API key', re: /\bpcsk_[A-Za-z0-9]{4,}_[A-Za-z0-9]{40,}\b/g, conf: 'medium', risk: 4, why: 'Pinecone API key: full index access' },
  { id: 'doppler', label: 'Doppler token', re: /\bdp\.(?:st|pt|ct)\.(?:[a-z0-9_-]{2,35}\.)?[A-Za-z0-9]{40,44}\b/g, conf: 'medium', risk: 4, why: 'Secrets manager token: read access to stored secrets' },
  { id: 'pulumi', label: 'Pulumi access token', re: /\bpul-[a-f0-9]{40}\b/g, conf: 'low', risk: 4, why: 'Infrastructure control: check the owner and scope' },
  { id: 'gitlab-new', label: 'GitLab token', re: /\bgl(?:dt|rt|ft|cbt|oas)-[\w-]{20,}/g, conf: 'medium', risk: 3, why: 'GitLab token' },
  { id: 'slack-xapp', label: 'Slack token', re: /\bxapp-\d-[\w-]{20,}/g, conf: 'low', risk: 3, why: 'Slack token' },
  { id: 'slack-xoxe', label: 'Slack token', re: /\bxoxe-\d-[\w-]{20,}/g, conf: 'medium', risk: 4, why: 'Slack refresh token: can mint new tokens' },
  { id: 'sentry-token', label: 'Sentry auth token', re: /\bsntryu_[a-f0-9]{64}\b|\bsntrys_[A-Za-z0-9+/=]+_[A-Za-z0-9+/]{43}/g, conf: 'high', risk: 4, why: 'Sentry auth token: reads projects and events' },
  { id: 'linear', label: 'Linear API key', re: /\blin_api_[A-Za-z0-9]{40}(?![A-Za-z0-9])/g, conf: 'medium', risk: 4, why: 'Reads and writes the owner\'s workspace' },
  // 2026 formats: Vercel (the _ form appears in third-party sources, so conf low), Cloudflare (checksum not published, not verified)
  { id: 'vercel', label: 'Vercel token', re: /\bvc[pciark]_[A-Za-z0-9]{20,}\b/g, conf: 'low', risk: 4, why: 'Vercel token: access to projects and deployments, check its type' },
  { id: 'cloudflare-token', label: 'Cloudflare API token', re: /\bcf(?:k|ut|at|ast)_[A-Za-z0-9]{46,48}\b/g, conf: 'medium', risk: 4, why: 'Cloudflare token: check its permissions' },
  // Prefixes from gitleaks rules
  { id: 'digitalocean', label: 'DigitalOcean token', re: /\bdo[opr]_v1_[a-f0-9]{64}\b/g, conf: 'high', risk: 4, why: 'Access token: check the owner and scope' },
  { id: 'newrelic', label: 'New Relic API key', re: /\bNRAK-[a-z0-9]{27}\b/gi, conf: 'high', risk: 3, why: 'Access token: check the owner and scope' },
  { id: 'postman', label: 'Postman API key', re: /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/gi, conf: 'high', risk: 3, why: 'Access token: check the owner and scope' },
  { id: 'pypi', label: 'PyPI upload token', re: /\bpypi-AgEIcHlwaS5vcmc[\w-]{50,}/g, conf: 'high', risk: 4, why: 'npm token: can publish packages' },
  { id: 'brevo', label: 'Brevo (Sendinblue) API key', re: /\bxkeysib-[a-f0-9]{64}-[a-z0-9]{16}\b/g, conf: 'high', risk: 3, why: 'Access token: check the owner and scope' },
  { id: 'shippo', label: 'Shippo live token', re: /\bshippo_live_[a-f0-9]{40}\b/g, conf: 'high', risk: 3, why: 'Access token: check the owner and scope' },
  { id: 'vault', label: 'HashiCorp Vault token', re: /\bhvs\.[\w-]{90,120}/g, conf: 'high', risk: 4, why: 'Secrets manager token: read access to stored secrets' },
  { id: 'planetscale', label: 'PlanetScale password', re: /\bpscale_pw_[\w.-]{32,64}/g, conf: 'high', risk: 4, why: 'Access token: check the owner and scope' },
  { id: 'prefect', label: 'Prefect API key', re: /\bpnu_[a-zA-Z0-9]{36}\b/g, conf: 'high', risk: 3, why: 'Access token: check the owner and scope' },
  { id: 'dropbox', label: 'Dropbox access token', re: /\bsl\.[\w-]{130,152}/g, conf: 'medium', risk: 4, why: 'Access token: check the owner and scope' },
  { id: 'flyio', label: 'Fly.io token', re: /\bfo1_[\w-]{43}\b/g, conf: 'high', risk: 4, why: 'Infrastructure control: check the owner and scope' },
  { id: 'notion', label: 'Notion token', re: /\bntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}\b/g, conf: 'high', risk: 4, why: 'Reads and writes the owner\'s workspace' },
  { id: 'grafana', label: 'Grafana Cloud token', re: /\bglc_[A-Za-z0-9+/]{32,400}={0,2}/g, conf: 'medium', risk: 3, why: 'Access token: check the owner and scope' },
  { id: 'heroku', label: 'Heroku API key', re: /\bHRKU-AA[0-9a-zA-Z_-]{58}\b/g, conf: 'high', risk: 4, why: 'Infrastructure control: check the owner and scope' },
  { id: 'age', label: 'age secret key', re: /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b/g, conf: 'high', risk: 4, why: 'Private key in code' },
  { id: 'teams-hook', label: 'Microsoft Teams webhook', re: /https:\/\/[a-z0-9-]+\.webhook\.office\.com\/webhookb2\/[a-z0-9-]{36}@[a-z0-9-]{36}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9-]{36}/gi, conf: 'high', risk: 3, why: 'Discord webhook: can post to a channel' },
  { id: 'gitlab-ptt', label: 'GitLab token', re: /\bglptt-[a-f0-9]{40}\b/g, conf: 'high', risk: 3, why: 'GitLab token' },
  { id: 'yandex', label: 'Yandex Cloud key', re: /\bAQVN[A-Za-z0-9_-]{35,38}\b/g, conf: 'low', risk: 3, why: 'Access token: check the owner and scope' },
  { id: 'azure-ad', label: 'Azure AD client secret', re: /\b[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}(?![a-zA-Z0-9_~.-])/g, conf: 'low', risk: 4, why: 'Access token: check the owner and scope' },
  { id: 'jwt', label: 'JWT', re: /(?:^|[^\w-])(eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*)/g, g: 1, conf: 'medium', risk: 2, why: 'JWT, signature not verified' }
];
const RE_GENERIC = /(["']?)([\w.-]{0,40}(?:api[_-]?key|apikey|secret|passw(?:or)?d|passwd|token|auth[_-]?key|client[_-]?secret|private[_-]?key|access[_-]?key)[\w.-]{0,20})\1\s*[:=]\s*(["'`])([^"'`\s]{8,200})\3/gi;
export function jwtInfo(tok) {
  try {
    const p = tok.split('.'), hd = JSON.parse(b64d(p[0])), pl = JSON.parse(b64d(p[1]));
    if (!hd || !hd.alg) return null;
    const why = ['alg=' + hd.alg]; let risk = 2;
    if (/^none$/i.test(hd.alg)) { why.push('alg=none: unsigned token'); risk = 3; }
    let dead = false;
    if (pl.exp && !(Number.isFinite(+pl.exp) && !isNaN(new Date(pl.exp * 1000)))) why.push('exp not a valid time'); // a strange exp must not drop the token
    else if (pl.exp) { const d = new Date(pl.exp * 1000); dead = d < new Date(); why.push('exp ' + d.toISOString().slice(0, 10) + (dead ? ', expired' : ', valid')); if (dead) risk = 1; }
    else why.push('no exp: never expires');
    // long lifetime, remote key in header, kid
    if (pl.exp && !dead) { const life = pl.iat ? pl.exp - pl.iat : pl.exp - Date.now() / 1000; if (life > (pl.iat ? 30 : 365) * 86400) { why.push(pl.iat ? 'lifetime ' + Math.round(life / 86400) + ' days' : 'expires more than a year ahead'); risk = Math.max(risk, 2); } }
    if (hd.jku || hd.x5u) why.push('remote key URL in header: ' + String(hd.jku || hd.x5u).slice(0, 120));
    if (hd.kid != null) why.push('kid: ' + String(hd.kid).slice(0, 40));
    if (/^HS/.test(hd.alg)) why.push('symmetric token: a secret in the page may verify it');
    const roles = Object.keys(pl).filter((k) => /^(?:roles?|is_?admin|admin|scope|permissions|groups)$/i.test(k));
    if (roles.length) why.push('roles in token: ' + roles.join(', '));
    // Supabase: anon key is public by design, service_role gives full DB access bypassing RLS
    if (pl.role === 'service_role') { why.unshift('Supabase service_role key: full database access, bypasses row-level security'); if (!dead) risk = 4; }
    else if (pl.role === 'anon' && /supabase/i.test(String(pl.iss || '') + String(pl.ref || ''))) { why.unshift('Supabase anon key: public by design, check row-level security'); risk = Math.min(risk, 1); }
    why.push('claims: ' + Object.keys(pl).slice(0, 12).join(', '));
    return { risk, why };
  } catch (e) { return null; }
}
// AIza key: next to a Firebase config it is public; next to Gemini it may have access to a paid model (2026)
function googleKey(near) {
  if (/generativelanguage\.googleapis|gemini/i.test(near)) return { risk: 3, why: ['Google API key near Gemini API calls: the key may reach Gemini; check its API restrictions'] };
  if (/firebase|authDomain|storageBucket|messagingSenderId/.test(near)) return { label: 'Firebase Web API key', risk: 1, publicKey: true, why: ['Public by design: check the key restrictions and Firebase security rules'] };
  return null;
}
// By name: keys without a prefix are recognized only by variable name
const NAMED = [
  { id: 'algolia-admin', label: 'Algolia admin key', re: /\badmin[_-]?(?:api)?[_-]?key["']?\s*[:=]\s*["']([0-9a-f]{32})["']/gi, conf: 'medium', risk: 4, why: 'Admin key: changes and deletes the search index' },
  { id: 'algolia-search', label: 'Algolia search key', re: /\bsearch[_-]?(?:api)?[_-]?key["']?\s*[:=]\s*["']([0-9a-f]{32})["']/gi, conf: 'medium', risk: 1, pub: true, why: 'Public by design: check which indexes it can read' },
  { id: 'walletconnect', label: 'WalletConnect project ID', re: /(?:walletconnect|wc)[_-]?project[_-]?id["']?\s*[:=]\s*["']([0-9a-f]{32})["']/gi, conf: 'medium', risk: 0, pub: true, why: 'Public by design: check the allowed origins of the project' },
  { id: 'rpc-infura', label: 'Infura RPC key', re: /\bhttps?:\/\/[a-z0-9-]{1,30}\.infura\.io\/v3\/([A-Za-z0-9]{20,64})\b/g, conf: 'medium', risk: 1, why: 'RPC key in client code: check the provider dashboard for a domain allowlist' },
  { id: 'rpc-alchemy', label: 'Alchemy RPC key', re: /\bhttps?:\/\/[a-z0-9-]{1,40}\.g\.alchemy\.com\/v2\/([A-Za-z0-9_-]{20,64})/g, conf: 'medium', risk: 1, why: 'RPC key in client code: check the provider dashboard for a domain allowlist' },
  { id: 'rpc-quicknode', label: 'QuickNode RPC token', re: /\bhttps?:\/\/[a-z0-9-]{1,60}\.quiknode\.pro\/([A-Za-z0-9_-]{20,128})/g, conf: 'medium', risk: 1, why: 'RPC key in client code: check the provider dashboard for a domain allowlist' },
  { id: 'sentry-legacy', label: 'Sentry auth token', re: /\bSENTRY_AUTH_TOKEN["']?\s*[:=]\s*["']([a-f0-9]{32,64})["']/gi, conf: 'medium', risk: 3, why: 'Sentry auth token: reads projects and events' }
];
export function scanSecrets(text, src, pos) {
  pos = pos || lineIndex(text);
  const out = [], seen = new Set();
  function push(p, raw, start, extra) {
    const k = p.id + raw; if (seen.has(k)) return; seen.add(k);
    const ps = pos(start);
    out.push(Object.assign({ type: p.id, label: p.label, raw, confidence: p.conf, risk: p.risk, why: [p.why], noMask: !!p.noMask, publicKey: !!p.pub, file: src, line: ps.line, col: ps.col, snippetRaw: snippetAt(text, start, raw.length) }, extra));
  }
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0; let m;
    while ((m = p.re.exec(text))) {
      // g: value is in the capture group, and the word boundary is eaten by the prefix (no lookbehind, no quadratic scan)
      const raw = p.g ? m[p.g] : m[0], at = m.index + m[0].length - raw.length;
      if (WEAK_PH.test(raw) || (p.id !== 'jwt' && !p.noMask && PH.test(raw))) continue; // placeholders like YOUR_, example, ${…}
      if (p.id === 'private-key' && !/-----END/.test(text.slice(at, at + 8000))) continue;
      if (p.id === 'mailgun' && !/mailgun|api\.eu\.|messages/i.test(text.slice(Math.max(0, at - 300), at + 300))) continue; // key-<md5> is often just a cache key; a lone BEGIN line in code is a format check, not a key
      let extra = null;
      if (p.id === 'jwt') { extra = jwtInfo(raw); if (!extra) continue; extra.why.unshift(p.why); }
      if (p.id === 'google-api') extra = googleKey(text.slice(Math.max(0, at - 400), at + 400));
      push(p, raw, at, extra);
    }
  }
  for (const p of NAMED) { p.re.lastIndex = 0; let m; while ((m = p.re.exec(text))) if (!WEAK_PH.test(m[1])) push(p, m[1], m.index + m[0].indexOf(m[1])); }
  RE_GENERIC.lastIndex = 0; let g;
  // Without a keyword in the text the generic rule finds nothing: skip the expensive pass
  const gen = /api[_-]?key|apikey|secret|passw|token|auth[_-]?key|private[_-]?key|access[_-]?key/i.test(text);
  while (gen && (g = RE_GENERIC.exec(text))) {
    const name = g[2], val = g[4];
    if (val.toLowerCase() === name.toLowerCase() || NAME_SKIP.test(name) || PH.test(val) || /^(?:true|false|null|undefined)$/.test(val)) continue;
    if (/^[./]|^https?:|\$\{|\{\{/.test(val) || /^[a-z]+(?:\.[a-z]+)+$/i.test(val) || UUID_RE.test(val)) continue;
    const isPwd = /pass/i.test(name), ent = entropy(val);
    if (!isPwd && !/\d/.test(val)) continue;
    if (isPwd ? (ent < 3 || val.length < 8) : (ent < 3.5 || val.length < 16)) continue;
    const hi = ent >= 4.2 && val.length >= 20;
    if (out.some((o) => o.raw === val)) continue; // value already found by an exact rule: do not show twice
    push({ id: 'generic', label: 'Secret near "' + name + '"', conf: hi ? 'high' : 'medium', risk: hi ? 3 : 2, why: 'Name "' + name + '", entropy ' + ent.toFixed(2) }, val, g.index + g[0].indexOf(val));
  }
  return out;
}
// Lengths are bounded: without this the patterns run in quadratic time on long a-a-a-… strings
const CLOUD_LIT = { 'AWS S3': ['amazonaws.com'], 'Alibaba OSS': ['aliyuncs.com'], 'Azure App Service': ['azurewebsites.net'], 'Azure Storage': ['core.windows.net'], CloudFront: ['cloudfront.net'], 'Cloudflare R2': ['r2.dev'], 'DigitalOcean Spaces': ['digitaloceanspaces.com'],
  'Firebase Hosting': ['firebaseapp.com', 'web.app'], 'Firebase RTDB': ['firebaseio.com', 'firebasedatabase.app'], 'Google App Engine': ['appspot.com'], 'Google Cloud Storage': ['storage.googleapis.com'], Heroku: ['herokuapp.com'], 'Netlify / Vercel': ['netlify.app', 'vercel.app'] };
const CLOUD = [
  ['AWS S3', /\b[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-](?:[a-z0-9-]{1,63}\.)?amazonaws\.com\b/gi],
  ['AWS S3', /\bs3(?:[.-][a-z0-9-]{1,30})?\.amazonaws\.com\/[a-z0-9][a-z0-9._-]{2,62}/gi, true],
  ['Azure Storage', /\b[a-z0-9]{3,24}\.(?:blob|file|queue|table|dfs)\.core\.windows\.net\b/gi],
  ['Azure App Service', /\b[a-z0-9-]{1,63}\.azurewebsites\.net\b/gi],
  ['Google Cloud Storage', /\bstorage\.googleapis\.com\/[a-z0-9][a-z0-9._-]{2,62}/gi],
  ['Google App Engine', /\b[a-z0-9-]{1,63}\.appspot\.com\b/gi],
  ['Firebase RTDB', /\b[a-z0-9._-]{1,100}\.firebaseio\.com\b/gi],
  ['Firebase RTDB', /\b[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,40})?\.firebasedatabase\.app\b/gi],
  ['Firebase Hosting', /\b[a-z0-9-]{1,63}\.(?:firebaseapp\.com|web\.app)\b/gi],
  ['CloudFront', /\b[a-z0-9]{10,16}\.cloudfront\.net\b/gi],
  ['DigitalOcean Spaces', /\b[a-z0-9-]{1,63}\.[a-z0-9-]{1,63}\.digitaloceanspaces\.com\b/gi],
  ['Heroku', /\b[a-z0-9-]{1,63}\.herokuapp\.com\b/gi],
  ['Netlify / Vercel', /\b[a-z0-9-]{1,63}\.(?:netlify\.app|vercel\.app)\b/gi],
  ['Cloudflare R2', /\b[a-z0-9-]{1,63}\.r2\.dev\b/gi],
  ['Alibaba OSS', /\b[a-z0-9-]{1,63}\.oss-[a-z0-9-]{1,63}\.aliyuncs\.com\b/gi]
];
function scanClouds(text, src, pos) {
  const out = [], seen = new Set();
  const low = text.toLowerCase();
  for (const [label, re, pathStyle] of CLOUD) {
    // Quick filter: each rule needs its domain in the text, else 15 full passes per file
    if (!CLOUD_LIT[label].some((x) => low.includes(x))) continue;
    re.lastIndex = 0; let m;
    while ((m = re.exec(text))) {
      if (pathStyle && /[\w.-]/.test(text[m.index - 1] || '')) continue;
      const k = m[0].toLowerCase(); if (seen.has(k)) continue; seen.add(k);
      const ps = pos(m.index);
      out.push({ label, url: m[0], file: src, line: ps.line, col: ps.col, snippet: snippetAt(text, m.index, m[0].length) });
    }
  }
  return out;
}

// Stack from text. Version only where unambiguous; otherwise null.
const VER = '(\\d+\\.\\d+(?:\\.\\d+)?)';
const TEXT_TECH = [
  ['Next.js', /__NEXT_DATA__|_next\/static/],
  ['Nuxt', /__NUXT__|_nuxt\//],
  ['webpack', /webpackChunk|webpackJsonp|__webpack_require__/],
  ['Vite', /__vite__|\/@vite\//],
  ['jQuery', new RegExp('jQuery (?:JavaScript Library )?v' + VER + '|jquery[-.@]' + VER + '(?:\\.min)?\\.js')],
  ['Bootstrap', new RegExp('Bootstrap v' + VER + '|bootstrap@' + VER)],
  ['Axios', new RegExp('Axios v' + VER)],
  ['Angular', /ng-version[=`"',\s\\]{1,6}(\d+\.\d+\.\d+)/],
  ['DOMPurify', new RegExp('@license DOMPurify ' + VER)],
  ['ethers', new RegExp('ethers/' + VER)],
  ['Socket.IO', /Socket\.IO server in v2\.x|engine\.io-client|socket\.io-client/],
  ['zone.js', /zone\.js\/plugins\/|__zone_symbol__/],
  ['cookieconsent', /cookieconsent_status/],
  ['CodeMirror', /@codemirror\/state|CodeMirror\.version/],
  ['Lodash', new RegExp('lodash\\.com/license|lodash@' + VER)],
  ['Moment.js', new RegExp('moment@' + VER + '|//! version : ' + VER)]
];
const TECH_LOW = new Set(TEXT_TECH.map((t) => t[0].toLowerCase().replace(/\.js$/, '')));
export function techFromText(text) {
  const out = [];
  for (const [name, re] of TEXT_TECH) { const m = re.exec(text); if (m) out.push({ name, version: m.slice(1).find(Boolean) || null }); }
  const bid = /"buildId"\s*:\s*"([\w.-]{4,64})"/.exec(text);
  if (bid) out.push({ name: 'Build ID', version: bid[1] });
  return out;
}
export { techFromRuntime } from './core/tech.js';
// End of support: only for a known version. Dates from official announcements.
export function eolNote(name, version) {
  if (!version) return null;
  const major = parseInt(version, 10);
  if (name === 'AngularJS') return 'AngularJS is unsupported since 2022-01';
  if (name === 'Vue' && major === 2) return 'Vue 2 is unsupported since 2023-12-31';
  if (name === 'jQuery' && major < 3) return 'jQuery ' + major + '.x is unsupported';
  if (name === 'Bootstrap' && major < 4) return 'Bootstrap 3 is unsupported since 2019';
  if (name === 'Moment.js') return 'Moment.js is in maintenance mode, no new versions';
  return null;
}

// Response headers of the document. h: object with lower-case keys.
// Headers pasted from DevTools or Burp: "Name: value" per line; status line and junk are skipped
export function parseHeaders(text) {
  const out = Object.create(null); // header named Constructor must not hit Object.prototype
  let last = null;
  for (const line of String(text || '').split(/\r?\n/)) {
    // Continuation line (starts with whitespace) is appended to the previous header; "https://…" is not a header
    if (/^\s+\S/.test(line) && last) { out[last] += ' ' + line.trim(); continue; }
    const m = /^\s*([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s*:(?!\/\/)\s*(.*?)\s*$/.exec(line);
    if (!m || !m[2] || /^https?$/i.test(m[1])) continue; // name without value (name on one line, value on the next) is not accepted
    const k = m[1].toLowerCase();
    // Set-Cookie and CSP repeats are stored per line: several CSP policies all apply, so they must not be comma-joined
    last = k;
    out[k] = out[k] && !/^(?:set-cookie|content-security-policy)$/.test(k) ? out[k] + ', ' + m[2] : out[k] ? out[k] + '\n' + m[2] : m[2];
  }
  return out;
}
export function headerFindings(h, isHttps, url) {
  const out = [], add = (risk, title, why) => out.push({ risk, title, why });
  const csp = h['content-security-policy'];
  if (!csp) add(1, 'No Content-Security-Policy', 'XSS is not limited by a policy');
  else {
    // CSP quality checks per Mozilla Observatory rules. There may be several policies and all apply, so a weakness counts only if present in each
    const pols = csp.split('\n').filter((x) => x.trim());
    const dirOf = (pol, name) => { const m = new RegExp('(?:^|;)\\s*' + name + '\\s+([^;]*)', 'i').exec(pol); return m ? m[1] : null; };
    const all = (fn) => pols.every(fn), scr = (pol) => dirOf(pol, 'script-src') || dirOf(pol, 'default-src');
    const trusted = (v) => /'nonce-|'sha(?:256|384|512)-/.test(v); // with nonce or hash the browser ignores unsafe-inline; with strict-dynamic also host lists
    const first = scr(pols[0]) || '';
    if (all((p) => scr(p) == null)) add(1, 'CSP does not restrict scripts', 'No script-src or default-src: any script can run');
    if (all((p) => { const v = scr(p) || ''; return /'unsafe-eval'/.test(v) || (/'unsafe-inline'/.test(v) && !trusted(v)); })) add(1, 'CSP allows unsafe-inline or unsafe-eval', 'script-src: ' + first.trim().slice(0, 140)); // scripts only: in style-src it is common
    if (all((p) => { const v = scr(p) || ''; return /(?:^|\s)(?:\*|https?:)(?:\s|$)/.test(v) && !(/'strict-dynamic'/.test(v) && trusted(v)); })) add(1, 'CSP allows scripts from any host', 'script-src: ' + first.trim().slice(0, 120));
    if (all((p) => dirOf(p, 'object-src') == null && dirOf(p, 'default-src') == null)) add(0, 'CSP has no object-src', 'Plugins are not restricted');
    if (all((p) => dirOf(p, 'base-uri') == null)) add(0, 'CSP has no base-uri', 'A <base> tag can redirect relative script URLs');
  }
  const hsts = /max-age\s*=\s*"?(\d+)/i.exec(h['strict-transport-security'] || '');
  if (isHttps && h['strict-transport-security'] && !hsts) add(1, 'HSTS header has no readable max-age', h['strict-transport-security'].slice(0, 80));
  if (hsts && +hsts[1] < 15552000) add(1, 'HSTS max-age is under 6 months', 'max-age=' + hsts[1]);
  const nosniff = h['x-content-type-options'];
  if (!nosniff || nosniff.trim().toLowerCase() !== 'nosniff') add(0, 'No X-Content-Type-Options: nosniff', 'The browser may guess content types');
  // origin and origin-when-cross-origin give other sites only the origin: not a URL leak
  // Browser takes the last valid value from the comma-separated list
  if (/^(?:unsafe-url|no-referrer-when-downgrade)$/i.test((h['referrer-policy'] || '').split(',').map((x) => x.trim()).filter(Boolean).pop() || '')) add(1, 'Referrer-Policy sends the full address to other sites', 'referrer-policy: ' + h['referrer-policy']);
  if (isHttps && !h['strict-transport-security']) add(1, 'No Strict-Transport-Security', 'Can fall back to http');
  if (!h['x-frame-options'] && !/frame-ancestors/.test(csp || '')) add(1, 'No framing protection', 'No X-Frame-Options or frame-ancestors: clickjacking');
  if (h['access-control-allow-origin'] === '*' && /true/i.test(h['access-control-allow-credentials'] || '')) add(1, 'CORS: * with credentials', 'Browsers ignore credentials with *: check whether the server reflects Origin');
  else if (/^https?:\/\//i.test(h['access-control-allow-origin'] || '') && /true/i.test(h['access-control-allow-credentials'] || '')) add(1, 'CORS allows credentials for a fixed origin', 'Check by hand whether the server reflects Origin');
  if (/^\s*null\s*$/i.test(h['access-control-allow-origin'] || '') && /true/i.test(h['access-control-allow-credentials'] || '')) add(2, 'CORS: null origin with credentials', 'Sandboxed frames send Origin: null and can read the response');
  for (const k of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']) if (h[k]) add(0, k + ': ' + h[k], 'Reveals the implementation');
  return out.concat(extraHeaderFindings(h, isHttps, url));
}
function resolveAbs(raw, base) { try { const u = new URL(raw, base); u.hash = ''; return /^https?:$/.test(u.protocol) ? u.href : null; } catch (e) { return null; } }
export function analyze(text, src) {
  const pos = lineIndex(text), hits = [], refs = [], maps = [], inlineMaps = [];
  let m;
  function hit(raw, start, len, extra) {
    const p = pos(start);
    hits.push(Object.assign({ raw, at: start, file: src, line: p.line, col: p.col, snippet: snippetAt(text, start, len), method: '?', params: [], confidence: 'low', via: 'string', auth: [] }, extra));
  }
  const ref = (raw, via) => { const a = resolveAbs(raw, src); if (a) refs.push({ abs: a, via }); };
  RE_CALL.lastIndex = 0;
  while ((m = RE_CALL.exec(text))) {
    if (/^fetch/.test(m[0]) && /[\w$.]/.test(text[m.index - 1] || '')) continue; // this.fetch() and x.fetch() are own methods, not browser fetch
    const end = m.index + m[0].length;
    let url = m[5];
    url = expandConcat(text, end, url); // also for a template string: `/api/${a}` + '/x'
    const win = argTail(text, end);
    let method = null;
    const mm = /\bmethod\s*:\s*(["'`])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1/i.exec(win);
    if (mm) method = mm[2].toUpperCase();
    else if (m[1] && m[1] !== 'request') method = m[1].toUpperCase();
    else if (m[3]) method = m[3].toUpperCase();
    else if (m[2]) method = { get: 'GET', post: 'POST', getjson: 'GET' }[m[2].toLowerCase()] || null;
    // fetch defaults to GET, but only if the method is not set by a variable or spread
    else if (/^fetch/.test(m[0])) method = /\bmethod\s*:|\.\.\./.test(win) ? null : 'GET';
    const params = [], auth = [];
    // fetch's second argument is options, not the body: body only from body: or JSON.stringify(
    const body = (/^fetch/.test(m[0]) ? /(?:JSON\.stringify\(\s*|\bbody\s*:\s*)\{([^{}]{0,300})\}/ : /(?:JSON\.stringify\(\s*|\bbody\s*:\s*|\bdata\s*:\s*|^\s*,\s*)\{([^{}]{0,300})\}/).exec(win);
    if (body) { const kr = /(?:^|,)\s*["']?([A-Za-z_$][\w$-]*)["']?\s*(?::|(?=,|$))/g; let kb; while ((kb = kr.exec(body[1]))) params.push(kb[1]); }
    if (/authorization|bearer\s|x-api-key/i.test(win)) auth.push('authorization');
    if (/x-(?:csrf|xsrf)/i.test(win)) auth.push('csrf');
    if (/withCredentials\s*:\s*(?:!0|true)|credentials\s*:\s*["']include/i.test(win)) auth.push('cookies');
    hit(url, m.index, m[0].length, { via: 'call', method: method || '?', params: uniq(params), auth, confidence: 'high' });
  }
  RE_REQ_FORM.lastIndex = 0;
  while ((m = RE_REQ_FORM.exec(text))) hit(m[4], m.index, m[0].length, { via: 'call', method: m[2].toUpperCase(), confidence: 'high' });
  RE_AXIOS_OBJ.lastIndex = 0;
  while ((m = RE_AXIOS_OBJ.exec(text))) {
    // Object body up to the matching brace: nested headers: {…} do not break the url and method search
    let d = 1, i = m.index + m[0].length; const lim = Math.min(text.length, i + 1500);
    for (; i < lim && d; i++) { const c = text[i]; if (c === '{') d++; else if (c === '}') d--; }
    const body = text.slice(m.index + m[0].length, i).replace(/\{[^{}]*\}/g, '{}');
    const u = /\burl\s*:\s*(["'`])([^"'`\n]{1,400})\1/.exec(body); if (!u) continue;
    const mt = /\bmethod\s*:\s*(["'`])(\w+)\1/i.exec(body);
    hit(u[2], m.index, m[0].length, { via: 'call', method: mt ? mt[2].toUpperCase() : /\bmethod\s*:/.test(body) ? '?' : 'GET', confidence: 'high' });
  }
  const inst = []; RE_INST.lastIndex = 0;
  while ((m = RE_INST.exec(text)) && inst.length < 20) inst.push(m[1].replace(/\$/g, '\\$'));
  if (inst.length) {
    const re = new RegExp('\\b(?:' + inst.join('|') + ')\\.(get|post|put|patch|delete)(?:<[^<>()\\n]{0,120}>)?\\(\\s*(["\'`])([^"\'`\\n]{1,400})\\2', 'g');
    while ((m = re.exec(text))) hit(m[3], m.index, m[0].length, { via: 'call', method: m[1].toUpperCase(), confidence: 'high' });
  }
  // Base URL from a class field or variable (host = '/api/Items'): substituted into ${this.host}/… and this.host + '…'
  // shortcut: file scope only and only the last definition before the call; bases are not visible across files (needs AST parsing)
  const defs = [];
  for (const d of text.matchAll(/\b(?:this\.)?([A-Za-z_$][\w$]{0,40})\s*=\s*(?:this\.[\w$]+\s*\+\s*)?(["'`])(\/[^"'`\n$]{1,200})\2/g)) if (defs.length < 500) defs.push([d[1], d[3], d.index]);
  const defOf = (name, at) => { let v = null; for (const [n, val, i] of defs) if (n === name && i < at) v = val; return v; };
  const RE_CALL_VAR = /\b(?:this\.)?(?:http|https|httpClient|api|client|axios)\.(get|post|put|patch|delete)(?:<[^<>()\n]{0,120}>)?\(\s*(?:this\.)?([A-Za-z_$][\w$]{0,40})\s*(?:\+\s*(["'`])([^"'`\n]{0,200})\3)?\s*[,)]/g;
  while ((m = RE_CALL_VAR.exec(text))) { const base = defOf(m[2], m.index); if (base) hit(base.replace(/\/$/, '') + (m[4] || ''), m.index, m[0].length, { via: 'call', method: m[1].toUpperCase(), confidence: 'high' }); }
  RE_XHR.lastIndex = 0;
  while ((m = RE_XHR.exec(text))) hit(expandConcat(text, m.index + m[0].length, m[3]), m.index, m[0].length, { via: 'call', method: m[1].toUpperCase(), confidence: 'high' });
  RE_URLPROP.lastIndex = 0;
  while ((m = RE_URLPROP.exec(text))) hit(expandConcat(text, m.index + m[0].length, m[2]), m.index, m[0].length, { via: 'url-prop', confidence: 'medium' });
  RE_WS.lastIndex = 0;
  while ((m = RE_WS.exec(text))) hit(m[2], m.index, m[0].length, { via: 'ws', confidence: 'high' });
  RE_PATH.lastIndex = 0;
  while ((m = RE_PATH.exec(text))) {
    const raw = expandConcat(text, m.index + m[0].length, m[2]);
    hit(raw, m.index, m[0].length, { confidence: API_LIKE.test(raw) || /[{?]/.test(raw) ? 'medium' : 'low' });
    if (/[.](?:m?js|map)(?:[?#]|$)/i.test(m[2])) ref(m[2], 'path');
  }
  RE_TPL.lastIndex = 0;
  while ((m = RE_TPL.exec(text))) hit(expandConcat(text, m.index + m[0].length, m[1]), m.index, m[0].length, { via: 'template', confidence: 'medium' });
  // webpack/terser move license banners to a neighbor file: it has package names and versions
  const lic = /For license information please see ([\w.\/-]{1,200}\.LICENSE\.txt)/.exec(text);
  if (lic) ref(lic[1].includes('/') ? lic[1] : './' + lic[1], 'license');
  for (const [re, via] of [[RE_IMPORT, 'import'], [RE_FROM, 'import'], [RE_REL_JS, 'rel-js'], [RE_OPENAPI, 'openapi']]) { re.lastIndex = 0; while ((m = re.exec(text))) ref(m[2], via); }
  const nextBase = /\/_next\//.test(src) || /__NEXT_DATA__|_next\/static/.test(text) ? resolveAbs('/_next/', src) : null;
  RE_STATIC_REL.lastIndex = 0;
  while ((m = RE_STATIC_REL.exec(text))) { ref(m[2], 'static-rel'); if (nextBase) { const a2 = resolveAbs(m[2], nextBase); if (a2) refs.push({ abs: a2, via: 'static-rel' }); } }
  const pp = /[.]p\s*=\s*(["'`])([^"'`]*)\1/.exec(text), pubBase = nextBase || (pp && resolveAbs(pp[2] || '/', src)) || resolveAbs('/', src);
  RE_CHUNKMAP.lastIndex = 0;
  while ((m = RE_CHUNKMAP.exec(text))) {
    const back = text.slice(Math.max(0, m.index - 220), m.index), rp = /["'`]([\w@.~\/-]*\/)["'`]/g;
    let pm, prefix = '';
    while ((pm = rp.exec(back))) prefix = pm[1];
    const er = /["']?([\w$-]+)["']?\s*:\s*["']([0-9a-f]{6,20})["']/g;
    let em, n = 0;
    while ((em = er.exec(m[1])) && n++ < 600) { const cu = pubBase && resolveAbs(prefix + em[1] + '.' + em[2] + m[3], pubBase); if (cu) refs.push({ abs: cu, via: 'chunk-map' }); }
  }
  RE_SRCMAP.lastIndex = 0;
  while ((m = RE_SRCMAP.exec(text))) {
    const v = m[1];
    if (/^data:application\/json[^,]*,/i.test(v)) { try { const body = v.replace(/^[^,]*,/, ''); inlineMaps.push(/;base64,/i.test(v) ? b64d(body) : decodeURIComponent(body)); } catch (e) { /* broken inline map */ } }
    else { const mu = resolveAbs(v, src); if (mu) { maps.push(mu); refs.push({ abs: mu, via: 'sourcemap' }); hit(mu, m.index, m[0].length, { via: 'sourcemap', method: 'GET', confidence: 'high' }); } }
  }
  for (const h of hits) { const t = /^\$\{(?:this\.)?([A-Za-z_$][\w$]{0,40})\}/.exec(h.raw); const base = t && defOf(t[1], h.at == null ? Infinity : h.at); if (base) h.raw = base.replace(/\/$/, '') + h.raw.slice(t[0].length); }
  const rt = realtimeFindings(text), rtSimple = [];
  for (const r of rt) if (r.t === 'hit') hit(r.raw, r.at, 0, { via: 'ws', confidence: 'high' }); else if (r.t === 'simple') rtSimple.push(Object.assign({ kind: 'realtime' }, r));
  const secrets = scanSecrets(text, src, pos), clouds = scanClouds(text, src, pos), pii = piiFindings(text, src);
  for (const r of rt) if (r.t === 'secret') { const p = pos(r.at); secrets.push({ type: r.type, label: r.label, raw: r.raw, confidence: r.conf, risk: r.risk, why: [r.why], noMask: false, publicKey: false, file: src, line: p.line, col: p.col, snippetRaw: snippetAt(text, r.at, r.raw.length) }); }
  // Token values in URL params (?token=, access_token=, credential:) are masked in all fragments too
  const qtok = Array.from(text.matchAll(/(?:[?&][\w-]{0,30}(?:token|ticket|sig|signature|code|key|auth|secret|pass)[\w-]{0,30}=|credential\s*:\s*["'`])([^&"'`\s#]{6,300})/gi), (m) => m[1]).slice(0, 200);
  secrets.sort((x, y) => y.raw.length - x.raw.length); // longest value is masked first: otherwise its tail stays open after the short one is replaced
  const maskAll = (str) => { secrets.forEach((s) => { if (!s.noMask) str = str.split(s.raw).join(mask(s.raw)); }); pii.forEach((p) => { if (p.raw) str = str.split(p.raw).join(p.masked); }); qtok.forEach((v) => { str = str.split(v).join(mask(v)); }); return maskEdges(pii.length ? maskEmails(str) : str, edgeRaws).replace(PEM_BODY, '$1 [body hidden]').replace(PEM_TAIL, '[key body hidden] '); };
  // A fragment window can cut a value: the tail or start of a long secret at the window edge is hidden too
  const edgeRaws = secrets.filter((s) => !s.noMask).map((s) => s.raw).concat(pii.map((p) => p.raw), qtok).filter((v) => v && v.length >= 12);
  pii.forEach((p) => { p.snippet = maskAll(p.snippetRaw || ''); });
  if (secrets.length || pii.length || qtok.length) {
    hits.forEach((h) => { h.snippet = maskAll(h.snippet); });
    clouds.forEach((c) => { c.snippet = maskAll(c.snippet); });
    secrets.forEach((s) => { s.snippet = s.noMask ? s.snippetRaw.replace(/-----BEGIN[^\n]*?-----[\s\S]*/, s.raw + ' [body hidden]') : maskAll(s.snippetRaw); });
  }
  // Simple findings from core modules: { kind, title, risk, why, at } -> line and fragment by position
  let host = ''; try { host = new URL(src).hostname; } catch (e) { /* not a URL */ }
  const fw = frameworkHints(text);
  for (const f of fw) if (f.hit) hit(f.hit, f.at, 0, { via: f.via, method: f.method, confidence: f.confidence });
  const simple = scanIdentity(text).concat(scanAi(text, hits, secrets, scanSecrets), rtSimple, fw.filter((f) => !f.hit), mobileHints(text).map((x) => Object.assign({ kind: 'mobile' }, x)), infraFromText(text, host).map((x) => Object.assign({ kind: 'infra' }, x)), browserFindings(text, host).map((x) => Object.assign({ kind: 'browser' }, x)), web3Findings(text, src).map((x) => Object.assign({ kind: 'web3' }, x))).map((f) => { const p = pos(f.at); return { kind: f.kind, title: f.title, risk: f.risk, why: f.why, file: src, line: p.line, snippet: secrets.length ? f.title : snippetAt(text, f.at, 40) }; });
  const code = codeFindings(text, src);
  for (const d of devbuildText(text, src)) { const p = pos(d.at); code.push({ type: d.type, title: d.title, risk: d.risk, file: src, line: p.line, col: p.col, snippet: snippetAt(text, d.at, 60) }); }
  for (const o of oauthLiteral(text, host)) { const p = pos(o.at); code.push({ type: o.type, title: o.title, risk: o.risk, file: src, line: p.line, col: p.col, snippet: secrets.length ? o.title : snippetAt(text, o.at, 60), why: o.why }); }
  code.forEach((c) => { c.snippet = maskAll(c.snippet || ''); }); simple.forEach((x) => { x.snippet = maskAll(x.snippet || ''); });
  return { hits, refs, maps, inlineMaps, secrets, clouds, simple, pii, tech: techFromText(text), code };
}

export class Store {
  constructor(pageUrl) {
    this.pageUrl = pageUrl || '';
    this.pageHost = hostOf(this.pageUrl);
    try { const u = new URL(this.pageUrl); this.pageOrigin = u.origin; this.pageProto = u.protocol; } catch (e) { this.pageOrigin = ''; this.pageProto = 'https:'; }
    this.listeners = []; this.rev = 0; // rev grows on any findings change: screens use it to know when to rebuild
    this.reset();
  }
  reset() {
    this.items = []; this.byKey = new Map();
    this.files = []; this.texts = new Map(); this.obf = new Map(); this.textBytes = 0; this.textsSkipped = 0; this.errors = []; this.skipped = []; this.blocked = []; this.deps = new Map(); this.docHeaders = null;
    this.status = ''; this.progress = { done: 0, total: 0 };
    this.notify();
  }
  // File texts for the file browser. Not included in history, session, or export
  addText(url, text, contentType) {
    if (typeof text !== 'string' || this.texts.has(url)) return;
    if (this.textBytes + text.length > TEXT_BUDGET) { this.textsSkipped++; return; } // "Files" reports how many did not fit
    this.textBytes += text.length; this.texts.set(url, { text, contentType: contentType || '' });
    if (/\.m?js(?:$|[?#])/i.test(url) || /javascript/.test(contentType || '')) { const o = obfuscationScore(text); if (o.level) { this.obf.set(url, o); this.addSimple('obfuscation', { title: (o.level === 'obfuscated' ? 'Obfuscated code: ' : 'Possibly obfuscated code: ') + o.signals.map((x) => OBF_LABEL[x.id]).join(', '), risk: 0, why: ['Obfuscation hides what the code does; it is context, not a vulnerability. Use Decode strings and Unpack in Files to read it'], file: url, line: 1 }); } }
  }
  on(fn) { this.listeners.push(fn); }
  notify() { for (const fn of this.listeners) try { fn(this); } catch (e) { /* a UI listener must not crash the scan */ } }
  _src(f, h) {
    // Key with column: a minified line has several places in a row; above 20 places a flag is set so the list is not taken as complete
    const key = h.file + ':' + h.line + ':' + h.col;
    if (f.sources.some((s) => s.file + ':' + s.line + ':' + s.col === key)) return;
    if (f.sources.length >= 20) { f.sourcesTruncated = true; return; }
    f.sources.push({ file: h.file, line: h.line, col: h.col, via: h.via });
  }
  // Repeated finding: add the place, risk is the highest seen
  _merge(key, c, h) {
    const ex = this.byKey.get(key);
    if (!ex) return false;
    const f = ex[0];
    if (h && h.file) this._src(f, h);
    if ((c.risk || 0) > f.risk) { f.risk = c.risk; f.level = LEVELS[f.risk]; f.priority = f.risk >= 3; this.rev++; }
    return true;
  }
  _put(key, f, h) { this.rev++; f.id = fnv(key); f.sources = []; this.byKey.set(key, [f]); this.items.push(f); if (h) this._src(f, h); return f; }
  addHit(h) {
    let raw = String(h.raw || '').trim();
    if (!raw) return null;
    if (raw.includes('${')) raw = tplToPath(raw);
    const bm = /^\{([^}]*)\}(\/.*)?$/.exec(raw);
    if (bm) { if (BASE_VAR.test(bm[1])) raw = bm[2] || '/'; else if (!bm[2]) return null; }
    if (!/^(?:https?:|wss?:)?\/\//i.test(raw) && raw[0] !== '/' && raw[0] !== '{') {
      if (h.via !== 'call' || !this.pageUrl || !/^[\w.-]+(?:\/\S*)?$/.test(raw)) return null;
      try { const qi = raw.indexOf('?'); raw = new URL(raw.split('?')[0], this.pageUrl).pathname + (qi >= 0 ? raw.slice(qi) : ''); } catch (e) { return null; }
    }
    if (isNoise(raw, h.via)) return null;
    const sp = splitUrl(raw);
    let origin = null, host = '';
    if (sp.origin) { origin = sp.origin.startsWith('//') ? this.pageProto + sp.origin : sp.origin; host = hostOf(origin); if (/[{}]/.test(host)) return null; }
    else if (this.pageOrigin && sp.path[0] === '/') { origin = this.pageOrigin; host = this.pageHost; }
    // Key is the path without query: variants with different params and method "?" merge into one finding
    const uk = (origin || '') + sp.path, list = this.byKey.get(uk) || [];
    const method = h.method && h.method !== '?' ? h.method : '?';
    // "?" with several methods on one path: goes to the "?" entry, or if absent to each, not the first one found
    if (method === '?' && list.length > 1 && !list.some((x) => x.method === '?')) { let r = null; for (const x of list.slice()) r = this.addHit(Object.assign({}, h, { method: x.method })); return r; }
    let f = method === '?' ? (list.length === 1 ? list[0] : list.find((x) => x.method === '?')) : (list.find((x) => x.method === method) || list.find((x) => x.method === '?'));
    if (f && method !== '?') f.method = method;
    if (!f) {
      f = { path: sp.path, origin, query: [], host, pageHost: this.pageHost, method, params: [], auth: [], sources: [], vias: [], confidence: h.confidence || 'low', snippet: h.snippet || '', observed: false };
      list.push(f); this.byKey.set(uk, list); this.items.push(f);
    }
    f.query = uniq(f.query.concat(sp.params));
    f.url = f.path + (f.query.length ? '?' + f.query.map((n) => n + '=').join('&') : '');
    f.resolved = f.origin ? f.origin + f.url : null;
    f.params = uniq(f.params.concat(sp.params, h.params || []));
    f.auth = uniq(f.auth.concat(h.auth || []));
    f.vias = uniq(f.vias.concat(h.via || []));
    if (CONF[h.confidence] > CONF[f.confidence]) f.confidence = h.confidence;
    if (h.via === 'observed') f.observed = true;
    if (!f.snippet && h.snippet) f.snippet = h.snippet;
    this._src(f, h);
    rescore(f);
    // id depends only on the URL and final method: same across runs in any file order
    f.id = fnv('hit|' + uk + '|' + f.method);
    this.rev++;
    return f;
  }
  // Personal data: key and id come from the mask, the original value stays in memory only for the "show" button
  addPii(p) {
    // One hash in different files is one finding with all places; in 5+ files it is more likely a library constant
    // Key from the hash of the original value: different maps with the same mask do not merge (id is not written to file: stableIds there)
    const key = 'pii|' + p.type + '|' + (p.type === 'hash' ? '' : p.file + '|') + p.masked + '|' + fnv(p.raw || p.masked), ex = this.byKey.get(key);
    if (ex) {
      const f = ex[0]; this._src(f, p);
      if (p.type === 'hash' && f.sources.length >= 5 && f.risk > 0) { f.risk = 0; f.level = LEVELS[0]; f.priority = false; f.why = f.why.concat('Same value in 5 or more files: most likely a library constant'); this.rev++; }
      return null;
    }
    return this._put(key, { kind: 'pii', type: p.type, url: p.label, resolved: null, method: '-', params: [], auth: [], host: '', confidence: p.confidence, risk: p.risk, level: LEVELS[Math.min(p.risk, 4)], owasp: ['API8'], why: p.why, priority: p.risk >= 3 && CONF[p.confidence] >= 1, secret: p.masked, raw: p.raw, snippet: p.snippet != null ? p.snippet : p.raw ? p.snippetRaw.split(p.raw).join(p.masked) : '' }, p);
  }
  addSecret(s) {
    const key = 'secret|' + s.type + '|' + s.raw, ex = this.byKey.get(key);
    if (ex) { this._src(ex[0], s); return ex[0]; }
    const masked = s.noMask ? s.raw : mask(s.raw);
    return this._put(key, {
      kind: 'secret', url: s.label, resolved: null, method: '-', params: [], auth: [], host: '', confidence: s.confidence, risk: s.risk, level: LEVELS[Math.min(s.risk, 4)],
      owasp: ['API8'], why: s.why, priority: !s.publicKey && s.risk >= 3 && CONF[s.confidence] >= 1, publicKey: !!s.publicKey, secret: masked, raw: s.raw,
      // For a private key the match is only the BEGIN line: the key body is removed from the fragment, whole only in snippetRaw
      snippet: s.snippet != null ? s.snippet : s.noMask ? (s.snippetRaw || '').replace(/-----BEGIN[^\n]*?-----[\s\S]*/, s.raw + ' [body hidden]') : (s.snippetRaw || '').split(s.raw).join(masked), snippetRaw: s.snippetRaw || ''
    }, s);
  }
  addCloud(c) {
    const key = 'cloud|' + c.url.toLowerCase(), ex = this.byKey.get(key);
    if (ex) { this._src(ex[0], c); return ex[0]; }
    return this._put(key, {
      kind: 'cloud', url: c.url, resolved: 'https://' + c.url, method: '-', params: [], auth: [], host: c.url.split('/')[0], confidence: 'high', risk: 2, level: 'medium',
      owasp: ['API8'], priority: false, why: [c.label + ': check the owner and permissions (listing, write); a dangling record means takeover risk'], snippet: c.snippet
    }, c);
  }
  addTech(t, file) {
    const key = 'tech|' + t.name.toLowerCase(), ex = this.byKey.get(key); // React and react from a banner are one entry
    if (t.version) this._bad(t.name.toLowerCase(), t.version, file);
    if (ex) { const f = ex[0]; if (t.version && !f.version) { f.version = t.version; this._techWhy(f); this.rev++; } return f; }
    const f = this._put(key, { kind: 'tech', name: t.name, version: t.version || null, method: '-', params: [], auth: [], host: '', confidence: t.version ? 'high' : 'medium', owasp: [], priority: false, snippet: '' }, { file, line: 1, col: 1, via: 'tech' });
    this._techWhy(f);
    return f;
  }
  // Known malicious version or attack marker package: separate finding so it is not lost among version advice
  _bad(name, version, file) {
    const b = badMatch(name, version);
    if (b) this.addSimple('custom', Object.assign({ file: file || '(source map)', line: 1 }, b));
    return !!b;
  }
  _techWhy(f) {
    const eol = eolNote(f.name, f.version);
    f.advisories = matchAdvisories(f.name, f.version).concat(f.osv || []);
    f.url = f.name + (f.version ? ' ' + f.version : '');
    f.risk = Math.max(eol ? 1 : 0, ...f.advisories.map((a) => a.risk || 2)); f.level = LEVELS[f.risk];
    f.why = f.advisories.map((a) => a.id + ': ' + a.summary + (a.fixed ? ', fixed in ' + a.fixed : '')).concat(eol ? [eol] : []);
    f.resolved = osvLink(f.name);
  }
  // OSV check result is appended to the tech; duplicates by id are removed
  addOsv(name, vulns) {
    this.rev++;
    const ex = this.byKey.get('tech|' + String(name).toLowerCase()); if (!ex) return;
    const f = ex[0], known = new Set(matchAdvisories(f.name, f.version).map((a) => a.id));
    f.osv = vulns.filter((v) => !known.has(v.id) && !(v.aliases || []).some((a) => known.has(a))).map((v) => ({ id: v.id, summary: String(v.summary || 'see osv.dev').slice(0, 140), risk: 2 }));
    this._techWhy(f); this.notify();
  }
  addCode(c) {
    // No file name: one finding in several bundles is one entry with all places, and the bundle hash in the name does not make it "new" after deploy
    const key = 'code|' + c.type + '|' + c.title;
    if (this._merge(key, c, c)) return null;
    return this._put(key, { kind: 'code', type: c.type, url: c.title, resolved: null, method: '-', params: [], auth: [], host: '', confidence: 'medium', risk: c.risk, level: LEVELS[c.risk], owasp: [], why: c.why ? [c.why] : [CODE_WHY[c.type]], priority: (c.risk || 0) >= 3, snippet: c.snippet }, c);
  }
  // Simple findings (cookies, storage, custom rules): title, level, reasons
  addSimple(kind, c) {
    const risk = Math.min(4, c.risk || 0);
    const key = kind + '|' + c.title;
    if (this._merge(key, c, { file: c.file, line: c.line || 1, col: 1, via: kind })) return null;
    return this._put(key, { kind, url: c.title, resolved: null, method: '-', params: [], auth: [], host: '', confidence: 'high', risk, level: LEVELS[risk], owasp: [], why: c.why || [], priority: risk >= 3, snippet: c.snippet || '' }, { file: c.file, line: c.line || 1, col: 1, via: kind });
  }
  addConfig(c, file) {
    const key = 'config|' + c.title;
    if (this.byKey.get(key)) return null;
    return this._put(key, { kind: 'config', url: c.title, resolved: null, method: '-', params: [], auth: [], host: this.pageHost, confidence: 'high', risk: c.risk, level: LEVELS[c.risk], owasp: ['API8'], why: [c.why], priority: false, snippet: '' }, { file, line: 1, col: 1, via: 'header' });
  }
  // Document headers are replaced as a whole (e.g. pasted by hand): old header findings are removed
  replaceHeaders(headers, isHttps, file) {
    this.items = this.items.filter((f) => f.kind !== 'config');
    for (const k of Array.from(this.byKey.keys())) if (k.startsWith('config|')) this.byKey.delete(k);
    this.docHeaders = headers; this.rev++;
    headerFindings(headers, isHttps, this.pageUrl).forEach((c) => this.addConfig(c, file || '(document)'));
    this.notify();
  }
  addDep(name, version, file) {
    let d = this.deps.get(name);
    if (d) d.count++; else this.deps.set(name, d = { name, scoped: name[0] === '@', count: 1, version: version || null, checked: new Set() });
    if (version && !d.version) d.version = version;
    const v = version || '';
    if (!d.checked.has(v)) { d.checked.add(v); if (!this._bad(name, version, file) && version && !TECH_LOW.has(name.toLowerCase())) this.addTech({ name, version }, file); } // version without a finding also goes to "Stack", except libraries techFromText already finds
  }
  list() {
    return this.items.slice().sort((a, b) => (b.priority - a.priority) || (b.risk - a.risk) || (CONF[b.confidence] - CONF[a.confidence]) || (a.url < b.url ? -1 : 1));
  }
  counts() {
    // total and levels count the same thing: without static and external, so tiles match the total
    const c = { total: 0, priority: 0, kinds: {}, levels: {} };
    for (const f of this.items) { c.kinds[f.kind] = (c.kinds[f.kind] || 0) + 1; if (f.kind === 'external' || f.kind === 'static') continue; c.total++; if (f.priority) c.priority++; c.levels[f.level] = (c.levels[f.level] || 0) + 1; }
    return c;
  }
  paramStats() {
    const m = new Map();
    for (const f of this.items) for (const p of f.params) {
      const e = m.get(p) || { name: p, count: 0, urls: [], risky: (paramRisk(p) || {}).tag || null };
      e.count++; if (e.urls.length < 3) e.urls.push(f.url);
      m.set(p, e);
    }
    return Array.from(m.values()).sort((a, b) => (!!b.risky - !!a.risky) || (b.count - a.count) || (a.name < b.name ? -1 : 1));
  }
}

export function parseSourceMap(text) { return parseSourceMaps(text)[0] || null; }
// Plain map or index map (sections[].map); the )]}' XSSI prefix is dropped
export function parseSourceMaps(text) {
  let j; try { j = JSON.parse(String(text).replace(/^\)\]\}'[^\n]*\n/, '')); } catch (e) { return []; }
  if (j && Array.isArray(j.sections)) return j.sections.map((x) => x && x.map).filter((m) => m && Array.isArray(m.sources)).slice(0, 200);
  return j && Array.isArray(j.sources) ? [j] : [];
}
// Namespace is stripped only before "./" (webpack://app/./src/x.js): otherwise the first source folder is eaten
const cleanSource = (s) => s.replace(/^(?:webpack|turbopack|vite|rollup):\/\/\/?(?:\[project\]\/|_N_E\/)?(?:[^\/]+\/(?=\.\/))?(?:\.\/)?/, '');
function pkgOf(s) { let m, last = null; const re = /node_modules\/((?:@[^\/]+\/)?[^\/]+)/g; while ((m = re.exec(s))) last = m[1]; return last; }
function handleMap(store, j, mapUrl) {
  const contents = j.sourcesContent || [];
  let budget = 0, noContent = 0;
  j.sources.forEach((s, i) => {
    if (typeof s !== 'string') return; // the spec allows null in sources
    const pn = pnpmPackage(s), pkg = pn ? pn.name : pkgOf(s);
    if (pkg) store.addDep(pkg, pn && pn.version, mapUrl); // package source is parsed too: it can hold keys, and volume is capped by MAP_BUDGET
    const name = cleanSource(s);
    if (/(?:^|\/)(?:admin|backoffice|superuser|internal-tools)(?:\/|$)/i.test(name)) store.addCode({ type: 'admin-src', title: 'Admin component in shipped source: ' + name.replace(/\/[^/]*$/, '/'), risk: 1, file: mapUrl.split('#')[0] + '#' + name, line: 1, col: 1, snippet: name }); // the place is the source inside the map, not the map itself
    const c = contents[i];
    // Two different sources with the same short name must not overwrite each other: then the key is the source string
    let key = mapUrl.split('#')[0] + '#' + name; if (store.texts.has(key)) key = mapUrl.split('#')[0] + '#' + s;
    if (typeof c === 'string' && !pkg) store.addText(key, c); // package sources are not stored (memory) but parsed below
    if (typeof c === 'string' && budget + c.length <= MAP_BUDGET) { budget += c.length; analyzeInto(store, c, key, { inMap: true }); }
    else if (typeof c === 'string') store.mapSkipped = (store.mapSkipped || 0) + 1;
    else noContent++;
  });
  if (noContent) store.addSimple('custom', { title: 'Source map without sourcesContent: ' + noContent + ' sources not analysed', risk: 0, why: ['The map lists file names only, so their code was not read'], file: mapUrl.split('#')[0], line: 1 });
}
function handleManifest(store, text, src) {
  let j; try { j = JSON.parse(text); } catch (e) { return false; }
  if (!j || typeof j !== 'object' || (!j.start_url && !j.name && !j.short_name && !j.shortcuts)) return false;
  [j.start_url, j.scope, j.serviceworker && j.serviceworker.src, j.share_target && j.share_target.action].concat((j.shortcuts || []).map((s) => s.url)).forEach((u) => {
    if (typeof u !== 'string') return;
    let p = u; try { p = new URL(u, src).pathname; } catch (e) { /* keep as is */ }
    store.addHit({ raw: p, file: src, line: 1, col: 1, via: 'manifest', confidence: 'medium', snippet: 'web manifest' });
  });
  return true;
}
function handleRobots(store, text, src, ctx) {
  text.split(/\r?\n/).slice(0, 2000).forEach((l, i) => {
    const m = /^\s*(?:Disallow|Allow)\s*:\s*(\S+)/i.exec(l), s = /^\s*Sitemap\s*:\s*(\S+)/i.exec(l);
    if (m) { const p = m[1].replace(/[*$]+/g, ''); if (p[0] === '/') store.addHit({ raw: p, file: src, line: i + 1, col: 1, via: 'robots', confidence: 'medium', snippet: l.trim().slice(0, 160) }); }
    if (s && ctx.enqueue) ctx.enqueue(s[1], ctx.depth || 0, 'sitemap', true);
  });
}
function handleSitemap(store, text, src, ctx) {
  const re = /<loc>\s*([^<\s]+)\s*<\/loc>/g, isIndex = /<sitemapindex/i.test(text);
  let m, n = 0;
  while ((m = re.exec(text)) && n++ < 300) {
    if (isIndex) { if (ctx.enqueue && n <= 5) ctx.enqueue(m[1], (ctx.depth || 0) + 1, 'sitemap', true); continue; }
    let p; try { const u = new URL(m[1]); if (store.pageHost && u.host !== store.pageHost) continue; p = u.pathname + u.search; } catch (e) { continue; }
    store.addHit({ raw: p, file: src, line: 1, col: 1, via: 'sitemap', confidence: 'low', snippet: 'sitemap.xml' });
  }
}
// Custom user rules: regular expressions with a per-file match limit
function applyRules(store, text, src) {
  const pos = lineIndex(text);
  for (const r of store.rules.slice(0, 50)) {
    let re; try { re = new RegExp(r.regex, String(r.flags || '').replace(/g/g, '') + 'g'); } catch (e) { continue; }
    let m, n = 0;
    while ((m = re.exec(text)) && n++ < 20) {
      if (!m[0]) { re.lastIndex++; continue; }
      // A custom rule match may be a secret: why and fragment hold only the mask, the original is for "show"
      const raw = snippetAt(text, m.index, m[0].length), v = m[0].slice(0, 120);
      const f = store.addSimple('custom', { title: String(r.title || r.id || 'Custom rule'), risk: Math.min(4, Math.max(0, r.risk | 0)), why: ['Rule "' + (r.id || r.title) + '": ' + mask(v)], file: src, line: pos(m.index).line, snippet: raw.split(m[0]).join(mask(m[0])) });
      if (f) f.snippetRaw = raw;
    }
  }
}
// Next.js: pages from __NEXT_DATA__ and _buildManifest.js. The manifest is a plain site JS file, it can be downloaded.
function nextJs(store, text, src, ctx) {
  const bid = /"buildId"\s*:\s*"([\w.-]{4,64})"/.exec(text);
  const hit = (raw, snippet) => store.addHit({ raw, file: src, line: 1, col: 1, via: 'next', confidence: 'high', snippet });
  const nd = /<script id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/.exec(text);
  if (nd) {
    try {
      const j = JSON.parse(nd[1]);
      if (typeof j.page === 'string' && j.page[0] === '/') { hit(j.page.replace(/\[([^\]]+)\]/g, '{$1}'), 'Next.js page'); if (j.buildId) hit('/_next/data/' + j.buildId + (j.page === '/' ? '/index' : j.page.replace(/\[([^\]]+)\]/g, '{$1}')) + '.json', 'Next.js page data'); }
    } catch (e) { /* not JSON */ }
  }
  if (bid && ctx.enqueue && /_next\//.test(text)) { const u = resolveAbs('/_next/static/' + bid[1] + '/_buildManifest.js', src); if (u) ctx.enqueue(u, ctx.depth || 0, 'next'); }
  if (/_buildManifest\.js$/.test(src.split('?')[0])) {
    const re = /["']?(\/[\w\-./[\]]*)["']?\s*:\s*\[/g; let m, n = 0;
    while ((m = re.exec(text)) && n++ < 500) if (!/^\/_/.test(m[1])) hit(m[1].replace(/\[([^\]]+)\]/g, '{$1}'), 'Next.js build manifest');
  }
}
// GraphQL: operation names from query strings in client code
function graphqlOps(store, text, src) {
  const pos = lineIndex(text);
  for (const g of graphqlFindings(text)) { const f = store.addSimple('graphql', { title: g.title, risk: g.risk, why: g.why, file: src, line: pos(g.at).line, snippet: snippetAt(text, g.at, 80) }); if (f) { f.op = g.op; f.frag = g.frag; } }
}
export function analyzeInto(store, text, src, ctx) {
  ctx = ctx || {};
  const bare = src.split('#')[0].split('?')[0];
  if (!ctx.inMap && (/\.map$/i.test(bare) || (text.charCodeAt(0) === 123 && /"sources"\s*:\s*\[/.test(text.slice(0, 3000))))) {
    const maps = parseSourceMaps(text); if (maps.length) { maps.forEach((j) => handleMap(store, j, src)); return; }
  }
  if (/^https?:/.test(bare) && isWellKnown(new URL(bare).pathname)) {
    const w = wellKnownFile(text, bare, store.pageHost);
    if (w && w.miss) return; // file missing, site served a stub page: not an error
    if (w) { w.simple.forEach((f) => store.addSimple(f.kind, Object.assign({ file: src, line: 1 }, f))); w.hits.forEach((x) => store.addHit({ raw: x.raw, file: src, line: 1, col: 1, via: x.via, confidence: 'high', snippet: x.via + ': ' + x.raw })); }
    return;
  }
  if (/\/\.vite\/manifest\.json$/.test(bare)) {
    const v = viteManifest(text, src);
    if (v) { v.files.forEach((u) => ctx.enqueue && ctx.enqueue(u, (ctx.depth || 0) + 1, 'vite-manifest')); store.addSimple('custom', { title: 'Vite build manifest: ' + v.files.length + ' files', risk: 1, why: ['The manifest lists every chunk and source file: source names: ' + v.sources.slice(0, 20).join(', ')], file: src, line: 1 }); }
    return;
  }
  if (/(?:manifest\.json|\.webmanifest)$/i.test(bare) && handleManifest(store, text, src)) return;
  const head = text.slice(0, 20000); // in big specs the openapi field can be past the start
  if ((text.trimStart()[0] === '{' && /"(?:openapi|swagger)"\s*:\s*"/.test(head)) || /^\s*(?:openapi|swagger)\s*:/m.test(head)) {
    const eps = openApiEndpoints(text);
    if (eps) { eps.forEach((e) => store.addHit({ raw: e.path, method: e.method, params: e.params, file: src, line: 1, col: 1, via: 'openapi', confidence: 'high', snippet: 'OpenAPI: ' + e.method + ' ' + e.path })); return; }
  }
  if (/\/robots\.txt$/i.test(bare)) { handleRobots(store, text, src, ctx); return; }
  if (/\/sitemap[^\/]*\.xml$/i.test(bare)) { handleSitemap(store, text, src, ctx); return; }
  const a = analyze(text, src);
  // A secret inside a URL (token in path, webhook) must not appear open in the endpoint list
  const secretVals = a.secrets.filter((s) => !s.noMask).map((s) => s.raw);
  a.hits.forEach((h) => { secretVals.forEach((v) => { h.raw = String(h.raw).split(v).join('{secret}'); }); store.addHit(h); });
  a.secrets.forEach((s) => store.addSecret(s));
  a.pii.forEach((p) => store.addPii(p));
  a.clouds.forEach((c) => store.addCloud(c));
  a.simple.forEach((f) => store.addSimple(f.kind, f));
  // Banners "/*! name v1.2.3" and "@license name 1.2.3": dependency with version, to check known malicious versions
  for (const m of text.slice(0, 400000).matchAll(/(?:\/\*!|@license)\s+(@?[a-z0-9][\w.-]{1,60}(?:\/[\w.-]{1,60})?)\s+v?(\d+\.\d+\.\d+(?:-[\w.]+)?)/gi)) store.addDep(m[1].toLowerCase(), m[2], src);
  a.tech.forEach((t) => store.addTech(t, src));
  nextJs(store, text, src, ctx);
  graphqlOps(store, text, src);
  a.code.forEach((c) => store.addCode(c));
  if (store.rules) applyRules(store, text, src);
  a.inlineMaps.forEach((t) => parseSourceMaps(t).forEach((j) => handleMap(store, j, src + '(inline-map)')));
  if (ctx.enqueue) {
    const d = (ctx.depth || 0) + 1;
    a.refs.forEach((r) => ctx.enqueue(r.abs, r.via === 'sourcemap' ? ctx.depth || 0 : d, r.via)); // a script's own map does not spend depth
    if (ctx.guessMaps && /\.m?js$/i.test(bare) && !a.maps.length && !a.inlineMaps.length) ctx.enqueue(bare + '.map', d, 'guess');
  }
}

// fetchText(url, {cookies}) -> {ok, status, text, headers}. Passed in from outside, so crawl is testable in node.
export async function crawl(o) {
  const store = o.store, scope = o.scope, maxDepth = o.maxDepth == null ? 3 : o.maxDepth, conc = o.conc || 4, maxFiles = o.maxFiles || 400;
  const seen = new Set(), queue = [], stopped = new Set(), spaHosts = new Set();
  let fetched = 0;
  const tick = () => { store.progress = { done: fetched, total: fetched + queue.length }; store.notify(); };
  function enqueue(url, depth, via, force) {
    let u; try { u = new URL(url); } catch (e) { return; }
    u.hash = ''; url = u.href;
    if (seen.has(url) || depth > maxDepth) return;
    seen.add(url);
    const chk = scope.check(url, force);
    if (!chk.ok) {
      (store.skipped.length < 500) && store.skipped.push({ url, reason: chk.reason });
      if (chk.reason === 'external-host' && /\.m?js$/i.test(u.pathname)) store.addHit({ raw: url, file: '(page)', line: 1, col: 1, via: 'external-script', confidence: 'high', snippet: 'external script' });
      return;
    }
    queue.push({ url, depth, via, force: !!force });
  }
  (o.seeds || []).forEach((s) => enqueue(s.url, s.depth == null ? 1 : s.depth, s.via || 'seed', s.force));
  async function run(item) {
    const host = hostOf(item.url);
    if (stopped.has(host) || o.isStopped && o.isStopped()) return;
    if (item.via === 'well-known' && spaHosts.has(host)) return; // site answers any path with an SPA stub: other service files are not requested
    fetched++;
    let r;
    try { r = await o.fetchText(item.url, { cookies: !!o.cookies, force: item.force }); } catch (e) { r = { ok: false, status: 0, error: String(e && e.message || e) }; }
    const why = r && (r.blocked || blockedReason(r)); // the collector may already have recognized a check page and not sent its text
    if (why) { stopped.add(host); store.blocked.push({ host, reason: why }); (store.errors.length < 500) && store.errors.push({ url: item.url, status: r.status, error: why }); tick(); return; }
    // Request or volume limit exhausted: other files will not download either, stop running the queue
    if (r && (r.error === 'budget' || r.error === 'limit')) { queue.length = 0; (store.errors.length < 500) && store.errors.push({ url: item.url, status: 0, error: r.error }); tick(); return; }
    if (!r || !r.ok || typeof r.text !== 'string') {
      if (!(r && r.status === 404 && /well-known|sitemap|vite-manifest/.test(item.via))) (store.errors.length < 500) && store.errors.push({ url: item.url, status: r && r.status, error: r && r.error }); // no robots/sitemap is normal
      tick(); return;
    }
    const isMap = /\.map$/i.test(new URL(item.url).pathname);
    const text = !isMap && r.text.length > MAX_TEXT ? r.text.slice(0, MAX_TEXT) : r.text; // a truncated map JSON cannot be parsed
    if (text !== r.text) { const sm2 = /[#@]\s*sourceMappingURL\s*=\s*([^\s'"`*]+)\s*$/.exec(r.text.slice(-2000)); if (sm2) { try { enqueue(new URL(sm2[1], item.url).href, item.depth, 'sourcemap'); } catch (e) { /* broken URL */ } } } // the map link sits at the end of the file, past the truncation
    // SPA stub (HTML, including one starting with a comment) instead of JS, map, robots, sitemap or service file is not a file
    if (isMap && !/^\s*(?:\)\]\}'[^\n]*\n\s*)?\{/.test(text) || /\.(?:m?js|map|txt|json|webmanifest)$|\/\.well-known\//i.test(new URL(item.url).pathname) && /^\s*<(?:!--|!doctype|html|head|body)/i.test(text) || /\.xml$/i.test(new URL(item.url).pathname) && /^\s*<(?:!doctype html|html)/i.test(text)) { if (item.via === 'well-known') spaHosts.add(host); else (store.errors.length < 500) && store.errors.push({ url: item.url, status: r.status, error: 'HTML returned instead of a file' }); tick(); return; } // a missing service file is normal, not an error
    store.files.push(item.url);
    // Map with sources is not stored whole: its sources are saved separately, else the text would be stored twice
    if (!(isMap && /"sourcesContent"\s*:\s*\[\s*"/.test(text))) store.addText(item.url, text, r.headers && r.headers['content-type']);
    try { analyzeInto(store, text, item.url, { enqueue, depth: item.depth, guessMaps: o.guessMaps }); }
    catch (e) { (store.errors.length < 500) && store.errors.push({ url: item.url, status: r.status, error: 'not parsed: ' + (e && e.message || e) }); } // one broken file does not kill the scan
    // Source map may be declared by a response header, not a comment in the file (SourceMap; X-SourceMap is the old name)
    const sm = r.headers && (r.headers.sourcemap || r.headers['x-sourcemap']);
    if (sm) { try { enqueue(new URL(sm, item.url).href, item.depth, 'sourcemap'); } catch (e) { /* broken map URL */ } }
    tick();
    await new Promise((res) => setTimeout(res, 0)); // parsing a file is synchronous: yield the thread to the page between files
  }
  tick();
  while (queue.length && fetched < maxFiles && !(o.isStopped && o.isStopped())) {
    const batch = queue.splice(0, Math.min(conc, maxFiles - fetched));
    await Promise.all(batch.map(run));
  }
  return store;
}

export { auditHtml, cookieTech } from './core/html.js';
export { wordlist } from './core/words.js';
export { parseTrafficExport } from './core/imports.js';
export { fileType, displayText, displayPosition, prettyJs, searchTexts, isMinified } from './core/files.js';
export { view, toJSON, toCSV, toURLs, toPaths, toMarkdown, KIND_LABEL, FORMATS } from './core/export.js';
