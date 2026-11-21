// D2: соответствие находок категориям OWASP Top 10 2025, API Top 10 2023, LLM Top 10 2025, ASVS 5.0, WSTG v4.2 и CWE.
// Правило вычисляется из вида, типа и английского заголовка находки (заголовки переводятся только при выводе). (j) в спецификации — суждение.
// Строка: top10|api|llm|asvs|wstg|cwe
import { ROUTE_KINDS } from './scope.js';
const MAP = {
  'path.admin': 'A01|API5||||284', 'path.debug': 'A02|API8||||489', 'path.files': 'A01|API8||||538', 'path.docs': 'A01|API9||||200', 'path.map': 'A01|API8||||540',
  'path.internal': 'A01|API9|||INFO-05|200', 'path.object': 'A01|API1||||639', 'path.version': '|API9||||', 'path.auth': 'A07|API2||||287', 'param': 'A01|API7||||918',
  'secret': 'A07|API8||||798', 'secret.ai': 'A07|API8|LLM02|||798', 'secret.private-key': 'A04|API8||||321', 'secret.generic': 'A07|API8||||259', 'secret.jwt': 'A04|API8||||798',
  'tech.cve': 'A03|||||1395', 'tech.eol': 'A03|||||1104', 'cloud': 'A02|API8||||',
  'hdr.csp': 'A02|API8||3.4.3||', 'hdr.hsts': 'A02|API8||3.4.1||', 'hdr.nosniff': 'A02|API8||3.4.4||', 'hdr.referrer': 'A02|API8||3.4.5||', 'hdr.framing': 'A02|API8||3.4.6|CLNT-09|1021',
  'hdr.cors': 'A02|API8||3.4.2|CLNT-07|942', 'hdr.disclose': 'A02|API8|||INFO-02|', 'hdr.other': 'A02|API8||||',
  'html.cleartext': 'A04|||||319', 'html.form.cross': 'A01|API8||||201', 'html.xss': 'A05|||3.2.2|CLNT-02|79', 'html.sri': 'A08|||3.6.1|CLNT-06|829', 'html.comment': 'A01||||INFO-05|615',
  'html.error': 'A10||||INFO-05|209', 'html.token': 'A01|||3.5.1||352', 'html.skimmer': 'A08||||CLNT-06|829',
  'code.sink': 'A05|||3.2.2|CLNT-01|79', 'code.postmessage': 'A01|||3.5.5|CLNT-11|346', 'code.route': 'A01||||INFO-07|425', 'code.authz': 'A01|API5||||285', 'code.internal': 'A01|API9|||INFO-05|200',
  'code.todo': 'A01||||INFO-05|615', 'code.proto': 'A05|||||1321', 'code.cspt': 'A01||||CLNT-04|22', 'code.redirect': 'A01||||CLNT-04|601', 'code.jsonp': 'A05||||CLNT-13|79', 'code.trust': 'A05|||3.2.2|CLNT-01|79',
  'code.oauth': 'A07|API2||||', 'code.token-store': 'A07||||CLNT-12|922', 'code.biz': 'A06|API6||||', 'code.devbuild': 'A02|API8|||INFO-05|489', 'code.buildenv': 'A02|API8|||INFO-05|200',
  'graphql.mutation': 'A01|API5|||INFO-06|862', 'graphql.op': '||||INFO-06|', 'cookie': 'A02|API8||3.3.1||614', 'storage': 'A07||||CLNT-12|922',
  'ai.prompt': 'A02||LLM07|||', 'ai': 'A01|API4|LLM10||INFO-06|', 'pii': 'A01|API3||||359', 'privacy': 'A01|||||359', 'supply': 'A03|||||1357', 'identity': 'A02|API8||||', 'realtime': 'A01||||CLNT-10|1385',
  'auth': 'A07|API2||||287', 'infra': '||||INFO-02|', 'mobile': '||||INFO-10|', 'wellknown': '||||INFO-03|', 'web3': 'A08|||||', 'browser': 'A06||||CLNT-01|', 'obfuscation': '||||INFO-05|'
};
export function ruleOf(f) {
  const k = f.kind, u = String(f.url || '');
  if (ROUTE_KINDS.has(k) || k === 'static') { const c = (f.cats || []).find((x) => MAP['path.' + x]); return c ? 'path.' + c : (f.cats || []).includes('param') ? 'param' : k === 'auth' ? 'auth' : null; }
  if (k === 'secret') return /anthropic|openai|huggingface|perplexity|groq|xai|bedrock/.test(f.type || '') ? 'secret.ai' : f.type === 'private-key' ? 'secret.private-key' : f.type === 'generic' ? 'secret.generic' : f.type === 'jwt' ? 'secret.jwt' : 'secret';
  if (k === 'tech') return (f.advisories || []).length ? 'tech.cve' : f.risk ? 'tech.eol' : null;
  if (k === 'config') return /CSP/.test(u) ? 'hdr.csp' : /HSTS|Strict-Transport/.test(u) ? 'hdr.hsts' : /nosniff/.test(u) ? 'hdr.nosniff' : /Referrer/.test(u) ? 'hdr.referrer' : /framing/.test(u) ? 'hdr.framing' : /CORS/.test(u) ? 'hdr.cors' : /^[\w-]+: /.test(u) ? 'hdr.disclose' : 'hdr.other';
  if (k === 'dom') return /HTTP|Mixed content|Password field/.test(u) ? 'html.cleartext' : /Card form|skimmer|GTM|Inline script|SVG or pixel|Hidden frame/.test(u) ? 'html.skimmer' : /another site/.test(u) ? 'html.form.cross' : /javascript:|Inline event/.test(u) ? 'html.xss' : /SRI/.test(u) ? 'html.sri' : /comment/i.test(u) ? 'html.comment' : /Error/.test(u) ? 'html.error' : /token/.test(u) ? 'html.token' : null;
  if (k === 'code') return /^(?:flag|debug-flag|bypass|ghost-route|admin-src)$/.test(f.type) ? 'code.route' : /^biz-/.test(f.type) ? 'code.biz' : MAP['code.' + f.type] ? 'code.' + f.type : null;
  if (k === 'graphql') return /^mutation/.test(u) ? 'graphql.mutation' : 'graphql.op';
  if (k === 'ai') return /System prompt/.test(u) ? 'ai.prompt' : 'ai';
  if (k === 'custom') return /Known-bad|Dependency present|compromised|CDN|not on npm/.test(u) ? 'supply' : null;
  if (k === 'tracker') return 'privacy';
  return MAP[k] ? k : null;
}
export function mapping(f) {
  const r = ruleOf(f), row = r && MAP[r];
  if (!row) return { rule: r, top10: [], api: [], llm: [], asvs: [], wstg: [], cwe: [] };
  const [top10, api, llm, asvs, wstg, cwe] = row.split('|').map((x) => (x ? [x] : []));
  return { rule: r, top10, api, llm, asvs, wstg, cwe: cwe.map((c) => 'CWE-' + c) };
}
export const TOP10_2025 = { A01: 'Broken Access Control', A02: 'Security Misconfiguration', A03: 'Software Supply Chain Failures', A04: 'Cryptographic Failures', A05: 'Injection', A06: 'Insecure Design', A07: 'Authentication Failures', A08: 'Software or Data Integrity Failures', A09: 'Security Logging and Alerting Failures', A10: 'Mishandling of Exceptional Conditions' };
