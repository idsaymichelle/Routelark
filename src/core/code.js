// Spots in client code for manual review. Noise is suppressed: every rule needs context.
const SINK = /(\.\s*(?:innerHTML|outerHTML)\s*\+?=(?!=)|\[\s*['"](?:innerHTML|outerHTML)['"]\s*\]\s*\+?=(?!=)|\.\s*setHTMLUnsafe\s*\(|\.\s*insertAdjacentHTML\s*\(|document\s*\.\s*write(?:ln)?\s*\(|dangerouslySetInnerHTML|(?:^|[^\w.$])eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["'`]|\.\s*html\s*\(\s*[^)\s])/g;
const SOURCE = /location\s*\.\s*(?:hash|search|href)|document\s*\.\s*(?:referrer|URL|documentURI)|window\s*\.\s*name|URLSearchParams|\.\s*data\b/;
// Window only: WebSocket, Worker and BroadcastChannel also have onmessage, but their origin is not checked
const LISTENER = /(?:^|[^\w$.])addEventListener\s*\(\s*(["'`])message\1|\b(?:window|self|globalThis)\s*\.\s*(?:addEventListener\s*\(\s*(["'`])message\2|onmessage\s*=(?!=))|(?:^|[^\w$.])onmessage\s*=(?!=)/g;
// Weak origin checks (indexOf, endsWith, unanchored regex) let lookalike domains through
const ORIGIN_WEAK = /\.origin\s*\.\s*(?:indexOf|includes|search|match|startsWith|endsWith)\s*\(|\/(?!\^)[^/\n]{2,200}\/[gimsuy]*\.test\(\s*(?:\w+\.)?origin\s*\)|origin\s*===?\s*['"]null['"]/;
const ORIGIN_EXACT = /\b(?:event|e|ev|evt|msg|message)\s*\.\s*origin\s*(?:===?|!==?)\s*(?:['"`]https?:\/\/[^'"`]+['"`]|[\w.$]*(?:ALLOWED|allowed|[Oo]rigin|ORIGIN)[\w.$]*)|\/\^[^\n]{2,200}?\$\/[gimsuy]*\.test\(\s*(?:\w+\.)?origin\s*\)|allowedOrigins?\s*\.\s*(?:includes|has|indexOf)\s*\(\s*\w+\s*\.\s*origin\s*\)/;
const PP_DEF = /\b(?:merge|deepMerge|deepExtend|extend|assign|deepAssign|assignDeep|defaultsDeep|mergeWith|setDeep|deepSet|setPath|setIn)\s*(?:=\s*(?:function\b|\(|async\b)|[:(]\s*function\b|\()/g;
const PP_LOOP = /\bfor\s*\(\s*(?:const|let|var)\s+(\w+)\s+in\s+\w+/;
const PP_GUARD = /__proto__|["'`](?:constructor|prototype)["'`]|Object\.create\(\s*null\s*\)|Object\.freeze\(\s*Object\.prototype\s*\)/;
const SOURCE_PP = /JSON\.parse\(|location\s*\.\s*(?:hash|search)|URLSearchParams|searchParams\s*\.\s*get\(/;
const PP_STRIP_ONCE = /\.replace\(\s*(?:\/__proto__\/g?|['"`]__proto__['"`])\s*,\s*['"`]{2}\s*\)/;
const PP_KEY_CMP = /(?:===?|!==?)\s*['"`]__proto__['"`]/;
const CSPT_SRC = /\b(?:location\s*\.\s*(?:pathname|hash|search|href)|URLSearchParams|searchParams\s*\.\s*get\(|\.params\s*\.\s*\w+|useParams\s*\(|route\s*\.\s*params|\$route\s*\.\s*params|snapshot\s*\.\s*params|match\s*\.\s*params|getParameter\s*\()/;
const CSPT_SINK = /\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|\$http\.\w+|\$\.(?:ajax|get|post))\s*\(\s*(`[^`]*\$\{(?!\s*encodeURIComponent\()[^}]*\}[^`]*`|[^,)]*\+\s*(?!encodeURIComponent)[\w.$[\]]+)/g;
const PM_STAR = /\.postMessage\s*\((?:[^,()]|\([^()]*\)){0,300},\s*['"`]\*['"`]\s*\)/g;
const PM_SECRET = /\b(?:token|password|passwd|secret|session|auth|jwt|bearer|apiKey|api_key|cookie)\b/i;
const NG_BYPASS = /\.\s*bypassSecurityTrust(Html|Style|Script|Url|ResourceUrl)\s*\(\s*(?!(['"`])[^'"`$]*\2\s*\))/g;
const VUE_VHTML = /\bv-html\s*=\s*"(?!\s*['"])[^"]*"|\bv-html\s*=\s*'(?!\s*["'])[^']*'/g;
const REACT_DSIH = /dangerouslySetInnerHTML\s*[=:]\s*\{\s*\{?\s*__html\s*:\s*(?!\s*["'`][^"'`$]*["'`]\s*\})/g;
const REACT_SANITIZED = /^dangerouslySetInnerHTML\s*[=:]\s*\{\s*\{?\s*__html\s*:\s*\w*(?:DOMPurify|purify|sanitize|sanitizeHtml)\w*\s*(?:\.\s*\w+\s*)?\(/;
const TT_PASS = /createPolicy\s*\(\s*[^,]{1,80},\s*\{[^}]{0,300}?(?:createHTML|createScript|createScriptURL)\s*:\s*(?:\(?\s*(\w+)\s*\)?\s*=>\s*\1\s*[,}]|function\s*\(\s*(\w+)\s*\)\s*\{\s*return\s+\2\s*;?\s*\})|createPolicy\s*:\s*\(\s*\w+\s*,\s*(\w+)\s*\)\s*=>\s*\3\b/g;
const JSONP_DYN = /[?&](?:callback|jsonp|cb)=(?:['"`]\s*\+|\$\{)|searchParams\s*\.\s*set\s*\(\s*['"`](?:callback|jsonp|cb)['"`]\s*,\s*(?!['"`])/g;
const REDIR_SINK = /\blocation\s*\.\s*(?:href|assign|replace)\s*(?:=(?!=)|\()|\bwindow\s*\.\s*location\s*=(?!=)|\bwindow\.open\s*\(/g;
const REDIR_SRC = /location\s*\.\s*(?:hash|search)|URLSearchParams|searchParams\s*\.\s*get\(|\.query\b|\b(?:returnUrl|return_url|redirect_?uri|redirectUrl|returnTo)\b/;
// The only defence is an origin comparison; startsWith('/') lets //evil.example through
const REDIR_CHECK = /\.origin\s*[!=]==?\s*(?:window\.)?location\.origin|location\.origin\s*[!=]==?\s*[\w.]+\.origin/;
const ROUTE = /\b(?:path|redirect)\s*:\s*["'`](\/[\w\/:.-]{2,80})["'`]/g;
const ROUTE_HIDDEN = /admin|dashboard|internal|beta|staging|debug|superuser|manage|backoffice/i;
const AUTHZ = /\b(?:isAdmin|is_admin|isSuperuser|isStaff|hasRole\s*\(|role\s*===?\s*["']admin["'])/;
const PRIVATE_IP = /\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b/g;
const FLAG_CALL = /\b(?:useFlag|isEnabled|getFeatureFlag|featureEnabled|variation)\(\s*(["'`])([\w.:-]{2,80})\1/g;
const DEBUG_NAME = /\b(debugMode|isDebug|devMode|debugEnabled|showDebug)\b\s*(?:[:=]|&&|\?|\))/g;
const BYPASS = /\b(bypassAuth|skipAuth|disableAuth|authDisabled|noAuth)\b\s*(?:[:=]|&&|\?|\))/g;
const BIZ_CALC = /\b(?:price|total|subtotal|amount)\w*\s*[*+-]\s*[\w.()]{1,40}|[*-]\s*(?:\(\s*)?[\w.]*\b(?:discount|coupon|promo)\w*/gi;
const BIZ_CTX = /\b(?:checkout|order|cart|payment|invoice|submit|pay)\b/i;
const BIZ_LIMIT = /\b(MAX_(?:LOGIN_|AUTH_|RETRY_|RETRIES|ATTEMPTS|TRIES|QUOTA|REQUESTS)[A-Z_]{0,30}|maxAttempts|rateLimit|retryLimit|maxRetries)\s*[:=]\s*(\d{1,6})\b/g;
const TOKEN_STORE = /\b(localStorage|sessionStorage)(?:\.setItem\(\s*(["'`])(?![\w.-]*(?:author|accessib))([\w.-]*(?:token|jwt|access|refresh|session|auth)[\w.-]*)\2|\s*\.\s*((?![\w]*(?:author|accessib))\w*(?:token|jwt|refresh|session)\w*)\s*=(?!=))/gi;
const LOGOUT_FN = /\b(?:logout|logOut|signOut|signout|handleLogout|onLogout)\s*[=:]\s*(?:async\s*)?(?:function\b|\(|\w+\s*=>)|\bfunction\s+(?:logout|logOut|signOut|signout|handleLogout|onLogout)\s*\(|(?:^|[\s;{}])(?:async\s+)?(?:logout|logOut|signOut|signout)\s*\([^)]*\)\s*\{/g;
const BC_NEW = /new\s+BroadcastChannel\s*\(\s*['"`]([^'"`]{1,64})['"`]\s*\)/g;
const TODO = /(?:\/\/|\/\*)\s*(?:TODO|FIXME|HACK)\b/;

// Line-number index is built once per text; otherwise every finding rescans the whole file
let lcText = null, lcNl = [];
function lineCol(text, pos) {
  if (text !== lcText) { lcText = text; lcNl = []; for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) lcNl.push(i); }
  let lo = 0, hi = lcNl.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (lcNl[mid] < pos) lo = mid + 1; else hi = mid; }
  return { line: lo + 1, col: pos - (lo ? lcNl[lo - 1] : -1) };
}
const snip = (text, pos) => text.slice(Math.max(0, pos - 60), pos + 120).replace(/\s+/g, ' ').trim();

export function codeFindings(text, file) {
  const out = [];
  const add = (type, title, risk, pos) => { const lc = lineCol(text, pos); out.push({ type, title, risk, file, line: lc.line, col: lc.col, snippet: snip(text, pos) }); };
  let m, n = 0;
  SINK.lastIndex = 0;
  while ((m = SINK.exec(text)) && n < 50) {
    if (m[1] === 'dangerouslySetInnerHTML' || !SOURCE.test(text.slice(Math.max(0, m.index - 260), m.index + 260))) continue; // the source may come before the sink: const v = location.hash; el.innerHTML = v
    n++; add('sink', 'DOM sink near external data: ' + m[1].replace(/\s+/g, '').replace(/^\./, '').slice(0, 30), 2, m.index);
  }
  LISTENER.lastIndex = 0; n = 0;
  while ((m = LISTENER.exec(text)) && n < 20) {
    const body = text.slice(m.index, m.index + 500);
    n++;
    if (!/\.\s*data\b/.test(body)) { add('postmessage', 'message handler, body not read', 1, m.index); continue; } // handler passed by name: its body lies beyond the window
    const weak = ORIGIN_WEAK.test(body.replace(/\/\^[^\n]{2,200}?\$\/[gimsuy]*\.test\(/g, '')), ok = !weak && ORIGIN_EXACT.test(body);
    add('postmessage', weak ? 'message handler uses a weak origin check' : ok ? 'message handler checks origin' : 'message handler without origin check', ok ? 0 : 2, m.index);
  }
  PM_STAR.lastIndex = 0; n = 0;
  while ((m = PM_STAR.exec(text)) && n++ < 20) add('postmessage', "postMessage to any origin ('*')", PM_SECRET.test(m[0]) ? 2 : 1, m.index);
  // Prototype pollution: recursive merge writing by a for-in key without a guard
  PP_DEF.lastIndex = 0; n = 0;
  while ((m = PP_DEF.exec(text)) && n < 20) {
    const w = text.slice(m.index, m.index + 500), loop = PP_LOOP.exec(w);
    if (!loop || PP_GUARD.test(w) || !new RegExp('\\[\\s*' + loop[1] + '\\s*\\]\\s*=(?!=)').test(w)) continue;
    n++; const reach = SOURCE_PP.test(text.slice(Math.max(0, m.index - 300), m.index + 600)); // "user keys" only if a source is near the function
    add('proto', reach ? 'Recursive merge with user-shaped keys' : 'Recursive merge without a __proto__ guard', reach ? 2 : 1, m.index);
  }
  if ((m = PP_STRIP_ONCE.exec(text))) add('proto', 'Key filter removes __proto__ in one pass', 2, m.index);
  else if ((m = PP_KEY_CMP.exec(text)) && !/\bconstructor\b|\bprototype\b/.test(text.slice(Math.max(0, m.index - 200), m.index + 200))) add('proto', 'Key filter checks __proto__ but not constructor/prototype', 2, m.index);
  // CSPT: request URL built from a route value or URL without encodeURIComponent
  CSPT_SINK.lastIndex = 0; n = 0;
  while ((m = CSPT_SINK.exec(text)) && n < 50) {
    if (!CSPT_SRC.test(text.slice(Math.max(0, m.index - 400), m.index))) continue;
    n++; const state = /method\s*:\s*['"`](?:POST|PUT|PATCH|DELETE)['"`]/i.test(text.slice(m.index, m.index + 300));
    add('cspt', 'Request URL built from a route or URL value: ' + m[1].replace(/\s+/g, ' ').slice(0, 40), state ? 3 : 2, m.index);
  }
  NG_BYPASS.lastIndex = 0; n = 0;
  while ((m = NG_BYPASS.exec(text)) && n++ < 20) add('trust', 'Angular trust bypass: bypassSecurityTrust' + m[1], 2, m.index);
  VUE_VHTML.lastIndex = 0; n = 0;
  while ((m = VUE_VHTML.exec(text)) && n++ < 20) add('trust', 'Vue v-html with an expression', 2, m.index);
  REACT_DSIH.lastIndex = 0; n = 0;
  while ((m = REACT_DSIH.exec(text)) && n++ < 20) { const san = REACT_SANITIZED.test(text.slice(m.index, m.index + 200)); add('trust', san ? 'dangerouslySetInnerHTML with sanitizer call (check config)' : 'dangerouslySetInnerHTML with non-literal value', san ? 0 : 2, m.index); }
  TT_PASS.lastIndex = 0; n = 0;
  while ((m = TT_PASS.exec(text)) && n++ < 5) add('trust', 'Trusted Types policy returns its input unchanged', 1, m.index);
  JSONP_DYN.lastIndex = 0; n = 0;
  while ((m = JSONP_DYN.exec(text)) && n++ < 10) add('jsonp', 'JSONP with a dynamic callback name', 2, m.index);
  REDIR_SINK.lastIndex = 0; n = 0;
  while ((m = REDIR_SINK.exec(text)) && n < 20) {
    const before = text.slice(Math.max(0, m.index - 300), m.index), after = text.slice(m.index, m.index + 120);
    if (!REDIR_SRC.test(before.slice(-200) + after) || REDIR_CHECK.test(before)) continue;
    n++; add('redirect', 'Redirect target from URL input', 2, m.index);
  }
  ROUTE.lastIndex = 0; const seen = new Set();
  while ((m = ROUTE.exec(text))) if (ROUTE_HIDDEN.test(m[1]) && !seen.has(m[1])) { seen.add(m[1]); add('route', 'Hidden client route: ' + m[1], 1, m.index); }
  const az = AUTHZ.exec(text);
  if (az) add('authz', 'Client-side permission check', 1, az.index);
  const ips = new Set();
  PRIVATE_IP.lastIndex = 0;
  while ((m = PRIVATE_IP.exec(text)) && ips.size < 10) if (!ips.has(m[0]) && !/\d\.$/.test(text.slice(m.index - 2, m.index))) { ips.add(m[0]); add('internal', 'Internal address: ' + m[0], 1, m.index); }
  const once = (re, cap, fn) => { const seen = new Set(); re.lastIndex = 0; let x; while ((x = re.exec(text)) && seen.size < cap) { const k = fn(x); if (k && !seen.has(k[1])) { seen.add(k[1]); add(k[0], k[1], k[2], x.index); } } };
  once(FLAG_CALL, 30, (x) => ['flag', 'Feature flag: ' + x[2], 0]);
  once(DEBUG_NAME, 10, (x) => ['debug-flag', 'Debug switch in client code: ' + x[1], 1]);
  once(BYPASS, 10, (x) => ['bypass', 'Auth bypass switch in client code: ' + x[1], 2]);
  once(BIZ_LIMIT, 10, (x) => ['biz-limit', 'Limit in client code: ' + x[1] + ' = ' + x[2], 1]);
  once(BIZ_CALC, 10, (x) => (BIZ_CTX.test(text.slice(Math.max(0, x.index - 120), x.index + 120)) ? ['biz-calc', 'Price or discount calculated in client code', 1] : null));
  once(TOKEN_STORE, 20, (x) => ['token-store', 'Token written to ' + x[1] + ': ' + (x[3] || x[4]), 2]);
  // Key in a constant: const KEY = 'token'; localStorage.setItem(KEY, t)
  once(/\b(localStorage|sessionStorage)\.setItem\(\s*([A-Za-z_$][\w$]{0,40})\s*,/g, 20, (x) => { const d = new RegExp('\\b' + x[2].replace(/\$/g, '\\$') + '\\s*=\\s*["\'`]([\\w.-]*(?:token|jwt|refresh|session)[\\w.-]*)["\'`]', 'i').exec(text); return d && !/author|accessib/i.test(d[1]) ? ['token-store', 'Token written to ' + x[1] + ': ' + d[1], 2] : null; });
  if (/\.setItem\(\s*["'`][\w.-]*(?:token|jwt)|(?:local|session)Storage\s*\.\s*\w*(?:token|jwt)\w*\s*=/i.test(text)) once(LOGOUT_FN, 5, (x) => (/removeItem\s*\(|\.clear\s*\(\s*\)/.test(text.slice(x.index, x.index + 600)) ? null : ['token-store', 'Logout function does not clear stored tokens', 1]));
  once(BC_NEW, 5, (x) => { const w = /\.postMessage\s*\(([^;]{0,200})\)/.exec(text.slice(x.index, x.index + 800)); return w && /token|jwt|bearer|password|secret|session/i.test(w[1]) ? ['token-store', 'BroadcastChannel carries a token: ' + x[1], 2] : null; });
  const td = TODO.exec(text);
  if (td) add('todo', 'Developer note (TODO/FIXME)', 0, td.index);
  return out;
}
export const CODE_WHY = {
  sink: 'Check whether an attacker can control the value and whether a sanitizer or CSP is in place',
  postmessage: 'Any site can send a message to this window',
  route: 'The screen may be reachable by a direct link; does the server check permissions?',
  authz: 'A permission decision made in the browser is bypassed by a direct API request',
  internal: 'Internal network address in public code',
  todo: 'A leftover note may point to unfinished work',
  proto: 'Recursive merge copies keys from the input; check whether a key named __proto__ or constructor.prototype reaches Object.prototype',
  cspt: 'The URL is built from a route or URL value without encodeURIComponent; a value like ../ can change the endpoint, and a state-changing request makes this CSRF-like',
  trust: 'Raw HTML or a trust bypass from a non-literal value; check where the value comes from and whether it is sanitized',
  jsonp: 'JSONP endpoints that echo an arbitrary callback name can run attacker JavaScript on the endpoint origin; check the server allowlist',
  'token-store': 'Any script on the page can read Web Storage and join a BroadcastChannel: check that tokens are cleared on logout and could move to an HttpOnly cookie',
  oauth: 'OAuth parameters in a literal URL: check the flow against RFC 9700 on the real requests',
  devbuild: 'Development or debug code in the production build: check whether it is reachable',
  devtools: 'Debug or API console tool on the client: check whether it is intended for production',
  buildenv: 'Build-time variables and paths end up in public code: check that no secret or internal detail is among them',
  flag: 'A feature flag name: check whether the server also enforces the feature, or only the UI hides it',
  'debug-flag': 'A debug switch shipped to users: check whether it can be turned on from the browser and what it reveals',
  bypass: 'An auth bypass switch in client code: check whether the server honours it',
  'biz-limit': 'A limit enforced only in the browser can be skipped by calling the API directly; check the server',
  'biz-calc': 'The browser computes a price or discount: check that the server recalculates it and ignores client totals',
  'admin-src': 'An admin screen is shipped to every visitor: check that its API calls require admin rights on the server',
  'ghost-route': 'The route exists in code but no link on the page points to it: try it directly and check server-side permissions',
  redirect: 'A redirect target from URL input can send users to another site; check for an origin or path check'
};
