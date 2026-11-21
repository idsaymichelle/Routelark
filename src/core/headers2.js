// Document header checks: Permissions-Policy, reporting, COOP/COEP, HSTS preload readiness, Server-Timing,
// Clear-Site-Data, CSP additions, debug headers and cache/CDN signs. Only reads headers already fetched.
const SENSITIVE = /^(?:camera|microphone|geolocation|display-capture|payment|usb|serial|hid|bluetooth|midi|publickey-credentials-get|publickey-credentials-create|identity-credentials-get|local-network-access|window-management)$/;
const TIMING_NAMES = /^(?:db|database|sql|app|upstream|pod|host|node|region|az|backend)$/i;
const CACHE_WHY = 'A shared cache may store this response. Confirm by hand, in a clean session, whether the response changes with login state';

export function extraHeaderFindings(h, isHttps, url) {
  const out = [], add = (risk, title, why) => out.push({ risk, title, why });
  const pp = h['permissions-policy'];
  if (!pp) add(0, 'No Permissions-Policy', h['feature-policy'] ? 'Only the deprecated Feature-Policy is sent: modern browsers ignore it' : 'Browser features like camera or geolocation are not restricted for embedded frames');
  else for (const m of pp.matchAll(/([a-z][a-z-]*)\s*=\s*(\*|\([^)]*\)|[^,\s]+)/gi)) if (m[1] !== 'report-to' && m[2] === '*') add(SENSITIVE.test(m[1]) ? 1 : 0, 'Permissions-Policy allows ' + m[1] + ' for any origin', '* lets any embedded frame use the feature: check whether the page embeds third-party frames');
  const re = h['reporting-endpoints'] || '', names = new Set(Array.from(re.matchAll(/([\w-]+)\s*=\s*"([^"]*)"/g), (m) => { if (/^http:/.test(m[2])) add(0, 'Reporting-Endpoints: endpoint is not HTTPS', 'Browsers ignore non-secure reporting endpoints'); return m[1]; }));
  if (h['report-to'] && !re) add(0, 'Report-To without Reporting-Endpoints', 'Reporting-Endpoints should be used in preference to Report-To');
  for (const m of String(h['content-security-policy'] || '').matchAll(/report-to\s+([\w-]+)/g)) if (re && !names.has(m[1])) add(0, 'Report target ' + m[1] + ' is not declared', 'Reports go nowhere: the name is not in Reporting-Endpoints');
  const coop = (h['cross-origin-opener-policy'] || '').trim(), coep = (h['cross-origin-embedder-policy'] || '').trim();
  if (/^unsafe-none/.test(coop)) add(0, 'Cross-Origin-Opener-Policy is unsafe-none', 'Pages that open this one, or that it opens, keep a window reference to it');
  if (/^same-origin\b/.test(coop) && !/^(?:require-corp|credentialless)/.test(coep)) add(0, 'Cross-Origin-Embedder-Policy missing: page is not cross-origin isolated', 'Hardening note: isolation needs COOP same-origin and COEP require-corp or credentialless');
  const sts = h['strict-transport-security'] || '', age = /max-age=(\d+)/i.exec(sts);
  if (isHttps && age && +age[1] >= 31536000 && (!/includeSubDomains/i.test(sts) || !/preload/i.test(sts))) add(0, 'HSTS is not ready for preload', 'Missing: ' + ['includeSubDomains', 'preload'].filter((d) => !new RegExp(d, 'i').test(sts)).join(', '));
  const st = h['server-timing'];
  if (st && (/desc=/.test(st) || st.split(',').some((x) => TIMING_NAMES.test(x.trim().split(/[;=\s]/)[0])))) add(0, 'Server-Timing exposes internal metrics', 'The header may expose application and infrastructure details');
  if ((h['timing-allow-origin'] || '').trim() === '*') add(0, 'Timing-Allow-Origin: * lets any site read timings', 'Detailed timings help cross-site leak attacks');
  const csd = h['clear-site-data'];
  if (csd && csd.split(',').some((d) => !/^\s*"[\w*]+"\s*$/.test(d))) add(0, 'Clear-Site-Data values are not quoted: header is invalid', 'Each directive must be in double quotes, otherwise it is ignored');
  const csp = h['content-security-policy'], script = (/(?:^|;)\s*script-src\s+([^;]*)/i.exec(csp || '') || [])[1] || '';
  if (/'strict-dynamic'/.test(script) && !/'nonce-|'sha(?:256|384|512)-/.test(script)) add(0, 'CSP: strict-dynamic without nonce or hash', 'strict-dynamic only trusts scripts loaded by a nonce or hash-approved script');
  if (!csp && h['content-security-policy-report-only']) add(1, 'CSP is only Report-Only, nothing is blocked', 'The policy only reports violations');
  if (h['x-debug-token-link']) add(1, 'X-Debug-Token-Link: profiler link in response', 'A debug profiler is on: open the link yourself while logged out');
  for (const k of ['x-debug-token', 'x-runtime', 'via', 'x-backend-server']) if (h[k]) add(0, k + ': ' + h[k], 'Reveals the implementation');
  const cc = new Map(String(h['cache-control'] || '').toLowerCase().split(',').map((p) => { const [k, v] = p.trim().split('='); return [k, v]; }));
  const cacheable = (+cc.get('max-age') > 0 || +cc.get('s-maxage') > 0) && !cc.has('private') && !cc.has('no-store');
  const priv = cc.has('private') || cc.has('no-store'), setCookie = !!h['set-cookie'];
  const hitHdr = [['cf-cache-status', /^hit$/i], ['x-nextjs-cache', /^(?:hit|stale)$/i], ['x-vercel-cache', /^hit$/i], ['x-cache', /(?:^|,\s*)(?:TCP_\w*)?HIT\b/i]].find(([k, r]) => h[k] && r.test(h[k].trim()));
  if (setCookie && cacheable) add(1, 'Response sets a cookie and looks cacheable', CACHE_WHY);
  if (hitHdr && priv) add(1, 'CDN returned a cached copy of a response marked private or no-store', 'The CDN overrides the origin, or a cache rule ignores Cache-Control. ' + CACHE_WHY);
  if (setCookie && cacheable && !h.vary) add(0, 'No Vary on a response that sets a cookie', CACHE_WHY);
  if (hitHdr) add(0, 'Served from a cache: ' + hitHdr[0] + ' = ' + h[hitHdr[0]].trim().slice(0, 40), /,/.test(h[hitHdr[0]]) ? 'One of several cache layers returned a cached copy' : 'This response came from a cache');
  if (+h.age > 0) add(0, 'Age: ' + (+h.age) + ': response was cached before it reached you', 'This response came from a cache');
  if (url && /\.(?:css|js|png|jpe?g|svg|ico|woff2?)$/i.test(url.split(/[?#]/)[0]) && !priv && /text\/html/i.test(h['content-type'] || '')) add(1, 'Static-looking URL returns HTML: check web cache deception', 'Test by hand, logged out, with an added path segment; do not send this from the tool');
  return out;
}
