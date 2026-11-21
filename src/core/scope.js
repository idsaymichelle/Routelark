// What may be requested. Shared by the collector (on the page) and the tab: one set of rules.
// Whole path parts, not substrings: /assets/deleteModal.js is a normal file, /account/delete is an action
// Does the path hold a logout/delete address? Decoded up to 3 times: %256Cogout -> %6Cogout -> logout. One rule for all checks
export function deniedPath(path) {
  for (let i = 0; i < 3; i++) { try { const d = decodeURIComponent(path); if (d === path) break; path = d; } catch (e) { break; } }
  return DEFAULT_DENY.test(path);
}
export const DEFAULT_DENY = /(?:^|[\/._?&=-])(?:log-?out|sign-?out|log_out|sign_out|deactivate|unsubscribe|terminate|erase|delete|remove|destroy|revoke)(?:$|[\/._?&=-])/i;
// Only JS, source maps, manifests and OpenAPI specs are downloaded. API addresses never.
export const FETCHABLE = /\.(?:m?js|map|webmanifest)$|\.LICENSE\.txt$|(?:^|\/)(?:asset-manifest|build-manifest|manifest)\.json$|(?:openapi|swagger|api-docs)[\w.-]*\.(?:json|ya?ml)$/i;
// Service files fetched only on direct request (robots, sitemap, security.txt)
// Address-finding kinds: one list for export, program scope, hide rules, map and standards mapping
export const ROUTE_KINDS = new Set(['api', 'ws', 'auth', 'debug', 'docs', 'page', 'external']);
export const FORCEABLE = /(?:^|\/)(?:robots|security)\.txt$|(?:^|\/)sitemap[\w.-]*\.xml$|^\/(?:\.well-known\/(?:openid-configuration|oauth-authorization-server|apple-app-site-association|assetlinks\.json|webauthn)|ads\.txt|humans\.txt|llms\.txt)$/i;

const hostOf = (u) => { try { return new URL(u).host; } catch (e) { return ''; } };
const SHARED = /\.(?:github\.io|gitlab\.io|vercel\.app|netlify\.app|herokuapp\.com|pages\.dev|workers\.dev|web\.app|firebaseapp\.com|appspot\.com|azurewebsites\.net|cloudfront\.net|amazonaws\.com|onrender\.com|fly\.dev|blogspot\.com|wordpress\.com|myshopify\.com|notion\.site|wixsite\.com|webflow\.io|glitch\.me|repl\.co|replit\.dev|surge\.sh|ngrok\.io|ngrok-free\.app|bitbucket\.io|neocities\.org|hashnode\.dev|lovable\.app|hf\.space|substack\.com|tumblr\.com|framer\.website|github\.dev|codesandbox\.io|stackblitz\.io|deno\.dev|railway\.app|up\.railway\.app|azurestaticapps\.net|cloudfunctions\.net|run\.app|r2\.dev|supabase\.co)$/;
const SLD = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'ltd', 'plc', 'me', 'nhs', 'sch', 'mil', 'nom', 'gen', 'biz', 'info', 'int']);
// shortcut: no Public Suffix List; domains like x.github.io count as one site with github.io, add PSL for accuracy
export function siteOf(host) {
  host = String(host).toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
  if (/^[\d.]+$/.test(host) || host.includes(':') || !host.includes('.')) return host;
  if (SHARED.test(host)) return host; // shared hosting: neighbouring subdomains belong to different people
  const p = host.split('.');
  const n = p.length > 2 && SLD.has(p[p.length - 2]) && p[p.length - 1].length === 2 ? 3 : 2;
  return p.slice(-n).join('.');
}
function hostMatch(p, h) { p = p.toLowerCase(); h = h.toLowerCase(); return p.startsWith('*.') ? (h === p.slice(2) || h.endsWith(p.slice(1))) : p === h; }

export function makeScope(o) {
  const pageHost = hostOf(o.pageUrl || ''), site = siteOf(pageHost), allow = o.allowHosts || [], deny = o.denyHosts || [];
  return {
    check(url, force) {
      let u; try { u = new URL(url); } catch (e) { return { ok: false, reason: 'bad-url' }; }
      if (!/^https?:$/.test(u.protocol)) return { ok: false, reason: 'protocol' };
      if (o.self && u.href.split('#')[0] === o.self) return { ok: false, reason: 'self' };
      const h = u.hostname.replace(/\.$/, '');
      if (deny.some((p) => hostMatch(p, u.host) || hostMatch(p, h))) return { ok: false, reason: 'deny-host' };
      const own = u.host === pageHost || h === site || h.endsWith('.' + site);
      const listed = allow.some((p) => hostMatch(p, u.host) || hostMatch(p, h));
      if (!own && !listed && !o.fetchExternal) return { ok: false, reason: 'external-host' };
      if (deniedPath(u.pathname + u.search)) return { ok: false, reason: 'deny-path' };
      if (!FETCHABLE.test(u.pathname) && !(force && FORCEABLE.test(u.pathname))) return { ok: false, reason: 'not-js' };
      return { ok: true };
    }
  };
}

// The response looks like a WAF check page or a rate limit. Ordinary 403/404 and words in JS do not count.
export function blockedReason(r) {
  const h = r.headers || {};
  if (r.status === 429) return 'rate limit (429)';
  if (h['cf-mitigated'] === 'challenge') return 'Cloudflare challenge';
  const html = /text\/html/i.test(h['content-type'] || '');
  if (html && (r.status === 403 || r.status === 503) && /cf-chl|challenge-platform|_Incapsula_Resource|captcha-delivery|awswaf/i.test(r.text || '')) return 'WAF challenge page';
  return null;
}

const num = (v, d, lo, hi) => { v = Number(v); return Math.min(hi, Math.max(lo, Number.isFinite(v) ? v : d)); };
// Settings come from the tab; the collector still clamps them to hard limits
export function clampSettings(s) {
  s = s || {};
  return {
    delay: num(s.delay, 500, 300, 2000),
    budget: num(s.budget, 400, 1, 2000),
    depth: num(s.depth, 3, 1, 4),
    cookies: s.cookies === true,
    allowHosts: Array.isArray(s.allowHosts) ? s.allowHosts.filter((x) => typeof x === 'string' && /^[\w*.-]+(?::\d+)?$/.test(x) && !/^\*(?:\.[^.:]*)?(?::\d+)?$/.test(x)).slice(0, 50) : []
  };
}
