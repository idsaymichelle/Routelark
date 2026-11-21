// D4, D8, D9: файлы .well-known (OIDC discovery, AASA, assetlinks, webauthn), ads/humans/llms.txt и следы мобильных приложений.
// Файлы берутся одним GET каждый в seeds (переключатель служебных файлов); change-password не читается — он работает через редирект.
import { siteOf } from './scope.js';
export const WELL_KNOWN = ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/.well-known/openid-configuration', '/.well-known/oauth-authorization-server', '/.well-known/apple-app-site-association', '/.well-known/assetlinks.json', '/.well-known/webauthn', '/ads.txt', '/humans.txt', '/llms.txt'];
const NAME = /\/(?:\.well-known\/(openid-configuration|oauth-authorization-server|apple-app-site-association|assetlinks\.json|webauthn|security\.txt)|(ads|humans|llms)\.txt)$/;
export const isWellKnown = (path) => NAME.test(path);

export function discoveryFindings(doc, prefix) {
  const out = [], arr = (k) => (Array.isArray(doc[k]) ? doc[k].slice(0, 50).map(String) : null), add = (title, risk, why) => out.push({ kind: 'auth', title, risk, why: [why] });
  if (typeof doc.issuer === 'string' && doc.issuer.replace(/\/$/, '') !== prefix.replace(/\/$/, '')) add('Discovery issuer does not match the URL', 1, 'OIDC Discovery: issuer must equal the URL prefix the document was fetched from');
  if (['authorization_endpoint', 'token_endpoint', 'jwks_uri'].some((k) => /^http:\/\//.test(doc[k] || ''))) add('Discovery endpoint not https', 3, 'Tokens or keys travel over plain http');
  const rt = arr('response_types_supported') || [], gt = arr('grant_types_supported') || [], cm = arr('code_challenge_methods_supported'), rm = arr('response_modes_supported') || [];
  if (rt.some((x) => /(?:^|\s)token(?:\s|$)/.test(x))) add('Server advertises implicit response types', 2, 'RFC 9700: clients SHOULD NOT use the implicit grant; check whether the server still issues tokens this way');
  if (gt.includes('implicit')) add('Server advertises implicit grant', 2, 'RFC 9700: clients SHOULD NOT use the implicit grant; check whether the server still issues tokens this way');
  if (!cm) add('Server does not advertise PKCE', 1, 'RFC 9700: public clients MUST use PKCE; check whether the server supports and enforces it');
  else if (cm.includes('plain')) add('Server accepts plain PKCE', 2, 'RFC 9700: use S256, plain does not protect the code');
  if (rm.includes('fragment') && rt.some((x) => /token/.test(x))) add('Tokens returned in fragment', 1, 'Tokens in the URL fragment end up in history and can leak through scripts');
  if (/[?#]/.test(doc.issuer || '')) add('Issuer has query or fragment', 1, 'OIDC Discovery: the issuer must not contain a query or fragment');
  return out;
}

// Возвращает { simple: [...], hits: [...] } или null, если файл не похож на ожидаемый (заглушка SPA)
export function wellKnownFile(text, url, pageHost) {
  text = String(text).slice(0, 65536);
  const m = NAME.exec(new URL(url).pathname); if (!m) return null;
  const name = m[1] || m[2] + '.txt', simple = [], hits = [], info = (title, risk, why, kind) => simple.push({ kind: kind || 'wellknown', title, risk, why: [why] });
  if (/^\s*</.test(text)) return { simple: [], hits: [], miss: true };
  if (m[2]) {
    if (name === 'ads.txt') { const n = text.split('\n').filter((l) => /^\s*[\w.-]+\s*,/.test(l)).length; if (n) info('ads.txt: ' + n + ' seller records', 0, 'Advertising sellers authorised for this site: shows ad partners'); }
    if (name === 'humans.txt' && text.trim()) info('humans.txt present', 0, 'Team and contact notes: check for names and addresses useful for social engineering');
    if (name === 'llms.txt') { const links = Array.from(text.matchAll(/\]\((\S{1,300}?)\)/g), (x) => x[1]).slice(0, 100); info('llms.txt: ' + links.length + ' links', 0, 'Links the site offers to AI crawlers: check for pages not linked elsewhere'); links.forEach((l) => hits.push({ raw: l, via: 'llms' })); }
    return { simple, hits };
  }
  if (name === 'security.txt') { // RFC 9116: Contact и Expires обязательны, просроченный файл не читают
    const F = (k) => (new RegExp('^' + k + ':[ \\t]*(.+)$', 'im').exec(text) || [])[1];
    if (!F('Contact')) info('security.txt: no Contact field', 1, 'RFC 9116: Contact is required, so researchers have nobody to report to');
    const ex = F('Expires'), t = ex && Date.parse(ex);
    if (!ex) info('security.txt: no Expires field', 1, 'RFC 9116: Expires is required, so the file can go stale unnoticed');
    else if (t < Date.now()) info('security.txt expired: ' + ex.trim(), 1, 'RFC 9116: an expired file should not be trusted, the contact may be gone');
    return { simple, hits };
  }
  let j; try { j = JSON.parse(text); } catch (e) { return { simple: [], hits: [], miss: true }; }
  if (!j || typeof j !== 'object') return { simple: [], hits: [], miss: true }; // null, число, строка
  if (/openid|oauth/.test(name)) {
    if (!j || typeof j.issuer !== 'string') return { simple: [], hits: [], miss: true };
    simple.push(...discoveryFindings(j, (u => u.origin + u.pathname.replace(/\/\.well-known\/[^/]+$/, ''))(new URL(url)))); // issuer = префикс до /.well-known/ (Keycloak: /realms/x)
    for (const k of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'revocation_endpoint', 'end_session_endpoint', 'registration_endpoint', 'jwks_uri']) if (typeof j[k] === 'string') hits.push({ raw: j[k], via: 'discovery' });
    if (j.registration_endpoint) info('Dynamic client registration endpoint', 1, 'Anyone may be able to register an OAuth client: check whether registration needs a token', 'auth');
  } else if (name === 'apple-app-site-association') {
    const det = (j.applinks && j.applinks.details) || [];
    if (!det.length && !j.webcredentials && !j.appclips) return { simple: [], hits: [], miss: true };
    for (const d of det.slice(0, 50)) {
      for (const id of [].concat(d.appIDs || d.appID || [])) info('iOS app: ' + id, 0, 'Universal links for this app: the paths below open in the app', 'mobile');
      for (const c of (d.components || []).slice(0, 100)) { const p = c['/']; if (!p) continue; if (/^\/?\*$/.test(p) && !c.exclude) info('iOS app claims every path', 1, 'All links of the site open in the app: check deep-link handling in the app', 'mobile'); else if (!c.exclude) hits.push({ raw: p.replace(/\*.*$/, ''), via: 'aasa' }); }
      for (const p of (d.paths || []).slice(0, 100)) if (!/^NOT /.test(p)) hits.push({ raw: p.replace(/\*.*$/, ''), via: 'aasa' });
    }
  } else if (name === 'assetlinks.json') {
    if (!Array.isArray(j)) return { simple: [], hits: [], miss: true };
    for (const e of j.slice(0, 50)) if (e && e.target && e.target.package_name) info('Android app: ' + e.target.package_name, 0, 'App links for this package: check intent handling in the app', 'mobile');
  } else if (name === 'webauthn') {
    if (!j || !Array.isArray(j.origins)) return { simple: [], hits: [], miss: true };
    for (const o of j.origins.slice(0, 50)) { let h = ''; try { h = new URL(o).hostname; } catch (e) { continue; } info('WebAuthn related origin: ' + o, siteOf(h) !== siteOf(pageHost) ? 1 : 0, 'Passkeys created for this site also work on that origin: check that it belongs to the same owner', 'auth'); }
  }
  return { simple, hits };
}

// D9: следы мобильных приложений в разметке и коде
export function mobileHints(text) {
  const out = []; let m;
  if ((m = /<meta\b[^>]*name=["']apple-itunes-app["'][^>]*content=["'][^"']*app-id=(\d{5,12})/i.exec(text))) out.push({ title: 'iOS app id: ' + m[1], risk: 0, why: ['Smart App Banner: the site has an iOS app; its API may differ from the web one'], at: m.index });
  if ((m = /play\.google\.com\/store\/apps\/details\?id=([\w.]{3,150})/.exec(text))) out.push({ title: 'Android app: ' + m[1], risk: 0, why: ['The site links to an Android app; its API may differ from the web one'], at: m.index });
  if ((m = /apps\.apple\.com\/[\w/-]{0,80}id(\d{5,12})/.exec(text))) out.push({ title: 'iOS app id: ' + m[1], risk: 0, why: ['The site links to an iOS app; its API may differ from the web one'], at: m.index });
  const seen = new Set(), re = /["'`]([a-z][a-z0-9+.-]{2,30}):\/\/[\w/?=&.-]{0,120}["'`]/g; let n = 0;
  while ((m = re.exec(text)) && n < 10) { const s = m[1].toLowerCase(); if (/^(?:https?|wss?|ftp|file|data|blob|chrome|chrome-extension|moz-extension|about|javascript|mailto|tel|sms|webpack|vite|rollup|turbopack|android-app|ios-app|ipfs|ipns|bzz|sia|ar|hyper)$/ .test(s) || seen.has(s)) continue; seen.add(s); n++; out.push({ title: 'App deep-link scheme: ' + s + '://', risk: 0, why: ['A custom URL scheme opens the app: check what parameters it accepts'], at: m.index }); }
  return out;
}
