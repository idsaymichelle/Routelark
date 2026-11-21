// Tokens in browser storage and OAuth parameters in code addresses. Only reads what was already collected.
const TOKEN_KEY = /(?:^|[_.-])(?:access|id|auth|session|bearer|api|jwt)?[_.-]?tokens?$|^(?:jwt|sid|session(?:id|_id)?|auth|bearer|credentials?)$|(?:^|[_.-])(?:jwt|session[_.-]?id)(?:$|[_.-])/i;
const REFRESH_KEY = /refresh[_.-]?token/i;
const JWT = /^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*$/;

// local, session: [[key, value]]; idb: [{name}] from indexedDB.databases(), database names only
export function storageFindings(local, session, idb) {
  const out = [];
  for (const [where, list] of [['localStorage', local || []], ['sessionStorage', session || []]]) for (const [k, v] of list) {
    const val = String(v || '');
    if (!val || val === 'null' || /csrf|xsrf/i.test(k)) continue;
    const cut = val.length >= 20000 && val.startsWith('eyJ') ? ['value truncated, JWT not parsed'] : [];
    if (REFRESH_KEY.test(k)) out.push({ title: 'Refresh token in ' + where + ': ' + k, risk: 3, why: ['Refresh tokens live longer than access tokens; one XSS can keep the session alive after the access token expires'].concat(cut) });
    else if (TOKEN_KEY.test(k) && (JWT.test(val) || cut.length)) out.push({ title: 'Access token in ' + where + ': ' + k, risk: where === 'localStorage' ? 2 : 1, why: ['Any script on the page can read Web Storage, so an XSS steals the token; an HttpOnly cookie cannot be read by scripts'].concat(cut) });
    else if (TOKEN_KEY.test(k) && val.length >= 16) out.push({ title: 'Opaque token in ' + where + ': ' + k, risk: 1, why: ['Check whether the value is a session identifier: OWASP says session identifiers do not belong in Web Storage'] });
  }
  for (const d of idb || []) if (d && d.name && /auth|token|session|jwt|credential/i.test(d.name)) out.push({ title: 'IndexedDB database: ' + d.name, risk: 0, why: ['The name suggests stored credentials; only the name is read, check the contents in DevTools'] });
  return out;
}

// shortcut: OAuth parameters built at runtime from variables are invisible, only address literals
const OAUTH_URL = /["'`]((?:https?:\/\/|\/)[^"'`\s]{0,300}\?[^"'`\s]{0,600}(?:response_type|redirect_uri|access_token|id_token)=[^"'`\s]{0,600})["'`]/g;
export function oauthLiteral(text, pageHost) {
  const out = []; let m, n = 0;
  OAUTH_URL.lastIndex = 0;
  while ((m = OAUTH_URL.exec(text)) && n < 20) {
    const q = {}, u = m[1];
    for (const p of u.replace(/^[^?]*\?/, '').split('&')) { const i = p.indexOf('='); if (i > 0) q[p.slice(0, i)] = p.slice(i + 1); }
    const add = (title, risk, why) => { n++; out.push({ type: 'oauth', title, risk, why, at: m.index }); };
    let rt = q.response_type || ''; try { rt = decodeURIComponent(rt); } catch (e) { /* broken %-encoding: as is */ }
    if (/(?:^|\s|\+)token(?:\s|\+|$)/.test(rt)) add('OAuth implicit flow (response_type=token)', 3, 'RFC 9700: clients SHOULD NOT use the implicit grant; the token travels in the URL');
    else if (q.response_type === 'code' && !q.code_challenge) add('OAuth code flow without PKCE in the URL', 2, 'RFC 9700: public clients MUST use PKCE with S256; check whether code_challenge is added at runtime');
    if (q.code_challenge_method === 'plain') add('OAuth PKCE with plain method', 2, 'RFC 9700: use S256, plain does not protect the code');
    if (q.response_type && !q.state) add('OAuth request without state', 1, 'Without state or PKCE the redirect is open to CSRF: check that state is added at runtime');
    if (q.redirect_uri) {
      let r = q.redirect_uri; try { r = decodeURIComponent(r); } catch (e) { /* as is */ }
      if (r.includes('#') || /^javascript:/i.test(r)) add('OAuth redirect_uri with fragment or script scheme', 3, 'The authorization server must match redirect_uri exactly; a fragment or script scheme is a sign of a loose check');
      else { const h = /^https?:\/\/([^/:?#]+)/i.exec(r); if (h && h[1] !== pageHost) add('OAuth redirect_uri points to another host: ' + h[1], 1, 'Check that this host belongs to the application'); }
    }
    if (q.access_token || q.id_token) add('Token in URL query', 3, 'Tokens in a URL end up in history, logs and Referer headers (RFC 9700 §4.3.2)');
  }
  return out;
}
