// Cookies: разбор, импорт, экспорт, расшифровка, аудит и строки для document.cookie.
// cookie: {name, value, domain?, path='/', secure?, sameSite?, expires? (мс), hostOnly?, httpOnly?, attrsKnown?}
const ATTR = /^(?:path|domain|expires|max-age|secure|httponly|samesite|partitioned|priority)$/i;
// Части имени, а не подстроки: sidebar_state и author_name — не сессия
const SENSITIVE = /(?:^|[^a-z])(?:sess(?:ion)?(?:id)?|sid|token|auth|jwt|csrf|xsrf|login|remember)(?:$|[^a-z])|^connect\.sid$|[a-z](?:Session|Token|Auth|Jwt|Csrf|Login)/i;

export function parseCookieHeader(str) {
  const out = [];
  String(str || '').split(/;\s*/).forEach((pair) => { const i = pair.indexOf('='); if (i > 0) out.push({ name: pair.slice(0, i).trim(), value: pair.slice(i + 1), path: '/' }); });
  return out;
}
function parseSetCookie(line) {
  const parts = line.split(/;\s*/), first = parts.shift(), i = first.indexOf('=');
  if (i <= 0) return null;
  const c = { name: first.slice(0, i).trim(), value: first.slice(i + 1), path: '/', attrsKnown: true }; // Set-Cookie несёт все атрибуты
  for (const p of parts) {
    const [k, ...rest] = p.split('='), v = rest.join('=').trim(), key = k.trim().toLowerCase();
    if (key === 'path') c.path = v || '/';
    else if (key === 'domain') { c.domain = v; c.hostOnly = false; }
    else if (key === 'secure') c.secure = true;
    else if (key === 'httponly') c.httpOnly = true;
    else if (key === 'partitioned') c.partitioned = true;
    else if (key === 'samesite') c.sameSite = v;
    else if (key === 'expires') { const t = Date.parse(v); if (t) c.expires = t; }
    else if (key === 'max-age') c.expires = Date.now() + Number(v) * 1000;
  }
  return c;
}
const isSetCookie = (line) => line.split(/;\s*/).slice(1).every((p) => p && ATTR.test(p.split('=')[0].trim()));

// Playwright и Puppeteer пишут expires в секундах, -1 значит «до закрытия браузера»
const ms = (v) => (typeof v !== 'number' || v <= 0 ? undefined : v < 1e11 ? v * 1000 : v);
export function parseCookieInput(text) {
  text = String(text || '').replace(/^[ \r\n]+|[ \r\n]+$/g, ''); // табуляцию в начале не срезаем: в Netscape-файле она значима
  if (text[0] === '[') {
    try {
      return JSON.parse(text).filter((o) => o && o.name).map((o) => ({ name: String(o.name), value: String(o.value ?? ''), domain: o.domain, path: o.path || '/', secure: !!o.secure, sameSite: ({ no_restriction: 'None', none: 'None', lax: 'Lax', strict: 'Strict', unspecified: null })[String(o.sameSite || '').toLowerCase()] || null, httpOnly: !!o.httpOnly, hostOnly: o.hostOnly !== false && !String(o.domain || '').startsWith('.'), expires: o.expirationDate ? o.expirationDate * 1000 : ms(o.expires) }));
    } catch (e) { /* не JSON — пробуем другие форматы */ }
  }
  const lines = text.split(/\r?\n/).map((l) => (l.includes('\t') ? l : l.trim())).filter((l) => l && !/^#(?!HttpOnly_)/.test(l));
  const out = [];
  for (const l of lines) {
    const t = l.split('\t');
    if (t.length >= 7) { const httpOnly = t[0].startsWith('#HttpOnly_'); out.push({ domain: t[0].replace('#HttpOnly_', ''), hostOnly: t[1] !== 'TRUE', path: t[2], secure: t[3] === 'TRUE', expires: +t[4] ? +t[4] * 1000 : undefined, name: t[5], value: t[6], httpOnly }); continue; }
    if (/^set-cookie:/i.test(l) || isSetCookie(l)) { const c = parseSetCookie(l.replace(/^set-cookie:\s*/i, '')); if (c) out.push(c); continue; }
    out.push(...parseCookieHeader(l.replace(/^cookie:\s*/i, '')));
  }
  return out;
}

export function exportCookies(list, fmt, host) {
  if (fmt === 'header') return list.map((c) => c.name + '=' + c.value).join('; ');
  if (fmt === 'netscape') return list.map((c) => {
    const dom = c.domain || host || '', sub = c.hostOnly === false; // Netscape без домена не импортируется
    return (c.httpOnly ? '#HttpOnly_' : '') + dom + '\t' + (sub ? 'TRUE' : 'FALSE') + '\t' + (c.path || '/') + '\t' + (c.secure ? 'TRUE' : 'FALSE') + '\t' + (c.expires ? Math.floor(c.expires / 1000) : 0) + '\t' + c.name + '\t' + c.value;
  }).join('\n');
  return JSON.stringify(list.map((c) => ({ name: c.name, value: c.value, domain: c.domain, path: c.path || '/', secure: !!c.secure, httpOnly: !!c.httpOnly, sameSite: c.sameSite || null, hostOnly: c.hostOnly !== false, expirationDate: c.expires ? c.expires / 1000 : undefined })), null, 2);
}

const printable = (s) => s && !/[\x00-\x08\x0e-\x1f]/.test(s);
function b64(s, strict) { try { const t = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)); try { return decodeURIComponent(escape(t)); } catch (e) { return strict && /[\x80-\xff]/.test(t) ? null : t; } } catch (e) { return null; } } // strict: байты 0x80-0xff не UTF-8 — это мусор, а не текст
export function decodeValue(v) {
  v = String(v || ''); const out = [];
  let u = v; try { u = decodeURIComponent(v); } catch (e) { /* не URL-кодировка */ }
  if (u !== v) out.push({ label: 'URL', text: u });
  const jwt = /^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*$/.exec(u);
  if (jwt) { const [h, p] = u.split('.'); out.push({ label: 'JWT', text: b64(h) + '\n' + b64(p) }); }
  else if (/^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(u) && !/^\d+$/.test(u)) { const d = b64(u, true); if (printable(d) && /[\x20-\x7e]{4}/.test(d)) out.push({ label: 'base64', text: d }); }
  try { const j = JSON.parse(u); if (j && typeof j === 'object') out.push({ label: 'JSON', text: JSON.stringify(j, null, 2) }); } catch (e) { /* не JSON */ }
  if (/^\d{10}(?:\d{3})?$/.test(u)) out.push({ label: 'Time', text: new Date(u.length === 10 ? +u * 1000 : +u).toISOString() });
  if (/^(?:[0-9a-f]{2}){8,}$/i.test(u)) { const t = u.match(/../g).map((x) => String.fromCharCode(parseInt(x, 16))).join(''); if (printable(t)) out.push({ label: 'hex', text: t }); }
  return out;
}

export function auditCookie(c, isHttps) {
  let risk = 0; const why = [], up = (r, w) => { risk = Math.max(risk, r); why.push(w); };
  const sens = SENSITIVE.test(c.name);
  if (sens && !c.httpOnly) up(2, 'Looks like a session cookie and is readable from JS (no HttpOnly): XSS can steal it');
  if (c.attrsKnown && isHttps && !c.secure) up(sens ? 2 : 1, 'No Secure flag on https');
  if (c.attrsKnown && /^none$/i.test(c.sameSite || '') && !c.secure) up(2, 'SameSite=None without Secure');
  if (c.attrsKnown && sens && !c.sameSite) up(1, 'Session cookie without an explicit SameSite');
  // Префиксы: браузер отклоняет такую cookie с нарушением правил, значит гарантия префикса здесь не действует
  if (c.attrsKnown && /^__Host-/.test(c.name) && (!c.secure || c.hostOnly === false || (c.path || '/') !== '/')) up(1, '__Host- cookie breaks the prefix rules (Secure, no Domain, Path=/)');
  if (c.attrsKnown && /^__Secure-/.test(c.name) && !c.secure) up(1, '__Secure- cookie is not Secure');
  if (c.attrsKnown && c.partitioned && !c.secure) up(1, 'Partitioned cookie is not Secure');
  if (c.expires && c.expires - Date.now() > 400 * 864e5) up(1, 'Lives longer than 400 days');
  if ((c.name.length + String(c.value).length) > 4096) up(1, 'Larger than 4 KB');
  return { risk, why };
}

const hostOnlyOf = (c) => c.hostOnly !== false;
// «;» и перевод строки в значении браузер воспримет как конец значения и атрибуты — такое не пишем
export const badCookieValue = (v) => /[;\r\n]/.test(String(v));
export function writeString(c) {
  if (badCookieValue(c.value) || badCookieValue(c.name)) throw new Error('Value cannot contain ";" or line breaks');
  let s = c.name + '=' + c.value + '; path=' + (c.path || '/');
  if (!hostOnlyOf(c) && c.domain) s += '; domain=' + c.domain; // без domain= cookie остаётся привязанной к одному хосту
  if (c.secure) s += '; secure';
  if (c.sameSite) s += '; samesite=' + c.sameSite;
  if (c.expires) s += '; expires=' + new Date(c.expires).toUTCString();
  return s;
}
export function deleteString(c) {
  return c.name + '=; path=' + (c.path || '/') + (!hostOnlyOf(c) && c.domain ? '; domain=' + c.domain : '') + '; expires=Thu, 01 Jan 1970 00:00:00 GMT';
}
export const isSensitiveCookie = (name) => SENSITIVE.test(name);
// Где может лежать cookie, если браузер не сообщил её домен (нет Cookie Store API): только этот хост,
// затем domain= для самого хоста и каждого родителя до регистрируемого домена (site). Для IP и localhost — только хост.
export function cookieVariants(host, site) {
  host = String(host).replace(/:\d+$/, '');
  const out = [{ hostOnly: true }];
  if (!site || !host.includes('.') || /^[\d.]+$/.test(host)) return out;
  for (let d = host; d && (d === site || d.endsWith('.' + site)); d = d.slice(d.indexOf('.') + 1)) { out.push({ hostOnly: false, domain: d }); if (d === site) break; }
  return out;
}
