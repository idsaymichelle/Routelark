// Page markup audit: forms, mixed content, SRI, links, comments, error texts, technologies from cookies.
// Reads the already fetched HTML (page snapshot). No requests. Regex parsing is enough for heuristics.

import { speculationFindings } from './browser.js';
const attr = (tag, name) => { const m = new RegExp('\\s' + name + '\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i').exec(tag); return m ? (m[1] != null ? m[1] : m[2] != null ? m[2] : m[3]) : null; };
const hostOf = (u, base) => { try { return new URL(u, base).host; } catch (e) { return ''; } };
const TOKEN_NAME = /csrf|xsrf|token|nonce|secret|api[_-]?key|session|auth|viewstate|eventvalidation|^state$|^lt$|authenticity|__requestverification/i;
const COMMENT_HINT = /todo|fixme|hack|\bbug\b|password|passwd|secret|token|api[_-]?key|admin|debug|internal|staging|\btest\b|dev\b|deprecated|remove|temporary|https?:\/\/|\/api\/|\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b|[\w.+-]+@[\w-]+\.[\w.]+/i;
const ERROR_TEXT = /Traceback \(most recent call last\)|Exception in thread|\bat [\w$.<>]+ \((?:[\w:/.\-]+):\d+:\d+\)|You have an error in your SQL syntax|SQLSTATE\[|ORA-\d{5}|Warning: [a-z_]+\(\)|Fatal error: |Stack trace:|Whitelabel Error Page|DEBUG = True|Fatal error(?:<[^>]{0,40}>)*\s*:|Uncaught \w*(?:Error|Exception)|NullReferenceException|System\.\w+Exception|org\.springframework\.|at [\w.$]+\([\w$]+\.java:\d+\)|ActiveRecord::|PG::\w+Error|SQLiteException|\bline \d+ of [\w\/.\\-]+\.(?:php|py|rb|js)\b/i;

// Skimmer signs. IOC lists are dated campaign data (Sansec 2026-04-07 and 2026-06-04), not a verdict on the current owner
const PAY_ALLOW = /(?:^|\.)(?:stripe\.com|paypal\.com|braintreegateway\.com|adyen\.com|checkout\.com|worldpay\.com|sberbank\.ru|yookassa\.ru|cloudpayments\.ru|payu\.com|klarna\.com)$/;
const SKIM_GTM = ['GTM-P6KZMF63', 'GTM-55976FLP', 'GTM-MSDHV3HG', 'GTM-TV4CSHVN'];
const SKIM_HOSTS = /(?:^|\.)(?:statistics-for-you|statistics-renew|morningflexpleasure|reusable-flex|goingfatter|wellfacing)\.com$/;
const CARD = /<input\b[^>]{0,2000}\b(?:autocomplete\s*=\s*["']?cc-(?:number|exp|csc|name)|name\s*=\s*["']?(?:payment\[cc_\w+\]|cc_?number|card_?number|cvv|cvc)\b)/i;
export function skimmerInline(body) {
  const dec = /\batob\s*\(|String\.fromCharCode\s*\(/.test(body);
  if (/atob\s*\(\s*['"][A-Za-z0-9+/=]{200,}['"]\s*\)/.test(body)) return { risk: /(?:setTimeout|setInterval|eval|Function)\s*\([\s\S]{0,80}atob/.test(body) ? 3 : 2, title: 'Inline script runs a long base64 payload' };
  if (/String\.fromCharCode\s*\((?:\s*\d{2,3}\s*,){20,}/.test(body)) return { risk: 2, title: 'Inline script builds code from character codes' };
  if (dec && /\beval\s*\(|\bnew\s+Function\s*\(/.test(body)) return { risk: 2, title: 'Inline script decodes and runs code' };
  return null;
}

export function auditHtml(html, pageUrl) {
  const out = [], https = /^https:/i.test(pageUrl || ''), pageHost = hostOf(pageUrl);
  if (!html) return out;
  const lineAt = (pos) => { let n = 1; for (let i = html.indexOf('\n'); i !== -1 && i < pos; i = html.indexOf('\n', i + 1)) n++; return n; };
  const add = (title, risk, why, pos, snippet) => out.push({ title, risk, why: [why], line: lineAt(pos), snippet: String(snippet).replace(/\s+/g, ' ').trim().slice(0, 240) });
  let m;

  const FORM = /<form\b[^>]{0,2000}>/gi;
  while ((m = FORM.exec(html))) {
    const action = attr(m[0], 'action');
    if (!action) continue;
    if (https && /^http:\/\//i.test(action)) add('Form sends data over HTTP', 2, 'The form action is plain http on an https page: the data travels unencrypted', m.index, m[0]);
    else if (/^(?:https?:)?\/\//i.test(action) && hostOf(action, pageUrl) && hostOf(action, pageUrl) !== pageHost) add('Form posts to another site: ' + hostOf(action, pageUrl), 1, 'Form data leaves the site: check that the receiving host is expected', m.index, m[0]);
    if (/^\s*javascript:/i.test(action)) add('javascript: URL in a form', 1, 'Script in an attribute: check where its parts come from', m.index, m[0]);
  }
  if (!https && /<input\b[^>]{0,2000}type\s*=\s*["']?password/i.test(html)) { const p = html.search(/<input\b[^>]{0,2000}type\s*=\s*["']?password/i); add('Password field on an HTTP page', 3, 'The page is not encrypted, so the password can be read on the network', p, html.slice(p, p + 160)); }
  const HIDDEN = /<input\b[^>]{0,2000}type\s*=\s*["']?hidden[^>]{0,2000}>/gi;
  while ((m = HIDDEN.exec(html))) {
    const name = attr(m[0], 'name') || attr(m[0], 'id') || '', value = attr(m[0], 'value') || '';
    if (TOKEN_NAME.test(name) && value.length >= 8) add('Hidden field with a token: ' + name, 0, 'Check that the token is bound to the session and changes between sessions', m.index, m[0].replace(value, value.slice(0, 4) + '…'));
  }

  const RES = /<(script|link|iframe|img|source|audio|video|embed|object)\b[^>]{0,2000}>/gi;
  while ((m = RES.exec(html))) {
    const tag = m[1].toLowerCase(), url = attr(m[0], tag === 'link' ? 'href' : tag === 'object' ? 'data' : 'src');
    if (!url) continue;
    const rel = (attr(m[0], 'rel') || '').toLowerCase();
    if (tag === 'link' && !/stylesheet|preload|modulepreload|icon/.test(rel)) continue;
    if (https && /^http:\/\//i.test(url)) {
      const active = tag === 'script' || tag === 'iframe' || tag === 'object' || tag === 'embed' || (tag === 'link' && /stylesheet|preload/.test(rel));
      add((active ? 'Mixed content (active): ' : 'Mixed content: ') + hostOf(url), active ? 2 : 1, active ? 'A script, style or frame is loaded over http on an https page: the browser blocks it or it can be replaced on the network' : 'A picture or media file is loaded over http on an https page', m.index, m[0]);
    }
    const ext = /^(?:https?:)?\/\//i.test(url) && hostOf(url, pageUrl) !== pageHost;
    if (ext && (tag === 'script' || (tag === 'link' && /stylesheet/.test(rel))) && !attr(m[0], 'integrity')) add('External file without SRI: ' + hostOf(url, pageUrl), 1, 'No integrity attribute: if that host is compromised, its code runs on this site', m.index, m[0]);
  }

  const blank = (html.match(/<a\b[^>]{0,2000}target\s*=\s*["']?_blank[^>]{0,2000}>/gi) || []).filter((a) => !/\brel\s*=\s*["']?[^"'\s>]*(?:noopener|noreferrer)/i.test(a));
  if (blank.length) add('Links with target=_blank without rel=noopener: ' + blank.length, 0, 'Old browsers give the opened page access to window.opener (tabnabbing)', html.indexOf(blank[0]), blank[0]);
  const JSURL = /\s(?:href|src|action|formaction)\s*=\s*["']?\s*javascript:/gi;
  // All matches, not the first: a harmless javascript:void(0) must not hide real ones
  for (const x of html.matchAll(JSURL)) if (!/javascript:\s*(?:void\s*\(?0\)?|;)?\s*;?\s*["']/i.test(html.slice(x.index, x.index + 60))) { add('javascript: URLs in markup', 1, 'Script in an attribute: check where its parts come from', x.index, html.slice(x.index, x.index + 160)); break; }
  const inline = html.match(/<[a-z][^>]{0,2000}\son[a-z]+\s*=/gi) || [];
  if (inline.length) add('Inline event handlers: ' + inline.length, 0, 'Handlers in attributes need \'unsafe-inline\' in CSP and make XSS easier to exploit', html.search(/<[a-z][^>]{0,2000}\son[a-z]+\s*=/i), inline[0]);

  const card = CARD.test(html);
  if (card) {
    add('Card fields on the page', 0, 'The page takes card data: every script on it can read the fields (PCI DSS 6.4.3)', html.search(CARD), html.slice(html.search(CARD), html.search(CARD) + 160));
    FORM.lastIndex = 0;
    while ((m = FORM.exec(html))) { const a = attr(m[0], 'action'), ah = a && hostOf(a, pageUrl); if (ah && ah !== pageHost && !PAY_ALLOW.test(ah.replace(/:\d+$/, ''))) add('Card form posts to a host not on the payment list: ' + ah, 3, 'Card data leaves the site for a host that is not a known payment provider: check who owns it', m.index, m[0]); }
  }
  const SCRIPT = /<script\b([^>]{0,2000})>([\s\S]*?)<\/script>/gi; let ns = 0;
  while ((m = SCRIPT.exec(html)) && ns < 10) { if (/\ssrc\s*=/i.test(m[1])) continue; const k = skimmerInline(m[2]); if (k) { ns++; add(k.title, k.risk, 'A common skimmer trick, also used by some minified tags: read the decoded code', m.index, m[2].slice(0, 200)); } }
  const SVG = /<(svg|img)\b[^>]{0,2000}\sonload\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]{0,2000}>/gi;
  while ((m = SVG.exec(html))) { const body = m[2] || m[3] || ''; if (m[1].toLowerCase() === 'img' && !/(?:width|height)\s*=\s*["']?1\b/i.test(m[0])) continue; const bad = /atob\(|eval\(|Function\(|setTimeout\(\s*["'`]/.test(body); add('SVG or pixel onload handler', bad ? 3 : 1, bad ? 'The handler decodes and runs code: a known skimmer loader pattern' : 'Code runs when the image loads: check what it does', m.index, m[0]); }
  const HID = /<(iframe|img)\b[^>]{0,2000}>/gi;
  while ((m = HID.exec(html))) {
    const t = m[0], src = attr(t, 'src'), h = src && /^(?:https?:)?\/\//i.test(src) ? hostOf(src, pageUrl) : '';
    if (!h || h === pageHost) continue;
    const tiny = /\shidden(?:\s|>|=)/i.test(t) || /(?:width|height)\s*:\s*0(?:px)?\b/i.test(attr(t, 'style') || '') || /\b(?:width|height)\s*=\s*["']?[01](?:px)?["']?/i.test(t) && /\b(?:width|height)\s*=\s*["']?[01](?:px)?["']?[^>]{0,2000}\b(?:width|height)\s*=\s*["']?[01]/i.test(t) || /display\s*:\s*none|visibility\s*:\s*hidden/i.test(attr(t, 'style') || '');
    if (tiny && !PAY_ALLOW.test(h) && m[1].toLowerCase() === 'iframe') add('Hidden frame to ' + h, card ? 3 : 2, 'An invisible frame loads another site: check what it sends and why', m.index, t);
  }
  const gtm = new Set(html.match(/\bGTM-[A-Z0-9]{4,10}\b/g) || []);
  for (const id of gtm) add(SKIM_GTM.includes(id) ? 'Known skimmer GTM container ' + id : 'GTM container ' + id, SKIM_GTM.includes(id) ? 4 : 0, SKIM_GTM.includes(id) ? 'This container was used in a 2026 card-skimming campaign: check the account it belongs to' : 'Compare it with your own containers: a foreign container runs its tags on this page', html.indexOf(id), id);
  for (const u of html.match(/https?:\/\/[a-z0-9.-]+/gi) || []) { const h = hostOf(u); if (SKIM_HOSTS.test(h)) { add('Known skimmer host: ' + h, 4, 'This host received stolen card data in a 2026 campaign: check every script that mentions it', html.indexOf(u), u); break; } }

  for (const f of speculationFindings(html)) add(f.title, f.risk, f.why[0], html.search(/speculationrules/i), 'speculationrules');
  if ((m = /<meta\b[^>]{0,2000}name\s*=\s*["']referrer["'][^>]{0,2000}content\s*=\s*["'](unsafe-url|no-referrer-when-downgrade)["']/i.exec(html))) add('Meta referrer tag sends the full address to other sites', 1, 'Full page addresses, with their query parameters, go to every linked site', m.index, m[0]);
  const rp = html.match(/\sreferrerpolicy\s*=\s*["']?unsafe-url/gi) || [];
  if (rp.length) add('Elements with referrerpolicy=unsafe-url: ' + rp.length, 1, 'Full page addresses, with their query parameters, go to every linked site', html.search(/\sreferrerpolicy\s*=\s*["']?unsafe-url/i), rp[0]);

  const COMMENT = /<!--([\s\S]*?)-->/g; let nc = 0;
  while ((m = COMMENT.exec(html)) && nc < 30) {
    const body = m[1].trim();
    if (body.length < 4 || /^\[if |^\s*\/?ko\b|^#|^-/.test(body) || !COMMENT_HINT.test(body)) continue;
    nc++; add('HTML comment: ' + body.replace(/\s+/g, ' ').slice(0, 60), 1, 'Comments are sent to every visitor and often mention internal names, paths or plans', m.index, m[0]);
  }

  const text = html.replace(/<script\b[\s\S]*?<\/script>|<style\b[\s\S]*?<\/style>/gi, ' ');
  if ((m = ERROR_TEXT.exec(text))) { const p = html.indexOf(m[0]); add('Error or stack trace on the page', 2, 'The page shows an error message: it reveals the backend stack and sometimes paths or queries', p < 0 ? 0 : p, text.slice(Math.max(0, m.index - 40), m.index + 200)); }
  return out;
}

const COOKIE_TECH = [[/^PHPSESSID$/, 'PHP'], [/^JSESSIONID$/, 'Java'], [/^(?:ASP\.NET_SessionId|\.ASPXAUTH|\.AspNetCore\.)/, 'ASP.NET'], [/^laravel_session$/, 'Laravel'], [/^csrftoken$|^django_language$/, 'Django'],
  [/^connect\.sid$/, 'Express'], [/^_[\w]+_session$/, 'Ruby on Rails'], [/^(?:cf_clearance|__cf_bm|__cflb)$/, 'Cloudflare'], [/^AWSALB(?:CORS)?$/, 'AWS load balancer'], [/next-auth\./, 'NextAuth.js'], [/^wp-settings|^wordpress_/, 'WordPress'], [/^_shopify_/, 'Shopify'], [/^language$/, null]];
export function cookieTech(names) {
  const out = new Set();
  for (const n of names) for (const [re, name] of COOKIE_TECH) if (name && re.test(n)) out.add(name);
  return Array.from(out);
}
