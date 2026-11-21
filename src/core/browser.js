// Modern browser features with security impact: Speculation Rules, Sanitizer API, FedCM, WebAuthn, Storage Access API.
// Nothing is requested: /.well-known/web-identity and Speculation-Rules files are not read.
import { siteOf } from './scope.js';
const DESTRUCTIVE = /logout|signout|sign-out|delete|remove|destroy|revoke|unsubscribe|confirm|approve|transfer|verify-email/i;

export function speculationFindings(html) {
  const out = [];
  for (const m of String(html || '').matchAll(/<script\b[^>]*type\s*=\s*["']?speculationrules["']?[^>]*>([\s\S]{0,200000}?)<\/script>/gi)) {
    let j; try { j = JSON.parse(m[1]); } catch (e) { continue; }
    for (const kind of ['prerender', 'prefetch']) for (const r of [].concat(j[kind] || []).slice(0, 50)) {
      const pats = [].concat(r.urls || [], (r.where && (r.where.href_matches || (r.where.and || []).map((x) => x.href_matches))) || [], r.href_matches || []).flat().filter((x) => typeof x === 'string');
      const bad = pats.find((p) => DESTRUCTIVE.test(p)) || (r.where && JSON.stringify(r.where).match(DESTRUCTIVE) && !JSON.stringify(r.where).includes('"not"') ? JSON.stringify(r.where).match(DESTRUCTIVE)[0] : null);
      // Without eagerness the browser uses immediate for a urls list and conservative for where
      const eager = r.eagerness || (r.urls ? 'immediate' : 'conservative');
      if (kind === 'prerender' && bad) out.push({ title: 'Speculation Rules prerender a destructive link: ' + bad, risk: /immediate|eager/.test(eager) ? 2 : 1, why: ['The browser loads matching links without a click: a GET that logs out, deletes or approves runs unnoticed'] });
      else if (kind === 'prefetch' && bad) out.push({ title: 'Speculation Rules prefetch a destructive link: ' + bad, risk: 1, why: ['prefetch downloads the response before the click; a GET with side effects can run on hover'] });
      else if (kind === 'prerender') out.push({ title: 'Speculation Rules prerender pages', risk: 0, why: ['Pages are rendered before the click: check that GET pages have no side effects'] });
    }
  }
  return out;
}
export function browserFindings(text, pageHost) {
  const out = []; let m;
  const add = (title, risk, why, at) => { if (!out.some((x) => x.title === title)) out.push({ title, risk, why: [why], at }); };
  if ((m = /\.\s*setHTML\s*\(/.exec(text)) && /new\s+Sanitizer\s*\(/.test(text.slice(m.index, m.index + 300))) add('Custom Sanitizer config', 1, 'setHTML with a custom Sanitizer: check the allowed elements and attributes', m.index);
  if ((m = /navigator\.credentials\.get\s*\(\s*\{[\s\S]{0,600}?\bidentity\s*:/.exec(text))) {
    const w = text.slice(m.index, m.index + 800), u = /configURL\s*:\s*(["'`])([^"'`]{1,300})\1/.exec(w);
    let host = ''; try { host = u ? new URL(u[2]).hostname : ''; } catch (e) { /* relative */ }
    add('FedCM identity provider' + (host ? ': ' + host : ''), 0, 'Federated sign-in via FedCM: check the IdP\'s client registration and what the accounts endpoint returns', m.index);
  }
  if (/navigator\.credentials\.(?:create|get)\s*\(|\bpublicKey\s*:\s*\{/.test(text)) {
    const rp = /\brpId\s*:\s*(["'`])([a-z0-9.-]{1,253})\1/i.exec(text);
    if (rp && pageHost && pageHost !== rp[2] && !pageHost.endsWith('.' + rp[2])) add('WebAuthn rpId ' + rp[2] + ' is not the page host ' + pageHost, 1, 'Passkeys are bound to the rpId; this page is on another origin, so /.well-known/webauthn on the rpId must list it', rp.index);
    else if (rp && pageHost && rp[2] === siteOf(pageHost) && pageHost !== rp[2]) add('WebAuthn rpId is the parent domain ' + rp[2], 0, 'Every subdomain can use these passkeys: check that all subdomains are trusted', rp.index);
    const uv = /userVerification\s*:\s*(["'`])(discouraged|preferred)\1/.exec(text);
    if (uv) add('WebAuthn user verification: ' + uv[2], 1, 'Passkeys may be used without a PIN or biometric check: check that the server enforces the flag it expects', uv.index);
  }
  if ((m = /\b(?:requestStorageAccess|hasStorageAccess|hasUnpartitionedCookieAccess)\s*\(/.exec(text))) add('Storage Access API used', 0, 'The page asks for unpartitioned cookies when embedded: check which sites embed it and what the cookies allow', m.index);
  return out;
}
