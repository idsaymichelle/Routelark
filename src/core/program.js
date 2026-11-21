// Bug bounty program scope (HackerOne JSON, Bugcrowd JSON or a line list). Only hides out-of-scope findings;
// what to request and where is still decided by the scope.js rules. Paths in entries are ignored, CIDR is unsupported.
const NON_HOST = /^(?:android|ios|apple|windows|source code|executable|hardware|iot|smart contracts?|ai model|google play|play store|app store|other app|downloadable)/i;
import { ROUTE_KINDS } from './scope.js';
function rule(asset, out) {
  let a = String(asset || '').trim().toLowerCase().replace(/\.$/, '');
  if (!a) return null;
  if (/^[a-z]+:\/\//.test(a)) { try { a = new URL(a).hostname; } catch (e) { return null; } }
  if (/\/\d+$/.test(a)) return null; // CIDR
  a = a.replace(/:\d+$/, '').replace(/\/.*$/, '');
  try { if (/[^\x00-\x7f]/.test(a)) a = new URL('http://' + a.replace(/^\*\./, '')).hostname.replace(/^/, a.startsWith('*.') ? '*.' : ''); } catch (e) { return null; } // IDN -> xn--
  if (a === '*') return { host: '', wild: true, out };
  const wild = a.startsWith('*.');
  if (wild) a = a.slice(2);
  return /^[a-z0-9.-]+$/.test(a) ? { host: a, wild, out } : null;
}
export function parseProgram(text) {
  text = String(text || '');
  if (text.length > 2e5) throw new Error('Scope text is too large');
  const rules = [], rejected = []; let ignored = 0, format = 'list';
  const push = (asset, out, type) => { type = type && String(type).toLowerCase().replace(/[\s_-]+/g, ' '); if (rules.length >= 2000) throw new Error('Scope has more than 2000 entries'); if (type && NON_HOST.test(type)) { ignored++; return; } /* an app id (com.app) looks like a domain but is not a host */ const r = rule(asset, out); if (r && rules.length < 2000) rules.push(r); else ignored++; };
  const tr = text.trim();
  let j; if (/^[{[]/.test(tr)) try { j = JSON.parse(tr); } catch (e) { /* not JSON: a line like [::1] is a plain list */ }
  if (j !== undefined) {
    if (j && Array.isArray(j.data) && j.data.some((x) => x && x.attributes)) { format = 'hackerone'; for (const x of j.data) { const a = x.attributes || {}; push(a.asset_identifier, a.eligible_for_submission === false, a.asset_type); } }
    else {
      const eng = Array.isArray(j) ? j : j && j.targets ? [j] : null;
      if (!eng || !eng.some((e) => e && (e.targets || e.in_scope))) throw new Error('Not a scope list');
      format = 'bugcrowd';
      for (const e of eng) { const tg = e.targets || e; for (const x of [].concat(tg.in_scope || [])) push(x.target || x.uri || x.name, false, x.type); for (const x of [].concat(tg.out_of_scope || [])) push(x.target || x.uri || x.name, true, x.type); }
    }
  } else for (const line of text.split('\n')) {
    const l = line.trim(); if (!l || l.startsWith('#')) continue;
    const out = l.startsWith('!'), a = (out ? l.slice(1) : l).replace(/\s+#.*$/, '').trim(); // trailing comment
    if (/\s/.test(a)) { if (rejected.length < 10) rejected.push(a); continue; }
    push(a, out);
  }
  return { rules, ignored, format, rejected };
}
const match = (r, host) => (r.wild ? !r.host || host === r.host || host.endsWith('.' + r.host) : host === r.host);
export const inScope = (host, rules) => !rules.some((r) => r.out && match(r, host)) && rules.some((r) => !r.out && match(r, host));
export function isOutOfProgram(f, pageHost, rules) {
  if (!rules || !rules.some((r) => !r.out) || !ROUTE_KINDS.has(f.kind) && f.kind !== 'realtime') return false;
  let host = f.host || pageHost; try { if (/^https?:/.test(f.resolved || '')) host = new URL(f.resolved).hostname; } catch (e) { /* relative */ }
  return !!host && !inScope(host, rules);
}
