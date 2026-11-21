// G6 и B8: карта поверхности атаки (хост → сегменты пути, число адресов и наибольший риск) и карта авторизации по хостам.
const AUTH_ROLE = /(?:^|\/)(?:(login|signin|sign-in|log-in)|(logout|signout|sign-out)|(refresh(?:[-_]?token)?)|(oauth2?\/(?:authorize|token|callback|userinfo|revoke)))(?=\/|$|\?)/i;
import { ROUTE_KINDS } from './scope.js';
export function surfaceTree(store) {
  const hosts = new Map();
  for (const f of store.items) {
    if (!ROUTE_KINDS.has(f.kind) || f.kind === 'external' || !f.path) continue;
    const host = f.host || store.pageHost || '';
    if (!hosts.has(host)) hosts.set(host, { host, n: 0, risk: 0, kids: new Map() });
    const hn = hosts.get(host); hn.n++; hn.risk = Math.max(hn.risk, f.risk);
    let node = hn;
    for (const seg of f.path.split('?')[0].split('/').filter(Boolean).slice(0, 3)) {
      const key = /^\{|^\d+$|^[0-9a-f-]{16,}$/i.test(seg) ? '{id}' : seg;
      if (!node.kids.has(key)) node.kids.set(key, { name: key, n: 0, risk: 0, kids: new Map(), ids: [] });
      node = node.kids.get(key); node.n++; node.risk = Math.max(node.risk, f.risk);
      if (node.ids.length < 50) node.ids.push(f.id);
    }
  }
  const out = (m) => Array.from(m.values()).sort((a, b) => b.risk - a.risk || b.n - a.n).slice(0, 60).map((x) => ({ name: x.name || x.host, n: x.n, risk: x.risk, ids: x.ids || [], kids: out(x.kids) }));
  return out(hosts);
}
export function authMap(store) {
  const rows = new Map();
  for (const f of store.items) {
    if (!ROUTE_KINDS.has(f.kind) || (f.kind === 'external' && !(f.auth || []).length)) continue; // чужой хост — только если на него уходит авторизация
    const host = f.host || store.pageHost || '';
    if (!rows.has(host)) rows.set(host, { host, endpoints: 0, auth: new Set(), roles: new Set() });
    const r = rows.get(host); r.endpoints++;
    (f.auth || []).forEach((a) => r.auth.add(a));
    const m = AUTH_ROLE.exec(f.path || ''); if (m) r.roles.add(m[1] ? 'login' : m[2] ? 'logout' : m[3] ? 'refresh' : 'oauth');
  }
  return Array.from(rows.values()).map((r) => ({ host: r.host, endpoints: r.endpoints, auth: Array.from(r.auth), roles: Array.from(r.roles), crossAuth: r.auth.has('authorization') && r.host && r.host !== store.pageHost })).sort((a, b) => b.crossAuth - a.crossAuth || b.endpoints - a.endpoints);
}
