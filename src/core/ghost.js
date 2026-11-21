// Routes from code that no page link points to. Second pass after the scan: needs DOM links.
export function ghostRoutes(store, anchors) {
  if (!Array.isArray(anchors)) return;
  const paths = new Set();
  // An SPA route in the hash (#/search) is the path /search, not an anchor
  for (const a of anchors) { try { const u = new URL(a, store.pageUrl), p = u.hash.startsWith('#/') ? u.hash.slice(1).split('?')[0] : u.pathname; paths.add(p.replace(/\/$/, '') || '/'); } catch (e) { /* broken link */ } }
  let n = 0;
  for (const f of store.items.slice()) {
    if (f.kind !== 'code' || f.type !== 'route' || n >= 50) continue;
    const path = f.url.replace(/^Hidden client route: /, '').replace(/(.)\/$/, '$1'); // root "/" stays "/"
    const re = new RegExp('^' + path.split('/').map((seg) => (/^(?:\[\.\.\.|\*)/.test(seg) ? '.+' : /^[:{[]/.test(seg) ? '[^/]+' : seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('/') + '$');
    if ([...paths].some((p) => re.test(p))) continue;
    n++; const s = f.sources[0] || {};
    store.addCode({ type: 'ghost-route', title: 'Route in code, not linked on the page: ' + path, risk: 1, file: s.file, line: s.line || 1, col: 1, snippet: f.snippet });
  }
}
