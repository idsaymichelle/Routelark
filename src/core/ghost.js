// B3: маршруты из кода, на которые не ведёт ни одна ссылка страницы. Второй проход после скана: нужны ссылки из DOM.
export function ghostRoutes(store, anchors) {
  if (!Array.isArray(anchors)) return;
  const paths = new Set();
  // Маршрут SPA в хеше (#/search) — это путь /search, а не якорь
  for (const a of anchors) { try { const u = new URL(a, store.pageUrl), p = u.hash.startsWith('#/') ? u.hash.slice(1).split('?')[0] : u.pathname; paths.add(p.replace(/\/$/, '') || '/'); } catch (e) { /* битая ссылка */ } }
  let n = 0;
  for (const f of store.items.slice()) {
    if (f.kind !== 'code' || f.type !== 'route' || n >= 50) continue;
    const path = f.url.replace(/^Hidden client route: /, '').replace(/(.)\/$/, '$1'); // корень «/» остаётся «/»
    const re = new RegExp('^' + path.split('/').map((seg) => (/^(?:\[\.\.\.|\*)/.test(seg) ? '.+' : /^[:{[]/.test(seg) ? '[^/]+' : seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('/') + '$');
    if ([...paths].some((p) => re.test(p))) continue;
    n++; const s = f.sources[0] || {};
    store.addCode({ type: 'ghost-route', title: 'Route in code, not linked on the page: ' + path, risk: 1, file: s.file, line: s.line || 1, col: 1, snippet: f.snippet });
  }
}
