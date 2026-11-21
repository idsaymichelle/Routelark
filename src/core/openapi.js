// Спецификация OpenAPI/Swagger → эндпоинты. JSON полностью, YAML — только раздел paths.
const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'];

function fromJson(j) {
  if (!j || (!j.openapi && !j.swagger) || !j.paths || typeof j.paths !== 'object') return null;
  let base = typeof j.basePath === 'string' ? j.basePath : '';
  if (!base && Array.isArray(j.servers) && j.servers[0] && typeof j.servers[0].url === 'string') { const sv = j.servers[0]; try { base = new URL(sv.url.replace(/\{(\w+)\}/g, (a, n) => String((sv.variables && sv.variables[n] && sv.variables[n].default) || 'x')), 'http://x').pathname; } catch (e) { /* относительный мусор */ } } // {scheme}:// подставляем default
  const ref = (x) => { for (let i = 0; x && typeof x.$ref === 'string' && i < 5; i++) { x = x.$ref.startsWith('#/') ? x.$ref.slice(2).split('/').reduce((o, k) => o && o[k.replace(/~1/g, '/').replace(/~0/g, '~')], j) : null; } return x; }; // $ref только внутри документа
  base = base.replace(/\/$/, '');
  const out = [];
  for (const [p, raw] of Object.entries(j.paths)) {
    const item = ref(raw);
    if (!item || typeof item !== 'object') continue;
    for (const m of METHODS) {
      const op = item[m]; if (!op) continue;
      const params = [].concat(item.parameters || [], op.parameters || []).map((x) => { x = ref(x); return x && x.name; }).filter((x) => typeof x === 'string');
      out.push({ path: base + p, method: m.toUpperCase(), params: Array.from(new Set(params)) });
    }
  }
  return out;
}
function fromYaml(text) {
  if (!/^\s*(?:openapi|swagger)\s*:/m.test(text.slice(0, 20000))) return null;
  const lines = text.split(/\r?\n/), out = [];
  let inPaths = false, pathIndent = -1, cur = null, base = '', last = null; // shortcut: YAML читается построчно, без $ref и якорей
  for (const l of lines) {
    if (!l.trim() || /^\s*#/.test(l)) continue;
    const ind = l.length - l.trimStart().length;
    if (!inPaths && ind === 0) { const b = /^basePath\s*:\s*['"]?([^'"\s#]+)/.exec(l); if (b) base = b[1].replace(/\/$/, ''); }
    if (!inPaths && !base && /^\s*-\s*url\s*:/.test(l)) { const u = /url\s*:\s*['"]?([^'"\s#]+)/.exec(l); try { base = new URL(u[1], 'http://x').pathname.replace(/\/$/, ''); } catch (e) { /* относительный */ } }
    if (/^['"]?paths['"]?\s*:\s*(?:#.*)?$/.test(l)) { inPaths = true; continue; }
    if (!inPaths) continue;
    if (ind === 0) break; // следующий раздел верхнего уровня
    const key = /^\s*['"]?([^'":]+?)['"]?\s*:/.exec(l);
    if (!key) continue;
    if (key[1].startsWith('/') && (pathIndent < 0 || ind === pathIndent)) { pathIndent = ind; cur = key[1]; continue; }
    if (cur && ind > pathIndent && METHODS.includes(key[1].toLowerCase())) { out.push(last = { path: base + cur, method: key[1].toUpperCase(), params: [] }); continue; }
    const nm = /^\s*-?\s*name\s*:\s*['"]?([\w.-]+)/.exec(l); if (nm && last && last.params.length < 50) last.params.push(nm[1]);
  }
  return out.length ? out : null;
}
export function openApiEndpoints(text) {
  const t = String(text).trim();
  if (t[0] === '{') { let j; try { j = JSON.parse(t); } catch (e) { return null; } return fromJson(j); }
  return fromYaml(t);
}
