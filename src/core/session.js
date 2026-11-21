// Файл сессии и сравнение запусков. Секреты в файл и историю не попадают.
import { view } from './export.js';
import { fnv } from '../core.js';
import { fileType } from './files.js';

// Хеш от самого значения секрета (короткий FNV без соли) подбирается перебором, поэтому в файл и историю идёт хеш от маски и места
// Место находки делает id разных секретов с одинаковой маской разными; само значение не хешируется
export const stableId = (f) => (f.kind === 'secret' || f.kind === 'pii' ? fnv(f.kind + '|' + f.type + '|' + f.secret + '|' + (f.sources && f.sources[0] ? f.sources[0].file + ':' + f.sources[0].line + ':' + f.sources[0].col : '') + '|' + f.url) : f.id);
// Совпавшие id (одинаковая маска в одном месте) получают суффикс по порядку, чтобы находки не сливались при сравнении
export function stableIds(items) { const n = {}; return items.map((f) => { const id = stableId(f); n[id] = (n[id] || 0) + 1; return n[id] > 1 ? id + '#' + n[id] : id; }); }
export function sessionFile(store, program) {
  const list = store.list(), ids = stableIds(list);
  return { format: 'routelark-session', version: 2, program: program ? program.rules : undefined, origin: store.pageOrigin, url: store.pageUrl, date: new Date().toISOString(), files: store.files.length, findings: list.map((f, i) => Object.assign(view(f, false), { id: ids[i] })), deps: Array.from(store.deps.values(), ({ name, scoped, count, version }) => ({ name, scoped, count, version })) };
}
export function readSession(text) {
  const j = JSON.parse(text);
  if (!j || j.format !== 'routelark-session' || !Array.isArray(j.findings)) throw new Error('Not a Routelark session file');
  j.findings = j.findings.filter((f) => f && typeof f === 'object'); // null в массиве не должен давать пустую находку
  return j;
}
const label = (f) => (f.kind === 'secret' || f.kind === 'pii' ? f.url : (f.method && f.method !== '?' && f.method !== '-' ? f.method + ' ' : '') + f.url);
export const historyKey = (origin) => 'rl:hist:' + origin;
export function historyEntry(store) {
  const labels = {};
  const ids = stableIds(store.items);
  store.items.slice(0, 5000).forEach((f, i) => { labels[ids[i]] = label(f).slice(0, 160); }); // подписи с пределом, id — все: иначе лишние находки каждый раз «новые»
  return { date: new Date().toISOString(), ids, labels, files: fileHashes(store) };
}
// Отпечатки JS-файлов и исходников: хеш собранного бандла в имени (main.3f2a9c1b.js) не считается, иначе каждый деплой — «новый файл»
// Query отбрасывается: в нём бывают подписи и токены, а в историю секреты не пишутся. Хеш — 8+ символов с цифрой (hex у webpack, base64url у Vite)
// Хеш — hex (webpack) или смесь регистров (Vite) с цифрой: имя вроде vendor-analytics2024.js хешем не считается
const isHash = (h) => /\d/.test(h) && (/^[0-9a-f]+$/i.test(h) || (/[a-z]/.test(h) && /[A-Z]/.test(h)));
export const fileKey = (url) => { const [a, src] = String(url).split('#'); return a.split('?')[0].replace(/[.-]([A-Za-z0-9_]{8,})(?=\.(?:m?js|css|map)\b)/g, (m, h) => (isHash(h) ? '' : m)) + (src ? '#' + src : ''); };
function fileEntries(store) {
  const list = [];
  for (const [url, v] of store.texts || []) { const ty = fileType(url, v.contentType); if (ty === 'js' || url.includes('#')) list.push([fileKey(url), url, fnv(v.text) + ':' + v.text.length]); }
  // Одно имя у разных чанков (index-<hash>.js у Vite): ключ дополняется хешем, иначе порядок загрузки давал бы ложные «изменения»
  const n = {}; list.forEach(([k]) => { n[k] = (n[k] || 0) + 1; });
  return list.map(([k, url, h]) => [n[k] > 1 ? k + '@' + h : k, url, h]).sort((a, b) => (a[0] < b[0] ? -1 : 1)).slice(0, 500);
}
export function fileHashes(store) { const out = {}; for (const [k, , h] of fileEntries(store)) out[k] = h; return out; }
export function compareFiles(prev, store) {
  const cur = fileHashes(store), urls = {};
  for (const [k, url] of fileEntries(store)) urls[k] = url;
  const added = [], changed = [];
  for (const k of Object.keys(cur)) { if (!(k in prev)) added.push(urls[k]); else if (prev[k] !== cur[k]) changed.push(urls[k]); }
  return { added, changed, removed: Object.keys(prev).filter((k) => !(k in cur)) };
}
export function compareRuns(prevIds, store) {
  const prev = new Set(prevIds), ids = stableIds(store.items), cur = new Set(ids);
  return { added: store.items.filter((f, i) => !prev.has(ids[i])), removed: prevIds.filter((id) => !cur.has(id)) };
}
