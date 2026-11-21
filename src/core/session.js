// Session file and run comparison. Secrets never reach the file or history.
import { view } from './export.js';
import { fnv } from '../core.js';
import { fileType } from './files.js';

// A hash of the secret value itself (short unsalted FNV) can be brute-forced, so the file and history get a hash of the mask and location
// The finding location makes ids of different secrets with the same mask distinct; the value itself is not hashed
export const stableId = (f) => (f.kind === 'secret' || f.kind === 'pii' ? fnv(f.kind + '|' + f.type + '|' + f.secret + '|' + (f.sources && f.sources[0] ? f.sources[0].file + ':' + f.sources[0].line + ':' + f.sources[0].col : '') + '|' + f.url) : f.id);
// Colliding ids (same mask in the same place) get an ordinal suffix so findings do not merge on comparison
export function stableIds(items) { const n = {}; return items.map((f) => { const id = stableId(f); n[id] = (n[id] || 0) + 1; return n[id] > 1 ? id + '#' + n[id] : id; }); }
export function sessionFile(store, program) {
  const list = store.list(), ids = stableIds(list);
  return { format: 'routelark-session', version: 2, program: program ? program.rules : undefined, origin: store.pageOrigin, url: store.pageUrl, date: new Date().toISOString(), files: store.files.length, findings: list.map((f, i) => Object.assign(view(f, false), { id: ids[i] })), deps: Array.from(store.deps.values(), ({ name, scoped, count, version }) => ({ name, scoped, count, version })) };
}
export function readSession(text) {
  const j = JSON.parse(text);
  if (!j || j.format !== 'routelark-session' || !Array.isArray(j.findings)) throw new Error('Not a Routelark session file');
  j.findings = j.findings.filter((f) => f && typeof f === 'object'); // a null in the array must not produce an empty finding
  return j;
}
const label = (f) => (f.kind === 'secret' || f.kind === 'pii' ? f.url : (f.method && f.method !== '?' && f.method !== '-' ? f.method + ' ' : '') + f.url);
export const historyKey = (origin) => 'rl:hist:' + origin;
export function historyEntry(store) {
  const labels = {};
  const ids = stableIds(store.items);
  store.items.slice(0, 5000).forEach((f, i) => { labels[ids[i]] = label(f).slice(0, 160); }); // signatures are capped, ids are all: otherwise the extra findings look "new" every time
  return { date: new Date().toISOString(), ids, labels, files: fileHashes(store) };
}
// Fingerprints of JS files and sources: the bundle hash in the name (main.3f2a9c1b.js) is ignored, otherwise every deploy is a "new file"
// Query is dropped: it may hold signatures and tokens, and secrets are never written to history. Hash is 8+ chars with a digit (hex for webpack, base64url for Vite)
// Hash is hex (webpack) or mixed case (Vite) with a digit: a name like vendor-analytics2024.js is not a hash
const isHash = (h) => /\d/.test(h) && (/^[0-9a-f]+$/i.test(h) || (/[a-z]/.test(h) && /[A-Z]/.test(h)));
export const fileKey = (url) => { const [a, src] = String(url).split('#'); return a.split('?')[0].replace(/[.-]([A-Za-z0-9_]{8,})(?=\.(?:m?js|css|map)\b)/g, (m, h) => (isHash(h) ? '' : m)) + (src ? '#' + src : ''); };
function fileEntries(store) {
  const list = [];
  for (const [url, v] of store.texts || []) { const ty = fileType(url, v.contentType); if (ty === 'js' || url.includes('#')) list.push([fileKey(url), url, fnv(v.text) + ':' + v.text.length]); }
  // Same name for different chunks (index-<hash>.js in Vite): the key gets the hash appended, otherwise load order would cause false "changes"
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
