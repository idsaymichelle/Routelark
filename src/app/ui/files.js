// Site files: host -> folder -> file tree, viewer with line numbers, and search across all texts.
// Shows only what was already downloaded under scan rules or loaded by the page itself. Requests only via the "Read metadata" button.
import { unpackPacked, decodeLiterals } from '../../core/obfuscation.js';
import { h, button, copy, copyIcon, download, openInTab } from './dom.js';
import { fileType, displayText, displayPosition, searchTexts } from '../../core.js';
import { fileMeta } from '../../core/meta.js';
import { officeMeta, fontMeta } from '../../core/office.js';
import { t } from '../../i18n.js';

const WINDOW = 1000, LONG = 3000;
const TYPES = [['', 'All types'], ['js', 'JavaScript'], ['source', 'Original sources'], ['json', 'JSON'], ['html', 'HTML'], ['css', 'CSS'], ['map', 'Source maps'], ['image', 'Images'], ['other', 'Other']];
const size = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B');

// All files: downloaded (with text) and other page resources (Resource Timing info only)
export function fileList(app, store) {
  const out = [], seen = new Set();
  for (const [url, v] of store.texts) {
    seen.add(url);
    const src = url.includes('#'), type = fileType(url, v.contentType);
    out.push({ url, text: v.text, type, source: src, bytes: v.text.length });
  }
  const res = (app.page ? app.page.resources : []).concat(app.traffic || []);
  for (const r of res) {
    if (!r.url || seen.has(r.url) || !/^https?:/.test(r.url)) continue;
    seen.add(r.url);
    out.push({ url: r.url, text: null, type: fileType(r.url), bytes: r.size || 0, initiator: r.initiator, status: r.status });
  }
  return out;
}
// Menu counter without building the whole list: the menu redraws several times a second during a scan
export function fileCount(app, store) {
  let n = store.texts.size; const seen = new Set();
  for (const r of (app.page ? app.page.resources : []).concat(app.traffic || [])) if (r.url && !seen.has(r.url) && !store.texts.has(r.url) && /^https?:/.test(r.url)) { seen.add(r.url); n++; }
  return n;
}

function place(f) {
  if (f.source) { const [map, path] = f.url.split('#'); const i = path.lastIndexOf('/'); return { group: t('Sources from {file}', { file: map.replace(/^.*\//, '') }) + (i > 0 ? ' / ' + path.slice(0, i) : ''), name: path.slice(i + 1) || path }; }
  try { const u = new URL(f.url), i = u.pathname.lastIndexOf('/'); return { group: u.host + u.pathname.slice(0, i + 1), name: (u.pathname.slice(i + 1) || '/') + u.search }; } catch (e) { return { group: '', name: f.url }; }
}
// SVG has type xml in the core, but to a human it is an image: it goes into the "Images" filter
const kindOf = (f) => (f.source ? 'source' : f.type === 'xml' && /\.svg(?:$|[?#])/i.test(f.url) ? 'image' : f.type);
function disp(store, f, raw) {
  if (raw || f.text == null) return f.text;
  const c = store._disp || (store._disp = new Map());
  if (c.has(f.url)) return c.get(f.url);
  // The cache of formatted copies is bounded like the texts: beyond the limit it is reformatted on every view
  const d = displayText(f.text, f.type);
  if ((store._dispBytes || 0) + d.length <= 40e6) { c.set(f.url, d); store._dispBytes = (store._dispBytes || 0) + d.length; }
  return d;
}

// Search in a Worker: a regex that hangs on a text (e.g. (a+)+$) can be stopped by a timer
const SEARCH_MS = 8000;
let current = null;
function searchAsync(texts, q, o) {
  if (current) current.cancel(); // a new search cancels the previous one
  let w = null, url = null;
  try { url = URL.createObjectURL(new Blob(['const f=' + searchTexts.toString() + ';onmessage=(e)=>postMessage(f(e.data[0],e.data[1],e.data[2]))'], { type: 'text/javascript' })); w = new Worker(url); }
  catch (e) { if (url) URL.revokeObjectURL(url); return Promise.resolve(searchTexts(texts, q, o)); } // Worker unavailable: search on the main thread
  return new Promise((resolve) => {
    let over = false;
    const done = (r) => { if (over) return; over = true; clearTimeout(timer); w.terminate(); URL.revokeObjectURL(url); if (current && current.w === w) current = null; if (r) resolve(r); };
    const timer = setTimeout(() => done({ results: [], error: 'the search took too long, simplify the regular expression' }), SEARCH_MS);
    current = { w, cancel: () => done(null) };
    w.onmessage = (e) => done(e.data);
    // Worker failed to start (e.g. page CSP forbids blob:): search on the main thread
    w.onerror = (e) => { if (e && e.preventDefault) e.preventDefault(); done(searchTexts(texts, q, o)); };
    w.postMessage([texts, q, o]);
  });
}

// Metadata: images are read only on button click (one GET of the same file the page already loaded)
const META = new Map();
async function readMeta(f, actions) {
  META.set(f.url, { loading: true }); actions.render();
  try {
    const r = await fetch(f.url, { credentials: 'same-origin', redirect: 'error' });
    const buf = await r.arrayBuffer(), bytes = new Uint8Array(buf);
    const m = (bytes[0] === 0x50 && bytes[1] === 0x4b && await officeMeta(bytes)) || fontMeta(bytes) || fileMeta(bytes);
    if (!m.paths) m.paths = Array.from(new Set(m.fields.flatMap(([, v]) => String(v).match(/[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\\\s"]+|\/(?:Users|home)\/[^/\s"]+/g) || [])));
    let hash = ''; try { hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', buf)), (x) => x.toString(16).padStart(2, '0')).join(''); } catch (e) { /* no crypto.subtle */ }
    META.set(f.url, Object.assign(m, { bytes: buf.byteLength, type: r.headers.get('content-type') || '', modified: r.headers.get('last-modified') || '', hash }));
  } catch (e) { META.set(f.url, { error: String(e && e.message || e) }); }
  actions.render();
}
function metaBlock(f) {
  const m = META.get(f.url);
  if (!m) return null;
  if (m.loading) return h('p', { class: 'muted', text: t('Reading metadata…') });
  if (m.error) return h('p', { class: 'note', text: t('Could not read the file: {error}', { error: m.error }) });
  const rows = [[t('File format'), m.format !== 'unknown' ? m.format : null], [t('Size'), m.bytes ? size(m.bytes) : null], [t('Content type'), m.type], [t('Last modified'), m.modified], ['SHA-256', m.hash]].concat(m.fields.map(([k, v]) => [t(k), v]));
  return h('section', { class: 'meta' }, h('h3', { text: t('Metadata') }),
    m.paths && m.paths.length ? h('p', { class: 'note', text: t('Paths from the author\'s computer: {paths}', { paths: m.paths.join(', ') }) }) : null,
    m.fields.length || m.bytes ? h('dl', { class: 'kv' }, rows.filter(([, v]) => v).flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { class: 'mono', text: v })])) : h('p', { class: 'muted', text: t('No metadata found') }));
}

export function renderFiles(ctx) {
  const { app, store, actions } = ctx;
  const fx = app.fx || (app.fx = { sel: null, line: 0, col: 0, len: 0, raw: false, filter: '', type: '', q: '', regex: false, cs: false, vendor: true, results: null, err: null, start: null, jump: false });
  const all = fileList(app, store);
  const sel = all.find((f) => f.url === fx.sel) || all.find((f) => f.text != null) || all[0];

  const runSearch = () => {
    // Search runs on the source text: no formatting of all files at once, and lines match "Where found"
    const texts = all.filter((f) => f.text != null).map((f) => ({ url: f.url, text: f.text }));
    fx.busy = true; actions.render();
    searchAsync(texts, fx.q, { regex: fx.regex, caseSensitive: fx.cs, skipVendor: fx.vendor }).then((r) => {
      fx.busy = false; fx.results = fx.q ? r.results : null; fx.err = r.error; fx.truncated = r.truncated; actions.render();
    });
  };
  // line and col are always counted on the source text; for the formatted view the position is recomputed on display
  const open = (url, line, col, len) => { Object.assign(fx, { sel: url, line: line || 0, col: col || 0, len: len || 0, start: null, jump: true, raw: false }); actions.render(); };

  const q = h('input', { class: 'in', type: 'search', placeholder: t('Search in all files'), 'aria-label': t('Search in all files'), value: fx.q,
    oninput: (e) => { fx.q = e.target.value; if (!fx.q) { fx.results = null; actions.render(); } }, onkeydown: (e) => { if (e.key === 'Enter') runSearch(); } });
  const chk = (key, label) => h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: fx[key], onchange: (e) => { fx[key] = e.target.checked; if (fx.results) runSearch(); } }), t(label));
  const left = h('div', { class: 'col list' },
    h('div', { class: 'bar' }, q, button(fx.busy ? t('Searching…') : t('Find'), runSearch), chk('regex', 'Regex'), chk('cs', 'Match case'), chk('vendor', 'Skip libraries')));

  if (fx.results || fx.err) {
    left.append(h('div', { class: 'bar' }, h('span', { class: 'muted grow', text: fx.err ? (/took too long/.test(fx.err) ? t(fx.err) : t('Bad regular expression: {error}', { error: String(fx.err).replace(/^Invalid regular expression: (?:\/.*\/[a-z]*: )?/, '') })) : t('Matches: {n}', { n: fx.results.length + (fx.truncated ? '+' : '') }) }), button(t('Back to files'), () => { fx.results = null; fx.err = null; actions.render(); })));
    let last = null;
    (fx.results || []).forEach((r) => {
      if (r.url !== last) { last = r.url; const p = place({ url: r.url, source: r.url.includes('#') }); left.append(h('p', { class: 'group mono', text: p.group + (p.group.endsWith('/') ? '' : ' / ') + p.name })); }
      left.append(h('button', { class: 'row hit', type: 'button', 'aria-current': r.url === fx.sel && r.line === fx.line ? 'true' : null, onclick: () => open(r.url, r.line, r.col, r.len) },
        h('span', { class: 'l1 mono' }, h('span', { class: 'ln', text: r.line }), h('span', { class: 'route' }, r.text.slice(0, r.at), h('mark', { text: r.text.slice(r.at, r.at + r.len) }), r.text.slice(r.at + r.len)))));
    });
    if (fx.results && !fx.results.length) left.append(h('p', { class: 'empty', text: t('Nothing found') }));
  } else {
    const name = h('input', { class: 'in', type: 'search', placeholder: t('Filter by name'), 'aria-label': t('Filter by name'), value: fx.filter, oninput: (e) => { fx.filter = e.target.value.toLowerCase(); actions.render(); } });
    const type = h('select', { class: 'in', 'aria-label': t('Type'), onchange: (e) => { fx.type = e.target.value; actions.render(); } }, TYPES.map(([v, n]) => h('option', { value: v, text: t(n), selected: fx.type === v })));
    const shown = all.filter((f) => (!fx.filter || f.url.toLowerCase().includes(fx.filter)) && (!fx.type || kindOf(f) === fx.type || (fx.type === 'other' && !TYPES.some((x) => x[0] === kindOf(f)))));
    left.append(h('div', { class: 'bar' }, name, type, h('span', { class: 'muted', text: shown.length === all.length ? String(all.length) : t('{shown} of {total}', { shown: shown.length, total: all.length }) })));
    if (store.mapSkipped) left.append(h('p', { class: 'hint', text: t('Source map files not analysed, the size limit is reached: {n}', { n: store.mapSkipped }) }));
    if (store.textsSkipped) left.append(h('p', { class: 'hint', text: t('Files not kept, the memory limit is reached: {n}', { n: store.textsSkipped }) }));
    if (!shown.length) left.append(h('p', { class: 'empty', text: all.length ? t('Nothing matches the filter') : t('Nothing here yet') }));
    const groups = new Map();
    if (shown.length > 2000) left.append(h('p', { class: 'hint', text: t('Showing the first 2000 of {n}. Narrow the filter', { n: shown.length }) }));
    shown.slice(0, 2000).forEach((f) => { const p = place(f); if (!groups.has(p.group)) groups.set(p.group, []); groups.get(p.group).push([f, p.name]); });
    for (const [g, list] of Array.from(groups).sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
      left.append(h('p', { class: 'group mono', text: g }));
      list.sort((a, b) => (a[1] < b[1] ? -1 : 1)).forEach(([f, n]) => left.append(h('button', { class: 'row', type: 'button', 'aria-current': f === sel ? 'true' : null, onclick: () => open(f.url) },
        h('span', { class: 'l1' }, h('span', { class: 'route' + (f.text == null ? ' muted' : ''), text: n }), h('span', { class: 'lv', text: (app.fileDiff && app.fileDiff.changed.includes(f.url) ? t('changed') + ', ' : app.fileDiff && app.fileDiff.added.includes(f.url) ? t('new') + ', ' : '') + (f.text == null ? t('not downloaded') + ', ' : '') + kindOf(f) + (f.bytes ? ', ' + size(f.bytes) : '') + (store.obf && store.obf.get(f.url) ? ', ' + t(store.obf.get(f.url).level) : '') })))));
    }
  }
  return h('div', { class: 'split files' }, left, h('div', { class: 'col viewer' }, sel ? viewer(ctx, sel, fx) : null));
}

function viewer(ctx, f, fx) {
  const { app, store, actions } = ctx;
  const box = h('section', { class: 'detail wide' });
  const real = /^https?:/.test(f.url) && !f.url.includes('#');
  box.append(h('div', { class: 'titlebar' }, h('h2', { class: 'mono path', text: f.url }), copyIcon(f.url, t('Copy address'))));
  if (f.text == null) {
    box.append(h('dl', { class: 'kv' }, h('dt', { text: t('Type') }), h('dd', { text: f.type }), h('dt', { text: t('Loaded by') }), h('dd', { text: f.initiator || '—' }), f.bytes ? h('dt', { text: t('Size') }) : null, f.bytes ? h('dd', { text: size(f.bytes) }) : null));
    const live = real && !/fetch|xmlhttprequest|beacon/.test(f.initiator || ''); // fetch/XHR responses are API calls: not repeated
    if (f.type !== 'image') box.append(h('p', { class: 'note', text: live ? t('Routelark does not download this file on its own: it reads only JS, source maps and service files. The Read metadata button requests it once more') : t('Routelark does not download this file: it reads only JS, source maps and service files. The page itself loaded it') }));
    // The browser itself shows the image via an img tag (usually from cache: the page already loaded it); scripts in it do not run
    if (live && f.type === 'image') box.append(h('div', { class: 'imgbox' }, h('img', { src: f.url, alt: f.url.replace(/^.*\//, ''), referrerpolicy: 'no-referrer', loading: 'lazy' })));
    if (live) box.append(h('div', { class: 'acts' },
      h('a', { class: 'btn', href: f.url, target: '_blank', rel: 'noopener noreferrer', text: t('Open in new tab') }),
      h('a', { class: 'btn', href: f.url, download: f.url.replace(/[?#].*$/, '').replace(/^.*\//, '') || 'file', text: t('Download') }),
      button(t('Read metadata'), () => readMeta(f, actions))));
    const mb = metaBlock(f); if (mb) box.append(mb); // append(null) would print the text "null"
    return box;
  }
  // Obfuscation: unpacking packed-eval and decoding strings, without executing code
  const obf = store.obf && store.obf.get(f.url), unp = obf && fx.unpacked ? unpackPacked(f.text) : null;
  const pretty = unp && unp.text ? displayText(unp.text, 'js') : disp(store, f, false), changed = pretty !== f.text;
  const text = fx.raw || !changed ? f.text : pretty;
  const lines = text.split('\n');
  const inFile = store.items.filter((x) => x.sources.some((s) => s.file === f.url)).length;
  box.append(h('div', { class: 'acts' },
    changed ? button(fx.raw ? t('Format') : t('Original'), () => { fx.raw = !fx.raw; fx.start = null; fx.jump = true; actions.render(); }) : null,
    button(t('Copy'), () => copy(text)),
    button(t('Download'), () => download(f.url.replace(/[?#].*$/, '').replace(/^.*\//, '') || 'file.txt', text)),
    button(t('Open as text'), () => openInTab(text)),
    obf ? button(fx.decode ? t('Hide decoded strings') : t('Decode strings'), () => { fx.decode = !fx.decode; actions.render(); }) : null,
    obf && /eval\(function\(p,a,c,k,e,/.test(f.text) ? button(fx.unpacked ? t('Packed') : t('Unpack'), () => { fx.unpacked = !fx.unpacked; fx.start = null; fx.jump = true; actions.render(); }) : null,
    h('span', { class: 'muted', text: [f.type, size(f.text.length), t('{n} lines', { n: lines.length }), inFile ? t('findings: {n}', { n: inFile }) : ''].filter(Boolean).join(', ') })));

  if (unp && unp.error) box.append(h('p', { class: 'note', text: t('Unpacking failed: {reason}', { reason: unp.error }) }));
  if (obf && fx.decode) { const dec = decodeLiterals(f.text); box.append(h('section', { class: 'meta' }, h('h3', { text: t('Decoded strings: {n}', { n: dec.length }) }), dec.slice(0, 200).map((d) => h('p', { class: 'mono', text: t('line {n}', { n: d.line }) + ': ' + d.raw + ' → ' + d.decoded })))); }
  let target = fx.sel === f.url ? fx.line : 0, tcol = fx.col;
  if (target && changed && !fx.raw) {
    const k = f.url + '|' + fx.line + '|' + fx.col;
    if (fx.posKey !== k) { fx.pos = displayPosition(f.text, f.type, fx.line, fx.col); fx.posKey = k; }
    target = fx.pos.line; tcol = fx.pos.col;
  }
  const start = fx.start != null ? fx.start : Math.max(0, (target || 1) - 200);
  const end = Math.min(lines.length, start + WINDOW);
  const pre = h('pre', { class: 'code' });
  if (start > 0) box.append(h('div', { class: 'acts' }, button(t('Previous lines'), () => { fx.start = Math.max(0, start - WINDOW); fx.jump = false; actions.render(); })));
  for (let i = start; i < end; i++) {
    let s = lines[i], col = target === i + 1 ? tcol : 0, len = fx.len;
    // Jump from a finding: no match length, so a word or quoted string from the position is selected
    if (col && !len) len = (/^["'`][^"'`\n]{0,200}["'`]?|^[\w$.\/-]{1,200}/.exec(s.slice(col - 1)) || ['x'])[0].length;
    let cut = 0;
    if (s.length > LONG) { cut = col > LONG - 200 ? Math.max(0, col - 1000) : 0; s = (cut ? '…' : '') + s.slice(cut, cut + LONG) + '…'; }
    const row = h('span', { class: 'cl' + (target === i + 1 ? ' hl' : '') }, h('span', { class: 'ln', text: i + 1 }));
    if (col && len) { const a = col - 1 - cut + (cut ? 1 : 0); row.append(s.slice(0, a), h('mark', { text: s.slice(a, a + len) }), s.slice(a + len)); } else row.append(s);
    pre.append(row, '\n');
  }
  box.append(pre);
  if (end < lines.length) box.append(h('div', { class: 'acts' }, button(t('Next lines'), () => { fx.start = end; fx.jump = false; actions.render(); }), h('span', { class: 'muted', text: t('Lines {from}–{to} of {n}', { from: start + 1, to: end, n: lines.length }) })));
  if (fx.jump && target) setTimeout(() => { const el = pre.querySelector('.hl'); if (el) el.scrollIntoView({ block: 'center' }); fx.jump = false; }, 0);
  return box;
}
