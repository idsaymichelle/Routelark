// WebAssembly parsing by bytes, without compiling or running (page CSP is not affected). Reads header, imports, exports,
// custom section names, producers, function names, debug data references and strings from the data section.
const KIND = ['func', 'table', 'memory', 'global', 'tag'];
export function parseWasm(b) {
  const r = { ok: false, version: 0, sections: 0, imports: [], exports: [], customs: [], producers: {}, funcNames: [], externalDebugInfo: null, sourceMappingURL: null, urls: [], paths: [], truncated: false };
  if (!(b instanceof Uint8Array)) b = new Uint8Array(b);
  if (b.length < 8 || b[0] !== 0 || b[1] !== 0x61 || b[2] !== 0x73 || b[3] !== 0x6d) return Object.assign(r, { error: 'not wasm' });
  r.version = b[4] | (b[5] << 8); r.ok = true;
  if (b[6] | (b[7] << 8)) return Object.assign(r, { layer: b[6] | (b[7] << 8), error: 'component' }); // Component Model: a different format, the module is not parsed
  let p = 8;
  const dec = new TextDecoder('utf-8');
  const leb = () => { let v = 0, s = 0; for (let i = 0; i < 5; i++) { if (p >= b.length) throw new Error('truncated'); const x = b[p++]; v |= (x & 0x7f) << s; if (!(x & 0x80)) return v >>> 0; s += 7; } throw new Error('bad leb'); };
  const str = () => { const n = leb(); if (p + n > b.length) throw new Error('truncated'); let s = ''; try { s = dec.decode(b.subarray(p, p + n)); } catch (e) { /* not UTF-8 */ } p += n; return s; };
  try {
    while (p < b.length) {
      const id = b[p++], size = leb(), start = p, end = p + size;
      if (end > b.length) { r.truncated = true; break; }
      r.sections++;
      if (id === 0) {
        const name = str();
        if (r.customs.length < 100) r.customs.push(name);
        if (name === 'external_debug_info' || name === 'sourceMappingURL') r[name === 'sourceMappingURL' ? 'sourceMappingURL' : 'externalDebugInfo'] = str();
        else if (name === 'producers') { for (let n = leb(), i = 0; i < n && p < end; i++) { const field = str(), list = []; for (let k = leb(), j = 0; j < k && p < end; j++) list.push([str(), str()]); r.producers[field] = list; } }
        else if (name === 'name') { while (p < end) { const sub = b[p++], sz = leb(), se = p + sz; if (sub === 1) for (let n = leb(), i = 0; i < n && p < se && r.funcNames.length < 300; i++) { leb(); r.funcNames.push(str()); } p = se; } }
      } else if (id === 2) {
        for (let n = leb(), i = 0; i < n && p < end; i++) {
          const module = str(), name = str(), kind = b[p++];
          if (kind === 0) leb(); else if (kind === 1) { p++; const f = b[p++]; leb(); if (f & 1) leb(); } else if (kind === 2) { const f = b[p++]; leb(); if (f & 1) leb(); } else if (kind === 3) p += 2; else if (kind === 4) { p++; leb(); } else throw new Error('bad import kind');
          if (r.imports.length < 500) r.imports.push({ module, name, kind: KIND[kind] || String(kind) });
        }
      } else if (id === 7) {
        for (let n = leb(), i = 0; i < n && p < end; i++) { const name = str(), kind = b[p++]; leb(); if (r.exports.length < 500) r.exports.push({ name, kind: KIND[kind] || String(kind) }); }
      } else if (id === 11) {
        let s = ''; for (let i = start; i < end; i++) s += String.fromCharCode(b[i]);
        const seen = new Set(), paths = new Set(); for (const m of s.matchAll(/https?:\/\/[\x21-\x7e]{4,200}|\/[\w./-]{3,200}/g)) { const t = m[0][0] === 'h' ? seen : paths; if (t.size < 50) t.add(m[0]); }
        r.urls = Array.from(seen); r.paths = Array.from(paths); // paths from data are not URLs
      }
      p = end;
    }
  } catch (e) { r.truncated = true; r.error = e.message; }
  return r;
}
// Fields for the metadata block in "Files"
export function wasmFields(w) {
  const f = [['Imports', w.imports.length + ''], ['Exports', w.exports.length + '']];
  const tool = (w.imports.find((i) => /^(?:wasi_snapshot_preview1|gojs|__wbindgen_placeholder__|wbg)$/.test(i.module)) || {}).module;
  if (tool) f.push(['Toolchain hint', tool]);
  for (const [k, v] of Object.entries(w.producers)) f.push(['Producers: ' + k, v.map((x) => x.join(' ')).join(', ')]);
  if (w.customs.length) f.push(['Custom sections', w.customs.join(', ')]);
  if (w.sourceMappingURL) f.push(['Source map', w.sourceMappingURL]);
  if (w.externalDebugInfo) f.push(['External debug info', w.externalDebugInfo]);
  const risky = w.imports.filter((i) => /fetch|xhr|websocket|eval|storage|cookie|postmessage|wallet|sign|request/i.test(i.name)).map((i) => i.module + '.' + i.name);
  if (risky.length) f.push(['Host functions to check', risky.slice(0, 20).join(', ')]);
  if (w.funcNames.length) f.push(['Function names', w.funcNames.slice(0, 40).join(', ')]);
  if (w.urls.length) f.push(['Strings', w.urls.slice(0, 30).join(' ')]);
  if (w.paths && w.paths.length) f.push(['Paths in data', w.paths.slice(0, 30).join(' ')]);
  return f;
}
