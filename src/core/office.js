// Office document metadata (docx/xlsx/pptx are ZIPs with docProps) and fonts (OpenType/TrueType name table).
// Only on button press and only for files the page loaded or links to. Unpacking uses DecompressionStream, no libraries.
const u16 = (b, o) => (b[o] << 8) | b[o + 1], u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const le16 = (b, o) => b[o] | (b[o + 1] << 8), le32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const WANT = /^(?:docProps\/(?:core|app|custom)\.xml)$/;

// ZIP central directory entries: { name, method, size, offset }
export function zipEntries(b) {
  let e = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (le32(b, i) === 0x06054b50) { e = i; break; }
  if (e < 0) return null;
  const out = [], n = le16(b, e + 10); let p = le32(b, e + 16);
  for (let i = 0; i < n && i < 2000 && p + 46 <= b.length && le32(b, p) === 0x02014b50; i++) {
    const nl = le16(b, p + 28), xl = le16(b, p + 30), cl = le16(b, p + 32);
    out.push({ name: new TextDecoder().decode(b.subarray(p + 46, p + 46 + nl)), method: le16(b, p + 10), size: le32(b, p + 20), offset: le32(b, p + 42) });
    p += 46 + nl + xl + cl;
  }
  return out;
}
async function entryText(b, en) {
  const h = en.offset; if (le32(b, h) !== 0x04034b50 || en.size > 2e6) return '';
  const start = h + 30 + le16(b, h + 26) + le16(b, h + 28), raw = b.subarray(start, start + en.size);
  if (en.method === 0) return new TextDecoder().decode(raw);
  if (en.method !== 8 || typeof DecompressionStream === 'undefined') return '';
  // Read the decompressed stream in chunks and stop at 200 KB: otherwise a zip bomb inflates fully into memory
  try {
    const rd = new Blob([raw]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader(), dec = new TextDecoder();
    let out = '';
    while (out.length < 2e5) { const { value, done } = await rd.read(); if (done) break; out += dec.decode(value, { stream: true }); }
    rd.cancel().catch(() => {});
    return out.slice(0, 2e5);
  } catch (e) { return ''; }
}
const xmlText = (x) => x.replace(/&(?:#(\d+)|#x([\da-f]+)|(lt|gt|quot|apos));|&amp;/gi, (m, d, h, n) => { if (n) return { lt: '<', gt: '>', quot: '"', apos: "'" }[n.toLowerCase()]; if (m === '&amp;') return '&'; try { return String.fromCodePoint(d ? +d : parseInt(h, 16)); } catch (e) { return m; } }); // &amp; is handled in a single pass, double decoding is excluded
const TAGS = [['dc:creator', 'Author'], ['cp:lastModifiedBy', 'Last modified by'], ['dc:title', 'Title'], ['dcterms:created', 'Created'], ['dcterms:modified', 'Modified'], ['Application', 'Created with'], ['AppVersion', 'App version'], ['Company', 'Company'], ['Manager', 'Manager'], ['Template', 'Template']];
export async function officeMeta(b) {
  const list = zipEntries(b); if (!list) return null;
  const docs = list.filter((x) => WANT.test(x.name));
  const kind = list.some((x) => x.name.startsWith('word/')) ? 'Word document' : list.some((x) => x.name.startsWith('xl/')) ? 'Excel workbook' : list.some((x) => x.name.startsWith('ppt/')) ? 'PowerPoint deck' : 'ZIP archive';
  const fields = [['Files inside', list.length + '']];
  for (const d of docs) {
    const xml = await entryText(b, d);
    for (const [tag, label] of TAGS) { const m = new RegExp('<' + tag + '\\b[^>]*>([^<]{1,300})</' + tag + '>').exec(xml); if (m) fields.push([label, xmlText(m[1].trim())]); }
    if (/custom\.xml$/.test(d.name)) for (const m of xml.matchAll(/<property\b[^>]*name="([^"]{1,80})"[^>]*>\s*<vt:\w+>([^<]{1,200})</g)) fields.push(['Custom: ' + m[1], xmlText(m[2])]);
  }
  if (docs.length && typeof DecompressionStream === 'undefined') fields.push(['Note', 'This browser cannot unpack ZIP entries']);
  return { format: kind, fields };
}
// Font name table: TTF/OTF as is; WOFF2 and WOFF are compressed and not parsed
const NAME_IDS = { 0: 'Copyright', 1: 'Family', 3: 'Unique ID', 4: 'Full name', 5: 'Version', 8: 'Manufacturer', 9: 'Designer', 10: 'Description', 11: 'Vendor URL', 12: 'Designer URL', 13: 'License', 14: 'License URL' };
export function fontMeta(b) {
  const tag = String.fromCharCode(b[0], b[1], b[2], b[3]);
  if (tag === 'wOFF' || tag === 'wOF2') return { format: tag === 'wOF2' ? 'WOFF2 font' : 'WOFF font', fields: [['Note', 'Compressed font: the name table is not read']] };
  if (!(u32(b, 0) === 0x00010000 || tag === 'OTTO' || tag === 'true')) return null;
  const n = u16(b, 4); let name = -1;
  for (let i = 0; i < n && 12 + i * 16 + 16 <= b.length; i++) { const r = 12 + i * 16; if (String.fromCharCode(b[r], b[r + 1], b[r + 2], b[r + 3]) === 'name') name = u32(b, r + 8); }
  if (name < 0 || name + 6 > b.length) return { format: 'Font', fields: [] };
  const count = u16(b, name + 2), store = name + u16(b, name + 4), fields = [], seen = new Set();
  for (let pass = 0; pass < 2; pass++) { for (let i = 0; i < count && i < 500; i++) {
    const r = name + 6 + i * 12; if (r + 12 > b.length) break;
    const plat = u16(b, r), id = u16(b, r + 6), len = u16(b, r + 8), off = store + u16(b, r + 10);
    if (!NAME_IDS[id] || off + len > b.length) continue;
    // two passes: Windows/Unicode first, then Mac for ASCII only (Mac Roman is not decoded)
    if (pass ? plat !== 1 : plat !== 3 && plat !== 0) continue;
    if (seen.has(id)) continue;
    let s = ''; if (!pass) for (let j = 0; j + 1 < len; j += 2) s += String.fromCharCode(u16(b, off + j)); else { for (let j = 0; j < len; j++) s += String.fromCharCode(b[off + j]); if (/[^\x20-\x7e]/.test(s)) continue; }
    if (s.trim()) { seen.add(id); fields.push([NAME_IDS[id], s.trim().slice(0, 300)]); }
  }}
  return { format: tag === 'OTTO' ? 'OpenType font' : 'TrueType font', fields };
}
