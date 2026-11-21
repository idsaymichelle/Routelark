// Метаданные файлов: размеры картинок, EXIF (камера, программа, автор, дата, GPS), текстовые блоки PNG, XMP, комментарии.
// Чистая функция над байтами, без библиотек. Разбирается только то, что полезно для разведки.

const ascii = (b, s, n) => { let t = ''; for (let i = s; i < s + n && i < b.length; i++) t += String.fromCharCode(b[i]); return t; };
// PDF hex-строка: UTF-16BE с BOM FEFF или однобайтовая
const hexStr = (h) => { const b = (h.replace(/\s/g, '').match(/../g) || []).map((x) => parseInt(x, 16)); let t = ''; if (b[0] === 0xfe && b[1] === 0xff) for (let i = 2; i + 1 < b.length; i += 2) t += String.fromCharCode((b[i] << 8) | b[i + 1]); else for (const c of b) t += String.fromCharCode(c); return t; };
const clean = (s) => String(s).replace(/\0+$/, '').trim();

// EXIF: TIFF-заголовок внутри JPEG (APP1) или PNG (eXIf). Возвращает пары [поле, значение]
const TAGS = { 0x010f: 'Camera make', 0x0110: 'Camera model', 0x0131: 'Software', 0x013b: 'Artist', 0x8298: 'Copyright', 0x0132: 'Modified', 0x9003: 'Taken', 0x010e: 'Description', 0xa430: 'Camera owner', 0xa431: 'Camera serial' };
function exif(b, t) {
  const out = [];
  if (t + 8 > b.length) return out;
  const le = b[t] === 0x49, u16 = (o) => (le ? b[o] | (b[o + 1] << 8) : (b[o] << 8) | b[o + 1]);
  const u32 = (o) => (le ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0 : ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0);
  const rational = (o) => { const d = u32(o + 4); return d ? u32(o) / d : 0; };
  const gps = {};
  const ifd = (off, kind, depth) => {
    if (depth > 3 || t + off + 2 > b.length) return;
    const n = u16(t + off);
    for (let i = 0; i < n && i < 200; i++) {
      const e = t + off + 2 + i * 12; if (e + 12 > b.length) return;
      const tag = u16(e), type = u16(e + 2), count = u32(e + 4), vo = count > 4 || type === 5 ? t + u32(e + 8) : e + 8;
      if (kind === 'gps') {
        if (tag === 1 || tag === 3) gps[tag] = ascii(b, e + 8, 1);
        if ((tag === 2 || tag === 4) && type === 5 && vo + 24 <= b.length) gps[tag] = rational(vo) + rational(vo + 8) / 60 + rational(vo + 16) / 3600;
        continue;
      }
      if (tag === 0x8769) ifd(u32(e + 8), 'exif', depth + 1);
      else if (tag === 0x8825) ifd(u32(e + 8), 'gps', depth + 1);
      else if (TAGS[tag] && type === 2 && vo + count <= b.length) { const v = clean(ascii(b, vo, count)); if (v) out.push([TAGS[tag], v]); }
    }
  };
  ifd(u32(t + 4), 'ifd0', 0);
  if (gps[2] != null && gps[4] != null) out.unshift(['GPS location', (gps[1] === 'S' ? -gps[2] : gps[2]).toFixed(6) + ', ' + (gps[3] === 'W' ? -gps[4] : gps[4]).toFixed(6)]);
  return out;
}
// XMP — XML внутри файла: программа, автор, история правок
function xmp(text) {
  const out = [], get = (re, name) => { const m = re.exec(text); if (m) out.push([name, clean(m[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' '))]); };
  get(/<xmp:CreatorTool>([^<]+)</, 'Created with'); get(/xmp:CreatorTool="([^"]+)"/, 'Created with');
  get(/<dc:creator>([\s\S]*?)<\/dc:creator>/, 'Author'); get(/<pdf:Producer>([^<]+)</, 'Producer');
  return out;
}

import { parseWasm, wasmFields } from './wasm.js';

export function fileMeta(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), out = [];
  let format = 'unknown';
  if (b[0] === 0xff && b[1] === 0xd8) {
    format = 'JPEG';
    for (let o = 2; o + 4 < b.length && b[o] === 0xff;) {
      const m = b[o + 1], len = (b[o + 2] << 8) | b[o + 3];
      if (m === 0xda) break; // дальше сами пиксели
      if (m === 0xe1 && ascii(b, o + 4, 4) === 'Exif') out.push(...exif(b, o + 10));
      else if (m === 0xe1 && ascii(b, o + 4, 28) === 'http://ns.adobe.com/xap/1.0/') out.push(...xmp(ascii(b, o + 4, len - 2)));
      else if (m === 0xfe) out.push(['Comment', clean(ascii(b, o + 4, len - 2))]);
      else if (m >= 0xc0 && m <= 0xc3) out.unshift(['Size', ((b[o + 7] << 8) | b[o + 8]) + ' × ' + ((b[o + 5] << 8) | b[o + 6])]);
      o += 2 + len;
    }
  } else if (ascii(b, 1, 3) === 'PNG') {
    format = 'PNG';
    for (let o = 8; o + 8 <= b.length;) {
      const len = ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0, type = ascii(b, o + 4, 4), d = o + 8;
      if (type === 'IHDR') out.push(['Size', (((b[d] << 24) | (b[d + 1] << 16) | (b[d + 2] << 8) | b[d + 3]) >>> 0) + ' × ' + (((b[d + 4] << 24) | (b[d + 5] << 16) | (b[d + 6] << 8) | b[d + 7]) >>> 0)]);
      else if (type === 'tEXt' || type === 'iTXt') {
        const raw = ascii(b, d, len), k = raw.indexOf('\0'), key = raw.slice(0, k);
        // iTXt: флаг сжатия, метод, язык, переведённый ключ; сжатые пропускаем
        const val = type === 'tEXt' ? raw.slice(k + 1) : raw.charCodeAt(k + 1) ? '' : raw.slice(k + 3).split('\0').slice(2).join('\0');
        if (key === 'XML:com.adobe.xmp') out.push(...xmp(val)); else if (val) out.push([key, clean(val).slice(0, 300)]);
      } else if (type === 'eXIf') out.push(...exif(b, d));
      else if (type === 'IEND') break;
      o = d + len + 4;
    }
  } else if (ascii(b, 0, 3) === 'GIF') {
    format = 'GIF'; out.push(['Size', (b[6] | (b[7] << 8)) + ' × ' + (b[8] | (b[9] << 8))]);
  } else if (b[0] === 0 && ascii(b, 1, 3) === 'asm') {
    format = 'WebAssembly'; out.push(...wasmFields(parseWasm(b)));
  } else if (ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 4) === 'WEBP') {
    format = 'WebP';
  } else {
    const text = ascii(b, 0, Math.min(b.length, 2e5));
    if (/<svg[\s>]/i.test(text)) {
      format = 'SVG';
      const g = (re, name) => { const m = re.exec(text); if (m) out.push([name, clean(m[1])]); };
      g(/inkscape:version="([^"]+)"/, 'Created with'); g(/Generator: ([^-]+?)\s*-->/, 'Created with');
      g(/sodipodi:docname="([^"]+)"/, 'Original file'); g(/(?:sodipodi:docbase|inkscape:export-filename)="([^"]+)"/, 'Path on author\'s computer');
      if (/xmlns:i="http:\/\/ns\.adobe\.com\/AdobeIllustrator/.test(text)) out.push(['Created with', 'Adobe Illustrator']);
      out.push(...xmp(text));
      for (const m of text.matchAll(/<!--([\s\S]*?)-->/g)) if (out.length < 40) out.push(['Comment', clean(m[1]).slice(0, 200)]);
    } else if (text.startsWith('%PDF')) {
      format = 'PDF';
      for (const [k, name] of [['Author', 'Author'], ['Creator', 'Created with'], ['Producer', 'Producer'], ['Title', 'Title']]) { const m = new RegExp('/' + k + '\\s*\\(([^)]{1,200})\\)').exec(text), x = !m && new RegExp('/' + k + '\\s*<([0-9A-Fa-f\\s]{2,400})>').exec(text); if (m) out.push([name, clean(m[1])]); else if (x) out.push([name, clean(hexStr(x[1]))]); }
      out.push(...xmp(text));
    }
  }
  // Пути на компьютере автора выдают имя пользователя и устройство папок
  const paths = [];
  for (const [, v] of out) for (const m of String(v).matchAll(/[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\\\s"]+|\/(?:Users|home)\/[^/\s"]+/g)) paths.push(m[0]);
  return { format, fields: out.filter(([, v]) => v), paths: Array.from(new Set(paths)) };
}
