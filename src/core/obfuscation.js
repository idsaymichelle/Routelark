// F4: признаки обфускации, распаковка packed-eval и расшифровка строк — без выполнения кода.
// Здесь нет eval, Function и строковых таймеров: только регулярки и ручной разбор (тест проверяет это по тексту модуля).
export const OBF_LABEL = { hexid: 'identifiers _0x…', array: 'string array', packed: 'packed eval', jsfuck: 'JSFuck', cff: 'control-flow flattening', esc: 'hex and Unicode escapes', b64: 'base64 literal' };
const PACKED = /eval\(function\(p,a,c,k,e,[dr]\)\{/;
const count = (re, text, cap) => { let n = 0; re.lastIndex = 0; while (re.exec(text) && n < cap) n++; return n; };

export function obfuscationScore(text) {
  text = String(text).slice(0, 2e6);
  const sig = [], add = (id, w, c) => { if (w) sig.push({ id, w, count: c }); };
  const ids = new Set(); const re = /\b_0x[0-9a-f]{4,6}\b/g; let m;
  while ((m = re.exec(text)) && ids.size < 500) ids.add(m[0]);
  add('hexid', ids.size >= 10 ? 3 : ids.size >= 3 ? 1 : 0, ids.size);
  if (/(?:var|let|const)\s+_0x[0-9a-f]{4,6}\s*=\s*\[(?:\s*(['"])(?:(?!\1)[^\\\n]|\\.){0,200}\1\s*,?){20,}\s*\]/.test(text.slice(0, 3e5))) add('array', 3, 1);
  if (PACKED.test(text)) add('packed', 4, 1);
  const tr = text.trim();
  if (tr.length >= 64 && /^[\s[\]()!+;]+$/.test(tr)) add('jsfuck', 4, 1);
  const cff = count(/while\s*\(\s*(?:!!\[\]|!0|true)\s*\)\s*\{\s*switch\s*\(/g, text, 50); add('cff', cff ? 2 : 0, cff);
  const x = count(/\\x[0-9a-fA-F]{2}/g, text, 1000) + count(/\\u[0-9a-fA-F]{4}/g, text, 1000); add('esc', x >= 300 ? 2 : x >= 50 ? 1 : 0, x);
  if (/atob\(\s*(['"])[A-Za-z0-9+/=]{200,}\1/.test(text)) add('b64', 1, 1);
  const score = sig.reduce((s, v) => s + v.w, 0), strong = sig.some((v) => v.id === 'packed' || v.id === 'jsfuck');
  return { score, level: score >= 4 || strong ? 'obfuscated' : score >= 2 ? 'possible' : null, signals: sig.map(({ id, count: c }) => ({ id, count: c })) };
}

// Строковый литерал с позиции i (кавычка); возвращает [значение, позиция после кавычки] или null
function readString(text, i) {
  const q = text[i]; if (q !== "'" && q !== '"') return null;
  let out = '';
  for (let j = i + 1; j < text.length && out.length < 2e6; j++) {
    const ch = text[j];
    if (ch === q) return [out, j + 1];
    if (ch !== '\\') { out += ch; continue; }
    const n = text[++j];
    if (n === 'n') out += '\n'; else if (n === 'r') out += '\r'; else if (n === 't') out += '\t';
    else if (n === 'x' && /^[0-9a-fA-F]{2}$/.test(text.substr(j + 1, 2))) { out += String.fromCharCode(parseInt(text.substr(j + 1, 2), 16)); j += 2; }
    else if (n === 'u' && /^[0-9a-fA-F]{4}$/.test(text.substr(j + 1, 4))) { out += String.fromCharCode(parseInt(text.substr(j + 1, 4), 16)); j += 4; }
    else out += n;
  }
  return null;
}
const B62 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
const token = (c, radix) => { if (radix <= 36) return c.toString(radix); let s = ''; do { s = B62[c % radix] + s; c = Math.floor(c / radix); } while (c); return s; };

// shortcut: замена в один проход; у исходного упаковщика возможна повторная замена, если слово содержит другой токен — доработать по реальному образцу
export function unpackPacked(text, depth = 0) {
  const m = PACKED.exec(text);
  if (!m) return depth ? { text, depth } : null;
  if (depth >= 3) return { text, depth };
  let i = text.indexOf("}('", m.index); if (i < 0) i = text.indexOf('}("', m.index);
  if (i < 0) return { error: 'no arguments' };
  const p = readString(text, i + 2); if (!p) return { error: 'arguments not recognised' };
  const rest = text.slice(p[1], p[1] + 200), nums = /^\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*/.exec(rest);
  if (!nums) return { error: 'arguments not recognised' };
  const k = readString(text, p[1] + nums[0].length);
  if (!k || !/^\.split\(\s*['"]\|['"]\s*\)/.test(text.slice(k[1], k[1] + 20))) return { error: 'arguments not recognised' };
  const radix = +nums[1], cnt = +nums[2];
  if (radix < 2 || radix > 62) return { error: 'radix ' + radix + ' not supported' };
  const words = k[0].split('|'), dict = new Map();
  for (let c = 0; c < cnt && c < 1e5; c++) if (words[c]) dict.set(token(c, radix), words[c]);
  const out = p[0].replace(/\b\w+\b/g, (w) => (dict.has(w) ? dict.get(w) : w));
  if (out.length > 4e6) return { error: 'output too large' };
  return unpackPacked(out, depth + 1);
}

export function decodeEscapes(s) {
  return s.replace(/\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\}|(.))/gs, (all, x, u, cp, other) => {
    if (x) return String.fromCharCode(parseInt(x, 16));
    if (u) return String.fromCharCode(parseInt(u, 16));
    if (cp) { const v = parseInt(cp, 16); return v <= 0x10ffff ? String.fromCodePoint(v) : all; }
    return all; // \\ и прочие экранирования не трогаем: \\x41 — это не \x41
  });
}
export function decodeB64(s) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s) || s.length % 4 === 1) return null;
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', bytes = [];
  let buf = 0, bits = 0;
  for (const ch of s.replace(/=+$/, '')) { buf = (buf << 6) | A.indexOf(ch); bits += 6; if (bits >= 8) { bits -= 8; bytes.push((buf >> bits) & 255); } }
  try { return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes)); } catch (e) { return null; }
}
export function decodeLiterals(text) {
  const out = [], re = /(['"`])((?:(?!\1)[^\\\n]|\\.){1,2000})\1/g;
  let m, line = 1, last = 0;
  while ((m = re.exec(text)) && out.length < 200) {
    if (m[1] === '`' && m[2].includes('${')) continue;
    const atob = /atob\(\s*$/.test(text.slice(Math.max(0, m.index - 10), m.index));
    if (!atob && !/\\[xu]/.test(m[2])) continue;
    for (let i = text.indexOf('\n', last); i !== -1 && i < m.index; i = text.indexOf('\n', i + 1)) line++;
    last = m.index;
    const d = atob ? decodeB64(m[2]) : decodeEscapes(m[2]);
    if (d != null && d !== m[2]) out.push({ line, raw: m[2].slice(0, 200), decoded: d.slice(0, 500) });
  }
  return out;
}
