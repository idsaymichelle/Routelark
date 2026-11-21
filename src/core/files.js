// Файлы сайта для обозревателя: тип, форматирование минифицированного кода, поиск. Чистые функции без DOM.

const EXT = { js: 'js', mjs: 'js', cjs: 'js', jsx: 'js', ts: 'js', tsx: 'js', vue: 'js', svelte: 'js', map: 'map', json: 'json', webmanifest: 'json', html: 'html', htm: 'html', css: 'css', scss: 'css', less: 'css', xml: 'xml', svg: 'xml', txt: 'text', md: 'text' };
const IMG = /\.(?:png|jpe?g|gif|webp|avif|ico|bmp)$/i, FONT = /\.(?:woff2?|ttf|otf|eot)$/i;

// Тип по адресу и заголовку ответа: js, map, json, html, css, xml, text, image, font, wasm, other
export function fileType(url, contentType) {
  const hp = String(url).split('#'), path = (hp.length > 1 && /\.[a-z0-9]+$/i.test(hp[hp.length - 1]) ? hp[hp.length - 1] : hp[0]).split('?')[0] /* map#src/a.ts — файл из карты, иначе # — просто якорь */, ext = (/\.([a-z0-9]+)$/i.exec(path) || [])[1];
  if (/\.svg$/i.test(path)) return 'image'; // SVG — картинка для фильтра «Images»
  if (ext && EXT[ext.toLowerCase()]) return EXT[ext.toLowerCase()];
  if (IMG.test(path)) return 'image';
  if (FONT.test(path)) return 'font';
  if (/\.wasm$/i.test(path)) return 'wasm';
  const ct = String(contentType || '');
  if (/javascript|ecmascript/.test(ct)) return 'js';
  if (/json/.test(ct)) return 'json';
  if (/html/.test(ct)) return 'html';
  if (/css/.test(ct)) return 'css';
  if (/xml/.test(ct)) return 'xml';
  if (/^text\//.test(ct)) return 'text';
  return 'other';
}

// Минифицирован ли текст: длинные строки в среднем
export function isMinified(text) {
  const n = (text.match(/\n/g) || []).length + 1;
  return text.length > 2000 && (text.length / n > 300 || text.split('\n').some((l) => l.length > 3000)); // одна длинная строка в обычном файле тоже режется в интерфейсе
}

const MARK = '\uE000';
const REGEX_BEFORE = new Set('(,=:[!&|?{};+-*%<>~^'.split(''));
const REGEX_WORD = /(?:^|[^\w$])(?:return|typeof|case|do|else|in|of|new|delete|void|throw|yield|await)\s*$/;
// Расстановка переносов и отступов по скобкам и точкам с запятой. Строки, шаблоны, комментарии и регулярки не трогаются.
// shortcut: не полноценный парсер — деление «/» на регулярку и деление угадывается по предыдущему символу; для точного вида нужен AST
export function prettyJs(src) {
  const out = []; const stack = []; let indent = 0, paren = 0, i = 0, prev = '';
  // Подряд идущие переносы не копятся: последний перенос заменяется, а не дублируется
  const nl = () => { while (out.length && out[out.length - 1] === ' ') out.pop(); if (out.length && /^\n *$/.test(out[out.length - 1])) out.pop(); out.push('\n' + '  '.repeat(Math.max(0, indent))); };
  const copyUntil = (end) => { const s = i; i++; while (i < src.length && src[i] !== end) { if (src[i] === '\\') i++; i++; } i++; out.push(src.slice(s, i)); };
  while (i < src.length) {
    const c = src[i], d = src[i + 1];
    if (c === '"' || c === "'" || c === '`') { copyUntil(c); prev = c; continue; }
    if (c === '/' && d === '/') { const e = src.indexOf('\n', i); const end = e < 0 ? src.length : e; out.push(src.slice(i, end)); i = end; nl(); continue; }
    if (c === '/' && d === '*') { const e = src.indexOf('*/', i + 2); const end = e < 0 ? src.length : e + 2; out.push(src.slice(i, end)); i = end; continue; }
    if (c === '/' && (prev === '' || (REGEX_BEFORE.has(prev) && !((prev === '+' || prev === '-') && src[i - 2] === prev)) || (/[\w$]/.test(prev) && REGEX_WORD.test(src.slice(Math.max(0, i - 12), i))))) {
      const s = i; let cls = false; i++;
      while (i < src.length && src[i] !== '\n') { if (src[i] === '\\') i++; else if (src[i] === '[') cls = true; else if (src[i] === ']') cls = false; else if (src[i] === '/' && !cls) break; i++; }
      i++; while (/[a-z]/i.test(src[i] || '')) i++;
      out.push(src.slice(s, i)); prev = '/'; continue;
    }
    if (c === '\n' || c === '\r') { i++; if (out.length && !/\n *$/.test(out[out.length - 1])) nl(); continue; }
    if (c === ' ' || c === '\t') { if (out.length && !/[\n ]$/.test(out[out.length - 1])) out.push(' '); i++; continue; }
    i++;
    if (c === MARK) { out.push(c); continue; } // метка позиции не влияет на разбор
    if (c === '(' || c === '[') paren++;
    if (c === ')' || c === ']') paren = Math.max(0, paren - 1);
    if (c === '{') { stack.push(paren); paren = 0; out.push('{'); indent++; nl(); prev = c; continue; }
    if (c === '}') { paren = stack.pop() || 0; indent--; if (!/\n *$/.test(out[out.length - 1] || '')) nl(); else { out.pop(); out.push('\n' + '  '.repeat(Math.max(0, indent))); } out.push('}'); if (!/[,;)\].]/.test(src[i] || '')) nl(); prev = c; continue; }
    if (c === ';' && !paren) { out.push(';'); nl(); prev = c; continue; }
    out.push(c); prev = c;
  }
  return out.join('').trim() + '\n';
}

// Текст для показа: минифицированный JS и JSON раскладываются по строкам, остальное как есть
export function displayText(text, type) {
  if (text.length > 6e6) return text;
  if (type === 'json' || type === 'map') { try { return JSON.stringify(JSON.parse(text), null, 2); } catch (e) { return text; } }
  if (type === 'js' && isMinified(text)) return prettyJs(text);
  return text;
}

// Поиск по файлам: [{url, text}] → [{url, line, col, text}]. Лимиты на файл и всего, чтобы большая выдача не вешала вкладку.
// Функция самодостаточна (без ссылок наружу): вкладка запускает её текст в Worker, чтобы зависшую регулярку можно было прервать
export function searchTexts(files, query, o) {
  o = o || {};
  const VENDOR = /node_modules|\/vendor\/|jquery|polyfill|bootstrap|lodash|moment|react-dom|zone\.js|core-js|webpack\/runtime|\.min\.js/i; // библиотеки, которые обычно не нужно искать
  if (!query) return { results: [], error: null };
  let re;
  try { re = new RegExp(o.regex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), o.caseSensitive ? 'g' : 'gi'); } catch (e) { return { results: [], error: e.message }; }
  const results = [], max = o.max || 500, perFile = o.perFile || 50, t0 = Date.now();
  let timedOut = false, capped = false;
  for (const f of files) {
    if (o.skipVendor && VENDOR.test(f.url)) continue;
    let m, n = 0, line = 1, last = 0;
    re.lastIndex = 0;
    if (Date.now() - t0 > (o.timeBudget || 3000)) { timedOut = true; break; }
    while ((m = re.exec(f.text)) && n < perFile && results.length < max) {
      if (!m[0]) { re.lastIndex++; continue; }
      for (let k = last; k < m.index; k++) if (f.text.charCodeAt(k) === 10) line++;
      last = m.index;
      // Совпадение, начинающееся с перевода строки, относится к концу своей строки
      const ls = m.index ? f.text.lastIndexOf('\n', m.index - 1) + 1 : 0, le = f.text.indexOf('\n', m.index + 1);
      const from = Math.max(ls, m.index - 80), to = Math.min(f.text.length, Math.max(le < 0 ? f.text.length : le, m.index + m[0].length), m.index + m[0].length + 80);
      results.push({ url: f.url, line, col: m.index - ls + 1, text: f.text.slice(from, to), at: m.index - from, len: m[0].length });
      n++;
    }
    if (m && n >= perFile) capped = true; // за лимитом на файл остались совпадения
    if (results.length >= max) break;
  }
  return { results, error: null, truncated: capped || results.length >= max || timedOut };
}

// Позиция (строка и колонка исходного текста) в отформатированном тексте: в исходник вставляется невидимая метка,
// текст форматируется, метка находится. Для JSON и неформатируемых файлов возвращает ту же позицию.
export function displayPosition(text, type, line, col) {
  if (line && (type === 'json' || type === 'map') && text.length <= 6e6) return jsonPosition(text, type, line, col);
  if (!line || type !== 'js' || !isMinified(text) || text.length > 6e6) return { line, col };
  let off = 0;
  for (let l = 1; l < line; l++) { off = text.indexOf('\n', off) + 1; if (!off) return { line, col }; }
  off += Math.max(0, (col || 1) - 1);
  const out = prettyJs(text.slice(0, off) + MARK + text.slice(off)), at = out.indexOf(MARK);
  if (at < 0) return { line, col };
  const ls = out.lastIndexOf('\n', at - 1) + 1;
  return { line: (out.slice(0, at).match(/\n/g) || []).length + 1, col: at - ls + 1 };
}

// JSON показывается переформатированным: находим то же по счёту вхождение строки исходной позиции в показанном тексте
function jsonPosition(text, type, line, col) {
  let off = 0;
  for (let l = 1; l < line; l++) { off = text.indexOf('\n', off) + 1; if (!off) return { line, col }; }
  off += Math.max(0, (col || 1) - 1);
  const shown = displayText(text, type); if (shown === text) return { line, col };
  // Один токен JSON (строка или число): пробелы вокруг : и , в показанном тексте другие
  const tok = /^(?:"(?:[^"\\\n]|\\.){0,200}"?|[^\s,:{}[\]]{1,200})/.exec(text.slice(off, off + 210)), needle = tok && tok[0]; if (!needle) return { line, col };
  let k = 0; for (let i = text.indexOf(needle); i >= 0 && i < off; i = text.indexOf(needle, i + 1)) k++;
  let at = -1; for (let i = 0; i <= k; i++) { at = shown.indexOf(needle, at + 1); if (at < 0) return { line, col }; }
  const ls = shown.lastIndexOf('\n', at - 1) + 1;
  return { line: (shown.slice(0, at).match(/\n/g) || []).length + 1, col: at - ls + 1 };
}
