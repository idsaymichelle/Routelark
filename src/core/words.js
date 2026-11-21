// Словарь цели: слова и имена параметров, которые сайт сам показывает. Только из уже полученных текстов, без запросов.
const STOP = new Set('the and for are but not you all any can had her was one our out day get has him his how man new now old see two way who boy did its let put say she too use that with have this will your from they know want been good much some time very when come here just like long make many more only over such take than them well were what into also back after then there their which would about could other these those where while should because through before being between both each most same under again does doing down few further once own why yes off per via http https www com org net html true false null undefined function return var const this void typeof'.split(' '));
// Только «словарные» токены: без пробелов, $ и скобок (иначе в словарь попадают куски кода вроде $dx$[$dx$)
const ok = (w) => /^[a-z0-9][a-z0-9_-]*$/.test(w) && w.length >= 3 && w.length <= 30 && !/^\d+$/.test(w) && !/^[0-9a-f]{12,}$/i.test(w) && !STOP.has(w);

function count(map, w, n) { map.set(w, (map.get(w) || 0) + (n || 1)); }
const sorted = (m, max) => Array.from(m).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, max).map(([w]) => w);

// store: Store с текстами файлов. → { words, params }
export function wordlist(store, o) {
  o = o || {};
  const words = new Map(), params = new Map();
  const page = store.texts && store.texts.get(String(store.pageUrl).split('#')[0]);
  const html = page ? page.text : '';
  if (html) {
    const visible = html.replace(/<script\b[\s\S]*?<\/script>|<style\b[\s\S]*?<\/style>/gi, ' ').replace(/<!--([\s\S]*?)-->/g, ' $1 ').replace(/<[^>]+>/g, ' ').replace(/&[a-z#0-9]+;/gi, ' ');
    for (const w of visible.toLowerCase().match(/[a-z][a-z0-9_-]{2,29}/g) || []) if (ok(w)) count(words, w);
    for (const m of html.matchAll(/\s(?:alt|title|placeholder|content|aria-label)\s*=\s*["']([^"']{1,300})["']/gi)) for (const w of m[1].toLowerCase().match(/[a-z][a-z0-9_-]{2,29}/g) || []) if (ok(w)) count(words, w);
    for (const m of html.matchAll(/<(?:input|select|textarea|button|form)\b[^>]*\s(?:name|id)\s*=\s*["']?([\w.\-[\]]{1,40})/gi)) count(params, m[1], 2);
  }
  for (const f of store.items) {
    if (f.path) for (const seg of f.path.split(/[/._-]+/)) { const w = seg.toLowerCase(); if (!/[{}]/.test(w) && ok(w)) count(words, w, 2); }
    for (const p of f.params || []) count(params, p, 2);
  }
  // Ключи JSON-файлов (OpenAPI, манифесты, конфиги): часто совпадают с полями API
  if (store.texts) for (const [url, v] of store.texts) {
    if (!/\.json(?:$|[?#])/i.test(url) && !/json/.test(v.contentType || '')) continue;
    let n = 0; for (const m of v.text.matchAll(/"([A-Za-z_][\w-]{1,39})"\s*:/g)) { count(params, m[1]); if (++n > 5000) break; }
  }
  return { words: sorted(words, o.max || 5000), params: sorted(params, o.max || 5000) };
}
