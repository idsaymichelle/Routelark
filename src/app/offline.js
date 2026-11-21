// Разбор сохранённых файлов без сети: сессия Routelark, HAR, экспорт Burp/ZAP/Caido, cookies, JS и source map
import { Store, analyzeInto, parseTrafficExport } from '../core.js';
import { parseCookieInput } from '../core/cookies.js';
import { readSession } from '../core/session.js';

export async function analyzeFiles(files, pasted, settings) {
  const inputs = pasted ? [{ name: 'pasted text', text: pasted }] : [];
  for (const f of files) inputs.push({ name: f.name, text: await f.text() });
  const json = (text) => { if (/^\s*[{[]/.test(text)) try { return JSON.parse(text); } catch (e) { /* не JSON */ } return null; };
  // Файл сессии становится основой, остальные файлы пачки дописываются в тот же набор, а не теряются
  const sess = inputs.find((x) => { const j = json(x.text); return j && j.format === 'routelark-session'; });
  let store = new Store(''), page = null, cookies = [], status = 'offline analysis';
  if (sess) { const j = readSession(sess.text); store = new Store(j.url || ''); j.findings.forEach((f) => store.items.push(Object.assign({ sources: [], params: [], why: [], owasp: [], auth: [] }, f))); status = 'session from ' + String(j.date).slice(0, 10); }
  store.rules = settings.rules && settings.rules.length ? settings.rules : null;
  for (const { name, text } of inputs) {
    if (sess && text === sess.text) continue;
    const src = 'https://offline.invalid/' + encodeURIComponent(name);
    const j = json(text);
    if (Array.isArray(j) && j[0] && j[0].name && 'value' in j[0]) { cookies = cookies.concat(parseCookieInput(text)); continue; }
    // Трафик из Burp, ZAP, Caido, HAR или список адресов: каждый запрос становится находкой из трафика
    let imp = null; try { imp = parseTrafficExport(text); } catch (e) { store.addSimple('dom', { title: 'File not parsed: ' + name, risk: 0, why: [String(e && e.message || e).slice(0, 200)], file: name }); }
    // Сам текст тоже разбирается: в заголовках и телах экспорта бывают токены и ключи
    if (imp) { imp.requests.forEach((r) => store.addHit({ raw: r.url, method: r.method, file: name, line: 1, col: 1, via: 'observed', confidence: 'high', snippet: imp.source })); store.addText(src, text); analyzeInto(store, text, src); (imp.bodies || []).forEach((b, i) => { const u = src + '#body' + (i + 1); store.addText(u, b); analyzeInto(store, b, u); }); store.files.push(name); continue; }
    // Текст разбирается всегда (в .env и похожих файлах лежат ключи); cookies — только из явного формата: Netscape с табами или строка Cookie
    store.addText(src, text); analyzeInto(store, text, src); store.files.push(name);
    if (!/[{}()]|=>|function|\bvar\b|\bconst\b/.test(text) && (/\t(?:TRUE|FALSE)\t/.test(text) || /^\s*(?:Set-)?Cookie\s*:/im.test(text) || /^[\w.-]+=[^;\n]*(?:;\s*[\w.-]+=[^;\n]*)+\s*$/.test(text.trim()))) cookies = cookies.concat(parseCookieInput(text));
  }
  store.status = status;
  return { store, page, cookies };
}
