// Маленькие помощники DOM. Данные сайта вставляются только через textContent.
import { t, getLang, plural as pluralI18n } from '../../i18n.js';
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const k in attrs || {}) {
    const v = attrs[k];
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c);
  return el;
}
const ICONS = {
  gear: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
  rescan: 'M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5', stop: 'M6 6h12v12H6z', close: 'M18 6 6 18M6 6l12 12',
  copy: 'M9 9h11v11H9zM5 15H4V4h11v1', download: 'M12 3v12m0 0-4-4m4 4 4-4M4 21h16', open: 'M14 3h7v7M21 3l-9 9M10 5H4v15h15v-6', check: 'M5 12l5 5L20 7', file: 'M14 3H6v18h12V7zM14 3v4h4'
};
export function icon(name) {
  const NS = 'http://www.w3.org/2000/svg', s = document.createElementNS(NS, 'svg'), p = document.createElementNS(NS, 'path');
  s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('aria-hidden', 'true'); s.setAttribute('class', 'ic'); p.setAttribute('d', ICONS[name]); s.append(p);
  return s;
}
export const iconButton = (name, title, onclick) => h('button', { class: 'ib', type: 'button', title, 'aria-label': title, onclick }, icon(name));
// Кнопка языка показывает ДРУГОЙ язык: RU при английском, EN при русском
export function langButton(actions) {
  const next = getLang() === 'en' ? 'ru' : 'en';
  return h('button', { class: 'btn lang', type: 'button', title: t('Switch language'), 'aria-label': t('Switch language') + ': ' + next.toUpperCase(), onclick: () => actions.setLang(next) }, next.toUpperCase());
}
// Значок копирования: после клика на секунду показывает галочку
export function copyIcon(text, title) {
  const b = iconButton('copy', title || t('Copy'), () => { copy(String(text == null ? '' : text)); b.replaceChildren(icon('check')); b.classList.add('done'); setTimeout(() => { b.replaceChildren(icon('copy')); b.classList.remove('done'); }, 1200); });
  b.classList.add('cp');
  return b;
}
export const button = (text, onclick, cls, title) => h('button', { class: 'btn' + (cls ? ' ' + cls : ''), type: 'button', onclick, title }, text);
export const plural = pluralI18n;
// Подпись продукта: параметры маршрута подсвечены акцентом
export function route(text) { const span = h('span', { class: 'route' }); String(text).split(/(\{[^}]*\})/).forEach((part, i) => span.append(i % 2 ? h('b', { text: part }) : part)); return span; }
export function copy(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).catch(fallback);
  fallback();
  function fallback() { const t = h('textarea'); t.value = text; document.body.append(t); t.select(); try { document.execCommand('copy'); } catch (e) { /* копирование запрещено */ } t.remove(); }
}
export function download(name, text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime || 'text/plain' })), a = h('a', { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
export function openInTab(text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: (mime || 'text/plain') + ';charset=utf-8' }));
  window.open(url, '_blank', 'noopener');
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}
// Значения английские; в интерфейсе выводятся через t()
export const LV = { info: 'info', low: 'low', medium: 'medium', high: 'high', critical: 'critical' };
export const CONF_LABEL = { low: 'Low', medium: 'Medium', high: 'High' };
export const dot = (level, title) => h('span', { class: 'dot ' + level, title: title || t(LV[level]), role: 'img', 'aria-label': t(LV[level]) });
export function kv(rows) {
  const box = h('dl', { class: 'kv' });
  for (const [k, v] of rows) if (v != null && v !== '' && !(Array.isArray(v) && !v.length)) box.append(h('dt', { text: k }), h('dd', {}, v && typeof v === 'object' && v.nodeType ? v : String(v)));
  return box;
}
