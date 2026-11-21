// Главная: файл routelark.html, открытый с диска. Установка закладки.
/* global RL_BOOKMARKLET */
import { h, button, copy, langButton } from './dom.js';
import { t } from '../../i18n.js';
import { analyzeFiles } from '../offline.js';


export function renderHome({ app, actions }) {
  const bm = RL_BOOKMARKLET, served = /^https?:$/.test(location.protocol);
  const st = app.home || (app.home = { note: '' });
  const link = h('a', { class: 'drag', href: bm, onclick: (e) => e.preventDefault(), text: 'Routelark' });
  const open = h('input', { type: 'file', multiple: true, hidden: true, onchange: async (e) => {
    try { const r = await analyzeFiles(Array.from(e.target.files), '', app.settings); if (!r.store.items.length && !(r.cookies || []).length) st.note = 'No findings in this data'; else return actions.showStore(r.store, r.page, r.cookies); }
    catch (x) { st.note = 'Could not parse: ' + (x && x.message || x); }
    actions.render();
  } });
  return h('div', { class: 'home' },
    h('div', { class: 'homebar' }, h('span', { class: 'grow' }), langButton(actions)),
    h('h1', { text: 'Routelark' }),
    h('p', { class: 'lead', text: t('Finds the APIs, secrets, stack and weak spots that a site gives away in its pages, scripts and files. Click the bookmarklet on a page and the results open in a new tab') }),

    h('section', { class: 'card' }, h('h2', { text: t('Bookmarklet') }),
      h('p', { text: t('Drag the button to your bookmarks bar. Open a site from your own scope and click it. Everything is inside the bookmarklet: no server, no install. The first pass reads only what the page already loaded; Full scan also downloads its JS, source maps and service files') }),
      // Firefox молча обрезает закладки длиннее 64 КБ: говорим сразу, а не после нерабочего нажатия
      /Firefox\//.test(navigator.userAgent) ? h('p', { class: 'note', text: t('Firefox is not supported: it cuts bookmarks longer than 64 KB. Use Chrome, Edge or Safari') }) : null,
      // Запасной путь, если браузер или сайт не дают запустить закладку: код вставляется в консоль разработчика (не в адресную строку)
      h('div', { class: 'acts' }, link, button(t('Copy code for DevTools console'), () => { copy(decodeURIComponent(bm.slice(11))); st.note = 'Code copied: open the target page, press F12, choose Console and paste it there'; actions.render(); }))),

    // Офлайн-анализ не требует сайта: сохранённую сессию, HAR или файл можно открыть прямо с главной
    h('section', { class: 'card' }, h('h2', { text: t('Open session or file') }),
      h('p', { text: t('A saved session, HAR, an export from Burp, ZAP or Caido, or a JS/map file') }),
      h('div', { class: 'acts' }, button(t('Open session or file'), () => open.click()), open)),

    h('p', { class: 'where' }, t('Use it on your own sites or on practice apps made for this, such as OWASP Juice Shop, and only where you are allowed to test'),
      served ? h('a', { class: 'btn', href: 'demo.html', text: t('Open the test page') }) : null),
    // Сообщения (код скопирован) — внизу страницы, чтобы не сдвигать кнопки
    h('p', { class: 'muted foot', 'aria-live': 'polite', text: st.note ? t(st.note) : '' })
  );
}
