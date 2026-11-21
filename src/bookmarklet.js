// Точка входа закладки. Весь Routelark внутри: закладка открывает пустую вкладку и сама строит в ней интерфейс.
// RL_RUN (интерфейс) и RL_CSS (стили) подставляет сборка (build.mjs). Ни сервера, ни хостинга не нужно.
/* global RL_RUN, RL_CSS, RL_ICON */
import { createCollector, channel } from './collector.js';

// Хранилище в памяти вместо localStorage: вкладка about:blank делит origin со страницей, а в хранилище сайта Routelark не пишет
function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => { m.set(k, String(v)); }, removeItem: (k) => { m.delete(k); } };
}

const page = window;
// Тексты нужны до того, как появится интерфейс, поэтому словарь i18n сюда не тянем: язык по браузеру
const ru = /^ru\b/i.test(page.navigator && page.navigator.language || '');
const MSG = { blocked: ru ? 'Routelark: браузер заблокировал новую вкладку. Разрешите всплывающие окна для этого сайта и нажмите закладку ещё раз.' : 'Routelark: the browser blocked the new tab. Allow pop-ups for this site and click the bookmarklet again.', slow: ru ? 'Routelark: вкладка не загрузилась. Нажмите закладку ещё раз.' : 'Routelark: the new tab did not load. Click the bookmarklet again.' };
{
  // Каждое нажатие — новая чистая вкладка с уникальным именем.
  // Значок — data: URI; на сайтах со строгой CSP (img-src без data:) браузер его не покажет и напишет в консоль, на работу это не влияет
  // Вкладка открывается по настоящему адресу (blob-страница того же origin, созданная в браузере):
  // пустую about:blank Safari открывает в фоне, а обычный адрес — сразу на переднем плане
  const url = page.URL.createObjectURL(new page.Blob(['<!doctype html><meta charset="utf-8"><title>Routelark</title><link rel="icon" href="' + RL_ICON + '"><body></body>'], { type: 'text/html' }));
  const tab = page.open(url, 'routelark' + Date.now());
  if (!tab) { page.URL.revokeObjectURL(url); page.alert(MSG.blocked); }
  else {
    let started = false;
    const t0 = Date.now();
    const start = () => {
      if (started) return;
      // Вкладку закрыли или она так и не загрузилась за 30 с: перестаём ждать, чтобы не нагружать страницу сайта; про зависшую вкладку говорим
      if (tab.closed || Date.now() - t0 > 3e4) { started = true; page.clearInterval(wait); page.URL.revokeObjectURL(url); if (!tab.closed) page.alert(MSG.slow); return; }
      let d; try { d = tab.document; } catch (e) { return; }
      if (!d || d.URL !== url || d.readyState !== 'complete' || !d.body) return; // ждём, пока загрузится именно наша страница
      started = true; page.clearInterval(wait); page.URL.revokeObjectURL(url);
      // Стили через CSSStyleSheet: строгая CSP сайта блокирует <style>, а такие таблицы — нет
      try { const sheet = new tab.CSSStyleSheet(); sheet.replaceSync(RL_CSS); d.adoptedStyleSheets = [sheet]; } catch (e) { const st = d.createElement('style'); st.textContent = RL_CSS; d.head.append(st); }
      const root = d.createElement('div'); root.id = 'app'; d.body.append(root);
      const ch = channel(page, tab);
      tab.__rlPort = ch.port; // интерфейс во вкладке берёт канал отсюда (src/app/link.js)
      createCollector(ch.collector).start();
      const mem = memoryStorage();
      RL_RUN(tab, d, tab.location, tab.history, mem, mem, tab.setTimeout.bind(tab), tab.clearTimeout.bind(tab));
    };
    const wait = page.setInterval(start, 30);
  }
}
