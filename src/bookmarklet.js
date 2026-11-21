// Bookmarklet entry point. All of Routelark is inside: the bookmarklet opens a blank tab and builds the UI in it.
// The build (build.mjs) injects RL_RUN (UI) and RL_CSS (styles). No server or hosting needed.
/* global RL_RUN, RL_CSS, RL_ICON */
import { createCollector, channel } from './collector.js';

// In-memory storage instead of localStorage: an about:blank tab shares the page origin, and Routelark writes nothing to site storage
function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => { m.set(k, String(v)); }, removeItem: (k) => { m.delete(k); } };
}

const page = window;
// Texts are needed before the UI exists, so the i18n dictionary is not pulled in: language comes from the browser
const ru = /^ru\b/i.test(page.navigator && page.navigator.language || '');
const MSG = { blocked: ru ? 'Routelark: браузер заблокировал новую вкладку. Разрешите всплывающие окна для этого сайта и нажмите закладку ещё раз.' : 'Routelark: the browser blocked the new tab. Allow pop-ups for this site and click the bookmarklet again.', slow: ru ? 'Routelark: вкладка не загрузилась. Нажмите закладку ещё раз.' : 'Routelark: the new tab did not load. Click the bookmarklet again.' };
{
  // Each click opens a fresh tab with a unique name.
  // The icon is a data: URI; on sites with strict CSP (img-src without data:) the browser will not show it and logs to the console, harmless
  // The tab opens at a real URL (a same-origin blob page made in the browser):
  // Safari opens blank about:blank in the background, a normal URL comes to the front
  const url = page.URL.createObjectURL(new page.Blob(['<!doctype html><meta charset="utf-8"><title>Routelark</title><link rel="icon" href="' + RL_ICON + '"><body></body>'], { type: 'text/html' }));
  const tab = page.open(url, 'routelark' + Date.now());
  if (!tab) { page.URL.revokeObjectURL(url); page.alert(MSG.blocked); }
  else {
    let started = false;
    const t0 = Date.now();
    const start = () => {
      if (started) return;
      // Tab closed or never loaded within 30 s: stop waiting so the site page is not loaded; a hung tab is reported
      if (tab.closed || Date.now() - t0 > 3e4) { started = true; page.clearInterval(wait); page.URL.revokeObjectURL(url); if (!tab.closed) page.alert(MSG.slow); return; }
      let d; try { d = tab.document; } catch (e) { return; }
      if (!d || d.URL !== url || d.readyState !== 'complete' || !d.body) return; // wait until our own page has loaded
      started = true; page.clearInterval(wait); page.URL.revokeObjectURL(url);
      // Styles via CSSStyleSheet: strict site CSP blocks <style>, but not these sheets
      try { const sheet = new tab.CSSStyleSheet(); sheet.replaceSync(RL_CSS); d.adoptedStyleSheets = [sheet]; } catch (e) { const st = d.createElement('style'); st.textContent = RL_CSS; d.head.append(st); }
      const root = d.createElement('div'); root.id = 'app'; d.body.append(root);
      const ch = channel(page, tab);
      tab.__rlPort = ch.port; // the tab UI takes the channel from here (src/app/link.js)
      createCollector(ch.collector).start();
      const mem = memoryStorage();
      RL_RUN(tab, d, tab.location, tab.history, mem, mem, tab.setTimeout.bind(tab), tab.clearTimeout.bind(tab));
    };
    const wait = page.setInterval(start, 30);
  }
}
