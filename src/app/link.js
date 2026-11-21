// Связь вкладки со сборщиком на странице сайта. Принимаем сообщения только от окна-открывателя.
const V = 2, TIMEOUT = 30000;

// Закладка кладёт во вкладку __rlPort: прямой канал к сборщику в той же странице, без postMessage браузера
export function connect({ win }) {
  const port = win.__rlPort; delete win.__rlPort; // канал забирается сразу, чтобы не висел на вкладке
  const opener = port ? port.opener : win.opener;
  const listen = port ? port.listen : (fn) => win.addEventListener('message', fn);
  if (!opener) return null;
  let pageOrigin = null, seq = 0, onReady;
  const waits = new Map(), traffic = [], cookieFns = [], errorFns = [];
  const ready = new Promise((r) => { onReady = r; });
  const post = (m) => { if (pageOrigin && !opener.closed) opener.postMessage(Object.assign({ rl: V }, m), pageOrigin); };
  function ask(m) {
    const id = ++seq;
    return new Promise((resolve) => {
      const t = setTimeout(() => { waits.delete(id); resolve({ ok: false, error: opener.closed ? 'page closed' : 'no response from page' }); }, TIMEOUT);
      waits.set(id, (r) => { clearTimeout(t); resolve(r); });
      post(Object.assign({ id }, m));
    });
  }
  listen((e) => {
    const d = e.data;
    if (e.source !== opener || !d || d.rl !== V) return;
    if (d.type === 'error') { errorFns.forEach((fn) => fn(d.error)); return; } // сборщик не смог прочитать страницу
    if (d.type === 'snapshot') {
      // Первый снимок фиксирует origin страницы; дальше принимаем только с него
      let origin; try { origin = new URL(d.page.url).origin; } catch (x) { return; }
      if (pageOrigin && origin !== pageOrigin) return;
      if (e.origin !== origin) return;
      pageOrigin = origin; onReady(d.page); return;
    }
    if (!pageOrigin || e.origin !== pageOrigin) return;
    if ((d.type === 'fetched' || d.type === 'cookie-result') && waits.has(d.id)) { waits.get(d.id)(d); waits.delete(d.id); }
    else if (d.type === 'traffic') traffic.forEach((fn) => fn(d.entries || []));
    else if (d.type === 'cookies') cookieFns.forEach((fn) => fn(d.cookies || []));
  });
  // В hello нет данных, origin страницы ещё неизвестен — поэтому '*'
  opener.postMessage({ rl: V, type: 'hello', version: V }, '*');
  if (win.addEventListener) win.addEventListener('pagehide', () => post({ type: 'bye' }));
  return {
    ready,
    onError: (fn) => errorFns.push(fn),
    get pageOrigin() { return pageOrigin; },
    get closed() { return opener.closed; },
    fetchText: (url, o) => ask({ type: 'fetch', url, force: !!(o && o.force), doc: !!(o && o.doc) }),
    setCookie: (cookie) => ask({ type: 'cookie-set', cookie }),
    deleteCookie: (cookie) => ask({ type: 'cookie-delete', cookie }),
    readCookies: () => ask({ type: 'cookie-read' }).then((r) => r.cookies),
    sendSettings: (s) => post(Object.assign({ type: 'settings' }, s)),
    stop: () => post({ type: 'stop' }),
    onTraffic: (fn) => traffic.push(fn),
    onCookies: (fn) => cookieFns.push(fn)
  };
}
