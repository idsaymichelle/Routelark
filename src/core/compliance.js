// D1: соответствие ASVS 5.0 (глава V3, веб-фронтенд) и WSTG v4.2 (CLNT, INFO) по тому, что видно из браузера.
// Статусы: pass — видно целиком и нарушений нет; fail — найден признак (подсказка для ручной проверки); check — видно частично; na — браузер этого не видит.
// Названия требований — короткие пересказы, не цитаты.
const SENS = /sess|sid|token|auth|jwt|csrf|login|remember/i;
export function complianceRows(store, app) {
  const H = store.docHeaders, items = store.items, has = (pred) => items.some(pred);
  const hdr = !!H, js = store.files.length > 0, html = store.texts && store.texts.has(String(store.pageUrl).split('#')[0]);
  const cookies = (app && app.cookies) || [], attrs = cookies.some((c) => c.attrsKnown);
  const csp = (H && H['content-security-policy']) || '', sts = (H && H['strict-transport-security']) || '';
  const dir = (n) => (new RegExp('(?:^|;)\\s*' + n + '\\s+([^;]*)', 'i').exec(csp) || [])[1];
  const R = [], add = (group, id, name, status, reason) => R.push({ group, id, name, status, reason: reason || '' });
  const need = (ok, reason, fn) => (ok ? fn() : ['na', reason]);
  const row = (group, id, name, res) => add(group, id, name, res[0], res[1]);
  const sink = has((f) => f.type === 'sink' || f.type === 'trust'), pmBad = has((f) => f.type === 'postmessage' && f.risk > 0), pmOk = has((f) => f.type === 'postmessage' && f.risk === 0);
  const sri = has((f) => f.kind === 'dom' && /without SRI/.test(f.url)), wsF = has((f) => f.kind === 'ws' || f.kind === 'realtime');
  row('asvs', '3.1.1', 'Browser security features documented', ['na', 'needs the app documentation']);
  row('asvs', '3.2.2', 'Content rendered safely (no unsafe DOM sinks)', need(js, 'input not read', () => [sink ? 'check' : 'pass']));
  row('asvs', '3.3.1', 'Cookies have the Secure attribute', need(attrs, 'cookie attributes not visible', () => [cookies.some((c) => c.attrsKnown && !c.secure) ? 'fail' : 'pass']));
  row('asvs', '3.3.2', 'SameSite value chosen for the cookie purpose', need(attrs, 'cookie attributes not visible', () => [cookies.some((c) => c.attrsKnown && SENS.test(c.name) && !/^(?:lax|strict)$/i.test(c.sameSite || '')) ? 'check' : 'pass', 'heuristic: Lax or Strict for session cookies']));
  row('asvs', '3.3.3', 'Session cookies use the __Host- prefix', need(attrs, 'cookie attributes not visible', () => [cookies.some((c) => SENS.test(c.name) && !/^__Host-/.test(c.name)) ? 'check' : 'pass']));
  row('asvs', '3.3.4', 'Session cookies are HttpOnly', need(cookies.length, 'cookies not read', () => cookies.some((c) => SENS.test(c.name)) ? ['fail', 'HttpOnly not visible to scripts'] : ['na', 'no session cookie seen']));
  row('asvs', '3.3.5', 'Cookie name and value under 4096 bytes', need(cookies.length, 'cookies not read', () => [cookies.some((c) => new TextEncoder().encode(c.name + c.value).length > 4096) ? 'fail' : 'pass']));
  row('asvs', '3.4.1', 'Strict-Transport-Security with max-age of a year or more', need(hdr, 'headers not read', () => { if (!/^https:/.test(store.pageUrl)) return ['check', 'the requirement is for HTTPS responses']; const a = +((/max-age=(\d+)/i.exec(sts) || [])[1] || 0); return !sts ? ['fail'] : a < 31536000 ? ['fail'] : /includeSubDomains/i.test(sts) ? ['pass'] : ['check', 'no includeSubDomains']; }));
  row('asvs', '3.4.2', 'CORS Access-Control-Allow-Origin is a fixed value', need(hdr, 'headers not read', () => { const o = H['access-control-allow-origin']; return !o ? ['pass'] : o === '*' && /true/i.test(H['access-control-allow-credentials'] || '') ? ['fail'] : ['check', 'Origin reflection needs a request with a different Origin']; }));
  row('asvs', '3.4.3', 'Content-Security-Policy restricts scripts, objects and base', need(hdr, 'headers not read', () => { if (!csp) return ['fail']; const s = dir('script-src') || dir('default-src') || '', obj = dir('object-src') || dir('default-src') || ''; if (/'unsafe-inline'/.test(s) && !/'nonce-|'sha\d+-/.test(s)) return ['fail']; if (/(?:^|\s)(?:\*|https?:)(?:\s|$)/.test(s)) return ['fail']; return /'none'/.test(obj) && /'none'/.test(dir('base-uri') || '') ? ['pass'] : ['check']; }));
  row('asvs', '3.4.4', 'X-Content-Type-Options: nosniff', need(hdr, 'headers not read', () => [/^\s*nosniff\s*$/i.test(H['x-content-type-options'] || '') ? 'check' : 'fail', 'only the document response was read']));
  row('asvs', '3.4.5', 'Referrer-Policy limits what is sent', need(hdr, 'headers not read', () => { const r = (H['referrer-policy'] || '').trim(); return !r && !/<meta\b[^>]*name=["']referrer/i.test(html ? store.texts.get(String(store.pageUrl).split('#')[0]).text : '') ? ['fail'] : /unsafe-url|no-referrer-when-downgrade/i.test(r) ? ['fail'] : ['pass']; }));
  row('asvs', '3.4.6', 'Framing restricted with frame-ancestors', need(hdr, 'headers not read', () => [/frame-ancestors/.test(csp) ? 'pass' : H['x-frame-options'] ? 'check' : 'fail']));
  row('asvs', '3.4.7', 'CSP reports violations', need(hdr && csp, hdr ? 'no CSP to check' : 'headers not read', () => [/report-uri|report-to/.test(csp) ? 'pass' : 'fail']));
  row('asvs', '3.4.8', 'Cross-Origin-Opener-Policy set', need(hdr, 'headers not read', () => { const c = H['cross-origin-opener-policy'] || ''; return [/^same-origin/.test(c) ? 'pass' : c ? 'check' : 'fail']; }));
  row('asvs', '3.5.1', 'Protection against cross-site requests', need(html, 'needs POST requests', () => ['check', 'needs POST requests']));
  row('asvs', '3.5.5', 'postMessage origin is checked', need(js, 'JS not read', () => (pmBad ? ['fail'] : pmOk ? ['pass'] : ['na', 'no postMessage listener in scanned JS'])));
  row('asvs', '3.6.1', 'External scripts and styles use integrity (SRI)', need(html, 'HTML not read', () => [sri ? 'fail' : 'pass']));
  row('asvs', '3.7.4', 'Domain on the HSTS preload list', need(hdr, 'headers not read', () => (!sts ? ['fail'] : ['check', 'list check needs an external request'])));
  const W = (id, name, res) => row('wstg', id, name, res);
  W('CLNT-01', 'DOM-based XSS', [sink ? 'fail' : 'na', sink ? '' : 'active test, not run by Routelark']);
  W('CLNT-02', 'JavaScript execution', [has((f) => f.kind === 'dom' && /javascript:|Inline event/.test(f.url)) ? 'fail' : 'na', 'active test, not run by Routelark']);
  W('CLNT-04', 'Client-side URL redirect', [has((f) => f.type === 'redirect') ? 'fail' : 'na', 'active test, not run by Routelark']);
  W('CLNT-06', 'Client-side resource manipulation', need(html, 'HTML not read', () => [sri ? 'fail' : 'pass']));
  W('CLNT-07', 'Cross-origin resource sharing', need(hdr, 'headers not read', () => { const o = H['access-control-allow-origin']; return !o ? ['pass'] : o === '*' && /true/i.test(H['access-control-allow-credentials'] || '') ? ['fail'] : ['check']; }));
  W('CLNT-09', 'Clickjacking', need(hdr, 'headers not read', () => [/frame-ancestors/.test(csp) ? 'pass' : H['x-frame-options'] ? 'check' : 'fail']));
  W('CLNT-10', 'WebSockets', [wsF ? 'fail' : 'na', 'active test, not run by Routelark']);
  W('CLNT-11', 'Web messaging', need(js, 'JS not read', () => (pmBad ? ['fail'] : pmOk ? ['pass'] : ['na', 'no postMessage listener in scanned JS'])));
  W('CLNT-12', 'Browser storage', need(app && app.page, 'input not read', () => [has((f) => f.kind === 'storage' && f.risk > 0) ? 'fail' : 'pass']));
  W('CLNT-13', 'Cross-site script inclusion', [has((f) => f.type === 'jsonp') ? 'fail' : 'na', 'active test, not run by Routelark']);
  W('INFO-02', 'Fingerprint the web server', need(hdr, 'headers not read', () => [H.server || H['x-powered-by'] ? 'fail' : 'pass']));
  W('INFO-05', 'Review page content for leaks', need(html, 'HTML not read', () => [has((f) => (f.kind === 'dom' && /comment|Error/.test(f.url)) || f.type === 'internal' || f.type === 'todo') ? 'fail' : 'pass']));
  W('INFO-06', 'Identify application entry points', [has((f) => ['api', 'page', 'auth', 'debug'].includes(f.kind)) ? (js ? 'pass' : 'check') : 'na', 'input not read']);
  W('INFO-07', 'Map execution paths', [has((f) => f.type === 'route' || f.type === 'ghost-route') ? 'check' : 'na', 'input not read']);
  W('INFO-08', 'Fingerprint the framework', [has((f) => f.kind === 'tech') ? 'check' : js ? 'pass' : 'na', 'input not read']);
  return R.map((r) => (r.status === 'na' && !r.reason ? Object.assign(r, { reason: 'input not read' }) : r));
}
