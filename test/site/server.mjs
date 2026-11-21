// Test stand: node test/site/server.mjs [port]. Serves dist/ and writes a request log to stdout.
// /csp/... - same files with a strict CSP;  /coop/... - with Cross-Origin-Opener-Policy;
// /limit.js - always 429. The log shows that Routelark requests only service files.
// /__log - the log as the site sees it: every request with method, headers and cookies, auto-refreshing.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

const dist = join(new URL('.', import.meta.url).pathname, '../../dist');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.map': 'application/json', '.txt': 'text/plain' };
const port = +process.argv[2] || 8888;
const log = []; let seq = 0; // in-memory log, last 2000 requests
const pick = (h) => ({ ua: h['user-agent'] || '', origin: h.origin || '', referer: h.referer || '', cookies: (h.cookie || '').split(/;\s*/).map((c) => c.split('=')[0]).filter(Boolean), dest: h['sec-fetch-dest'] || '', mode: h['sec-fetch-mode'] || '', site: h['sec-fetch-site'] || '', ip: '' });

createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/__log') return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(LOG_PAGE);
  if (u.pathname === '/__log.json') {
    if (u.searchParams.has('clear')) log.length = 0;
    const after = +u.searchParams.get('after') || 0;
    return res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify(log.filter((e) => e.n > after)));
  }
  let path = decodeURIComponent(u.pathname);
  const headers = { server: 'test-server/1.0', 'set-cookie': 'demo_session=abc123; Path=/; SameSite=Lax' };
  if (path.startsWith('/csp/')) { headers['content-security-policy'] = "default-src 'self'"; path = path.slice(4); }
  if (path.startsWith('/coop/')) { headers['cross-origin-opener-policy'] = 'same-origin'; path = path.slice(5); }
  const file = join(dist, normalize(path === '/' ? '/index.html' : path));
  headers['content-type'] = TYPES[extname(file)] || 'application/octet-stream';
  let status = 200, body;
  if (path === '/limit.js') { status = 429; body = 'slow down'; }
  else try { body = await readFile(file); } catch (e) { status = 404; body = 'not found'; }
  res.writeHead(status, headers).end(body);
  console.log(req.method, req.url, status);
  log.push(Object.assign({ n: ++seq, t: Date.now(), method: req.method, url: req.url, status }, pick(req.headers), { ip: req.socket.remoteAddress }));
  if (log.length > 2000) log.shift();
}).on('error', (e) => {
  // Port in use: usually Routelark is already running in another terminal
  if (e.code === 'EADDRINUSE') { console.error('Port ' + port + ' is busy. Stop the other server (lsof -i :' + port + ') or pass another port: node test/site/server.mjs 8889'); process.exit(1); }
  throw e;
}).listen(port, '127.0.0.1', () => console.log('Routelark: http://localhost:' + port + '/   Request log: http://localhost:' + port + '/__log'));

// Log page. Data is inserted only via textContent
const LOG_PAGE = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Request log</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#6b6b6b;--line:#e5e5e5;--bad:#c0392b;--ok:#1e7e5a;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#161618;--fg:#ececec;--mut:#949499;--line:#2c2c30;--bad:#ff6b5b;--ok:#4cc38a}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/20px system-ui,sans-serif}
header{position:sticky;top:0;display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;padding:12px 16px;background:var(--bg);border-bottom:1px solid var(--line)}
h1{font-size:16px;margin:0}.mut{color:var(--mut)}button{font:inherit;padding:4px 12px;border:1px solid var(--line);border-radius:8px;background:none;color:inherit;cursor:pointer}
table{width:100%;border-collapse:collapse;font:12px/18px ui-monospace,monospace}th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{position:sticky;top:53px;background:var(--bg);font-weight:500;color:var(--mut)}td.u{word-break:break-all}.bad{color:var(--bad);font-weight:600}.ok{color:var(--ok)}
tr.mark td{border-top:2px solid var(--fg)}
</style>
<header><h1>Request log</h1><span class="mut" id="sum"></span><button id="mark">Mark: before click</button><button id="clear">Clear</button>
<span class="mut">Click "Mark" right before you press the bookmarklet: everything after the line is the scan.</span></header>
<table><thead><tr><th>#</th><th>Time</th><th>Method</th><th>Status</th><th>URL</th><th>Type</th><th>Origin / Referer</th><th>Cookies sent</th><th>IP</th><th>User-Agent</th></tr></thead><tbody id="rows"></tbody></table>
<script>
let after = 0, total = 0, nonGet = 0, markAt = 0;
const rows = document.getElementById('rows'), sum = document.getElementById('sum');
const td = (text, cls) => { const e = document.createElement('td'); e.textContent = text; if (cls) e.className = cls; return e; };
// Type by Sec-Fetch-Dest: empty = request from code (fetch/XHR, how Routelark fetches), script/style/document = ordinary browser load
const kind = (e) => e.dest === 'empty' ? 'fetch from code (' + e.mode + ')' : (e.dest || '?') + ' load';
function add(e) {
  const tr = document.createElement('tr'); if (markAt && e.n === markAt) tr.className = 'mark';
  tr.append(td(e.n), td(new Date(e.t).toLocaleTimeString()), td(e.method, e.method === 'GET' ? 'ok' : 'bad'), td(e.status), td(e.url, 'u'), td(kind(e)), td([e.origin, e.referer].filter(Boolean).join(' / ') || '—', 'u'), td(e.cookies.join(', ') || '—'), td(e.ip), td(e.ua, 'u'));
  rows.prepend(tr); total++; if (e.method !== 'GET') nonGet++;
}
async function poll() {
  try { const list = await (await fetch('/__log.json?after=' + after, { cache: 'no-store' })).json(); list.forEach((e) => { if (markAt === -1) markAt = e.n; add(e); after = e.n; }); } catch (e) { /* server is restarting */ }
  sum.textContent = total + ' requests, ' + nonGet + ' not GET';
}
document.getElementById('mark').onclick = () => { markAt = -1; };
document.getElementById('clear').onclick = async () => { await fetch('/__log.json?clear=1'); rows.textContent = ''; total = nonGet = 0; markAt = 0; };
setInterval(poll, 1000); poll();
</script>`;
