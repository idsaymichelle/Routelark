// Цепочка поставок (H6, A7, F6): известные вредоносные версии, скомпрометированные хосты скриптов, мёртвые CDN и похожие на CDN домены.
// Данные сверены с OSV MAL-, отчётами поставщиков и CSA. Находки — «проверьте», не «взломан»: версия на странице ещё не значит, что её установили.
// Только чтение адресов и версий, которые страница уже показала. Без запросов.

// name|версии через запятую|id OSV или -|дата|кампания. TanStack — 12 проверенных пар из 84 (полный список в GHSA-g7cv-rxg3-hmpx не прочитан)
const BAD = `axios|1.14.1,0.30.4|MAL-2026-2307|2026-03-31|plain-crypto-js dependency
plain-crypto-js|4.2.1,4.2.0,0.0.1-security|MAL-2026-2306|2026-03-31|postinstall RAT
@tanstack/react-router|1.169.5,1.169.8|GHSA-g7cv-rxg3-hmpx|2026-05-11|Mini Shai-Hulud
@tanstack/vue-router|1.169.5,1.169.8|GHSA-g7cv-rxg3-hmpx|2026-05-11|Mini Shai-Hulud
@tanstack/solid-router|1.169.5,1.169.8|GHSA-g7cv-rxg3-hmpx|2026-05-11|Mini Shai-Hulud
@tanstack/router-core|1.169.5,1.169.8|GHSA-g7cv-rxg3-hmpx|2026-05-11|Mini Shai-Hulud
@tanstack/react-start|1.167.68,1.167.71|GHSA-g7cv-rxg3-hmpx|2026-05-11|Mini Shai-Hulud
@tanstack/router-plugin|1.167.38,1.167.41|GHSA-g7cv-rxg3-hmpx|2026-05-11|Mini Shai-Hulud
keyv|6.0.0|MAL-2026-11524|2026-08-04|ChainDrop
cacheable|2.5.1|-|2026-08-04|ChainDrop
flat-cache|6.1.24|-|2026-08-04|ChainDrop
file-entry-cache|11.1.6|-|2026-08-04|ChainDrop
cacheable-request|13.0.20|-|2026-08-04|ChainDrop
@cacheable/memory|2.2.1|-|2026-08-04|ChainDrop
cache-manager|7.2.10|MAL-2026-11523|2026-08-04|ChainDrop
@cacheable/node-cache|3.1.2|-|2026-08-04|ChainDrop
@cacheable/utils|2.5.1|-|2026-08-04|ChainDrop
@cacheable/net|2.1.1|-|2026-08-04|ChainDrop
ecto|5.0.1|-|2026-08-04|ChainDrop
chalk|5.6.1|MAL-2025-46969|2025-09-08|wallet clipper
debug|4.4.2|GHSA-4x49-vf9v-38px|2025-09-08|wallet clipper
ansi-styles|6.2.2|-|2025-09-08|wallet clipper
strip-ansi|7.1.1|-|2025-09-08|wallet clipper
supports-color|10.2.1|-|2025-09-08|wallet clipper
wrap-ansi|9.0.1|-|2025-09-08|wallet clipper
color-convert|3.1.1|-|2025-09-08|wallet clipper
color-name|2.0.1|-|2025-09-08|wallet clipper
color-string|2.1.1|-|2025-09-08|wallet clipper
ansi-regex|6.2.1|-|2025-09-08|wallet clipper
error-ex|1.3.3|-|2025-09-08|wallet clipper
has-ansi|6.0.1|-|2025-09-08|wallet clipper
is-arrayish|0.3.3|-|2025-09-08|wallet clipper
simple-swizzle|0.2.3|-|2025-09-08|wallet clipper
slice-ansi|7.1.1|-|2025-09-08|wallet clipper
backslash|0.2.1|GHSA-53mq-f4w3-f7qv|2025-09-08|wallet clipper
chalk-template|1.1.1|-|2025-09-08|wallet clipper
supports-hyperlinks|4.1.1|-|2025-09-08|wallet clipper
@duckdb/duckdb-wasm|1.29.2|GHSA-w62p-hx95-gf2c|2025-09-08|wallet clipper
proto-tinker-wc|0.1.87|-|2025-09-08|wallet clipper
node-ipc|9.1.6,9.2.3,12.0.1|MAL-2026-3744|2026|malicious release
@ctrl/tinycolor|4.1.1,4.1.2|MAL-2025-47141|2025-09|Shai-Hulud
@tanstack/history|1.161.9|MAL-2026-3463|2026-05-11|Mini Shai-Hulud
@tanstack/eslint-plugin-router|1.161.9|MAL-2026-3461|2026-05-11|Mini Shai-Hulud
@tanstack/nitro-v2-vite-plugin|1.154.12|MAL-2026-3464|2026-05-11|Mini Shai-Hulud
@tanstack/arktype-adapter|1.166.12|MAL-2026-3460|2026-05-11|Mini Shai-Hulud`;
const TABLE = new Map();
for (const line of BAD.split('\n')) { const [name, vs, id, date, tag] = line.split('|'); TABLE.set(name, { versions: vs.split(','), id, date, tag }); }
// Пакеты, само присутствие которых — повод проверить
const NAME_ONLY = { 'plain-crypto-js': 'MAL-2026-2306', '@tanstack/setup': 'Shai-Hulud 2.0' };

export function badMatch(name, version) {
  const r = TABLE.get(name), v = String(version || '').replace(/^v/, '');
  if (r && v && r.versions.includes(v)) return { risk: 3, title: 'Known-bad release: ' + name + '@' + v, why: [(r.id !== '-' ? r.id + ', ' : '') + r.tag + ', ' + r.date + '. This version was published by an attacker. Check the lockfile and install history; if it was installed, rotate credentials and rebuild', 'The version is visible on the page; that alone does not prove it is installed'] };
  if (NAME_ONLY[name]) return { risk: 2, title: 'Dependency present: ' + name, why: [NAME_ONLY[name] + ': check the lockfile and install history'] };
  return null;
}
// Версия из пути pnpm: node_modules/.pnpm/@scope+name@1.2.3_peer@4/node_modules/...
export function pnpmPackage(path) {
  const m = /node_modules\/\.pnpm\/((?:@[^+/]+\+)?[^@/]+)@(\d[^_/(]*)/.exec(path);
  return m ? { name: m[1].replace('+', '/'), version: m[2] } : null;
}

// Скрипты с хостов, где поставщик сообщил о подмене. Совпадение хоста и пути — подсказка, не вердикт
const HOSTS = [
  [/^a\.(?:omappapi|opmnstr|optnmstr|trstplse)\.com$/, /\/app\/js\/api\.min\.js/, 'OptinMonster/TrustPulse CDN tampering, 2026-06-12'],
  [/^tidio\.cc$/, null, 'lookalike host named in the OptinMonster incident, 2026-06-12'],
  [/(?:^|\.)(?:brevo\.com|sibforms\.com)$/, /(?:sdk-loader|brevo-conversations)\.js/, 'Brevo CDN tampering, 2026-09-14 16:05–20:30 UTC'],
  [/^cdn\.debugbear\.com$/, null, 'DebugBear DNS hijack, 2026-10-29']
];
// Мёртвые и захваченные CDN: polyfill.io с 2024 года отдаёт вредоносный код, остальные — тот же оператор
const DEAD = { 'polyfill.io': 4, 'bootcdn.net': 3, 'bootcss.com': 3, 'staticfile.net': 3, 'staticfile.org': 3 };
const KNOWN = ['jsdelivr.net', 'unpkg.com', 'cloudflare.com', 'googleapis.com', 'gstatic.com', 'jquery.com', 'bootstrapcdn.com', 'jsdelivr.com', 'skypack.dev', 'esm.sh', 'jspm.io', 'aspnetcdn.com', 'cdnjs.com'];
const reg = (host) => host.split('.').slice(-2).join('.');
const lev = (a, b) => { let p = [...Array(b.length + 1).keys()]; for (let i = 1; i <= a.length; i++) { const c = [i]; for (let j = 1; j <= b.length; j++) c[j] = Math.min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (a[i - 1] !== b[j - 1])); p = c; } return p[b.length]; };

// resources: [{ url, script: bool, sri: bool }]
export function hostFindings(resources, pageHost) {
  const out = [], seen = new Set();
  for (const r of resources) {
    let u; try { u = new URL(r.url); } catch (e) { continue; }
    const host = u.hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, ''), rd = reg(host);
    if (host === pageHost || seen.has(host + u.pathname)) continue;
    seen.add(host + u.pathname);
    const drop = r.sri ? 1 : 0, sriNote = r.sri ? ['SRI present: the browser rejects a changed file'] : [];
    for (const [hre, pre, what] of HOSTS) if (hre.test(host) && (!pre || pre.test(u.pathname))) out.push({ title: 'Script host was reported compromised: ' + host, risk: 2, why: [what + '. Check whether the page loaded the script during that window and whether the vendor has confirmed a clean version'].concat(sriNote) });
    if (DEAD[rd]) out.push({ title: 'File from a dead or compromised CDN: ' + host, risk: Math.max(1, (r.script ? DEAD[rd] : 2) - drop), why: ['This CDN was taken over or is unmaintained; scripts from it can change at any time. Replace it with the vendor\'s host or a self-hosted copy'].concat(sriNote) });
    else if (rd.length >= 6 && !KNOWN.includes(rd) && rd !== reg(pageHost || '')) {
      const near = KNOWN.find((k) => { const d = lev(rd, k); return d >= 1 && d <= 2; });
      if (near) out.push({ title: 'Host looks like a known CDN: ' + host + ' (close to ' + near + ')', risk: Math.max(0, (r.script ? 2 : 1) - drop), why: ['The name is one or two letters away from a well-known CDN. Check that the host really belongs to the vendor'].concat(sriNote) });
    }
  }
  return out;
}
