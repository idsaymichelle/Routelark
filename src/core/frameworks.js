// Framework endpoints from already loaded text. No new requests except one GET /.vite/manifest.json when Vite is detected (seeds).
// _payload.json and __data.json addresses are only listed, not requested: they are dynamic data, not static files.
const TRPC_DENY = /^(?:router|req|request|url|searchParams|params|location|db|knex|sql|this|window|document|console|Object|Array|Promise|JSON|Math)$/;

// Simple findings { kind, title, risk, why, at } and address hints { hit: raw, method, via, confidence, at }
export function frameworkHints(text) {
  const out = []; let m, n = 0;
  const sa = /createServerReference\)?\(\s*["']([0-9a-f]{32,128})["']/g;
  while ((m = sa.exec(text)) && n++ < 50) out.push({ kind: 'custom', title: 'Server action ' + m[1].slice(0, 12), risk: 1, why: ['Next.js server action: callable by direct POST to the page that uses it. Check that the action re-verifies auth and ownership'], at: m.index });
  if (/__webpack_require__|\bwindow\[/.test(text) && /\binit\b/.test(text)) {
    const ex = /["'](\.\/[\w@./~-]{1,120})["']\s*:\s*\(\)\s*=>/g; n = 0;
    while ((m = ex.exec(text)) && n++ < 100) out.push({ kind: 'custom', title: 'Federated module ' + m[1], risk: 0, why: ['Module Federation exposes this module; it is loaded through the remote container'], at: m.index });
  }
  if (/createTRPCProxyClient|createTRPCClient|@trpc\/client/.test(text)) { // httpLink exists in other libraries too
    const tr = /\b([a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*){1,4})\.(query|mutate|useQuery|useMutation|useInfiniteQuery|useSuspenseQuery)\(/g, seen = new Set(); n = 0;
    while ((m = tr.exec(text)) && seen.size < 50) {
      const parts = m[1].split('.'); if (TRPC_DENY.test(parts[0])) continue;
      const name = parts.slice(1).join('.'); if (!name || seen.has(name)) continue; seen.add(name);
      out.push({ hit: '/api/trpc/' + name, method: /mutat/i.test(m[2]) ? 'POST' : 'GET', via: 'trpc', confidence: 'low', at: m.index });
    }
  }
  return out;
}
// Hints from the page itself: Nuxt payload and SvelteKit data
export function pageDataHints(html, pageUrl) {
  let p; try { p = new URL(pageUrl).pathname; } catch (e) { return []; }
  const out = [];
  if (/window\.__NUXT__|id=["']__NUXT_DATA__["']/.test(html)) out.push({ hit: p.replace(/\/$/, '') + '/_payload.json', method: 'GET', via: 'nuxt', confidence: 'medium', why: 'Nuxt route payload. If the route is cached and user-specific, the payload may leak to other users: check with a second session' });
  if (/\/_app\/immutable\//.test(html)) out.push({ hit: /\.html$/.test(p) ? p.replace(/\.html$/, '.html__data.json') : p.replace(/\/$/, '') + '/__data.json', method: 'GET', via: 'sveltekit', confidence: 'medium', why: 'SvelteKit page data: check whether it contains more than the page shows' });
  return out;
}
// Vite marker: module script <name>-<hash>.js in any folder (build.assetsDir may differ)
export const viteSignature = (html) => /<script\b[^>]*type=["']module["'][^>]*src=["'][^"']*\/[\w-]+-[\w-]{8}\.js["']|src=["'][^"']*\/[\w-]+-[\w-]{8}\.js["'][^>]*type=["']module["']/.test(html);
// Vite manifest: file paths are relative to the build root, not the .vite folder
export function viteManifest(text, url) {
  let j; try { j = JSON.parse(text); } catch (e) { return null; }
  if (!j || typeof j !== 'object' || Array.isArray(j)) return null;
  const base = url.replace(/\.vite\/manifest\.json(?:[?#].*)?$/, ''), files = new Set(), sources = [];
  for (const [k, v] of Object.entries(j)) {
    if (!v || typeof v.file !== 'string') continue;
    if (/\.m?js$/.test(v.file)) files.add(new URL(v.file, base).href);
    if (v.src || k) sources.push(v.src || k);
  }
  return files.size ? { files: Array.from(files).slice(0, 500), sources: sources.slice(0, 500) } : null;
}
