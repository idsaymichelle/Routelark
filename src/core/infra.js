// D10: подсказки об инфраструктуре — сторонние хосты из CSP и preconnect, платформа хостинга, тестовые окружения, номера сборок.
// Отпечатки Netlify, Cloudflare, CloudFront и S3 не подтверждены и не добавлены.
import { siteOf } from './scope.js';
const CSP_DIR = /^(?:default-src|script-src|style-src|img-src|connect-src|frame-src|font-src|media-src|worker-src|form-action)$/;

export function infraFromHeaders(headers, html, pageHost) {
  const out = [], site = siteOf(pageHost || ''), hosts = new Map();
  const note = (host, dir) => { host = host.replace(/^\*\./, '').toLowerCase(); if (!host || siteOf(host) === site) return; if (!hosts.has(host)) hosts.set(host, new Set()); hosts.get(host).add(dir); };
  for (const part of String((headers || {})['content-security-policy'] || '').split(';')) {
    const [dir, ...vals] = part.trim().split(/\s+/);
    if (!CSP_DIR.test(dir || '')) continue;
    for (const v of vals) { const m = /^(?:https?:)?\/\/([^/:'"]+)|^(\*\.[\w.-]+)$|^([a-z0-9-]+(?:\.[a-z0-9-]+)+)$/i.exec(v); if (m) note(m[1] || m[2] || m[3], dir); }
  }
  for (const m of String(html || '').matchAll(/<link\b[^>]*rel=["'][^"']*(?:preconnect|dns-prefetch)[^"']*["'][^>]*href=["']([^"']+)["']|<link\b[^>]*href=["']([^"']+)["'][^>]*rel=["'][^"']*(?:preconnect|dns-prefetch)/gi)) { try { note(new URL(m[1] || m[2], 'https://' + pageHost).hostname, 'preconnect'); } catch (e) { /* битый адрес */ } }
  for (const [h, dirs] of Array.from(hosts).slice(0, 100)) { const d = Array.from(dirs); out.push({ title: 'Third-party host: ' + h, risk: d.length === 1 && d[0] === 'connect-src' ? 1 : 0, why: ['Named in ' + d.join(', ') + '. Check whether the host is expected, and whether it is a forgotten staging or internal service'] }); }
  const H = headers || {};
  if (/^vercel$/i.test(H.server || '') || H['x-vercel-id']) out.push({ title: 'Hosting: Vercel', risk: 0, why: ['Platform fingerprint from response headers. Check the platform\'s own access rules and subdomain takeover patterns'] });
  return out;
}
export function infraFromText(text, pageHost) {
  const out = [], seen = new Set(), site = siteOf(pageHost || ''); let m;
  const add = (title, risk, why, at) => { if (seen.has(title) || seen.size >= 50) return; seen.add(title); out.push({ title, risk, why: [why], at }); };
  const HOST = /(?:^|[^\w-])((?:[a-z0-9-]+\.){0,5}(?:[a-z0-9]+-){0,3}(?:dev|devel|development|staging|stage|stg|uat|qa|test|preprod|sandbox|demo|beta|internal)(?:-[a-z0-9]+){0,3}\.[a-z0-9-]+(?:\.[a-z0-9-]+){1,6})\b/gi; // целые метки: developer.* и testnet.* не тест-стенд; без lookbehind
  while ((m = HOST.exec(text))) { const h = m[1]; if (/\.(?:js|jsx|ts|tsx|mjs|cjs|vue|css|map|png|svg|json|html?)$/i.test(h)) continue; add('Test-environment host: ' + h, siteOf(h.toLowerCase()) === site ? 1 : 0, 'A test environment is often less protected than production: check whether it is reachable and in scope', m.index + m[0].indexOf(h)); }
  const ENV = /["'`]?(?:NODE_ENV|APP_ENV|ENVIRONMENT|STAGE|REACT_APP_ENV|NEXT_PUBLIC_ENV|VITE_[A-Z_]*ENV)["'`]?\s*[:=]\s*["'`](dev|development|staging|stage|uat|qa|test|preprod|sandbox|demo|beta)["'`]/g;
  while ((m = ENV.exec(text))) add('Environment name: ' + m[1], 1, 'This build is not production: check debug features and test accounts', m.index);
  const next = /_next\//.test(text);
  const BID = /["'`]?(build_id|BUILD_ID|__BUILD_ID__|BUILD_NUMBER|buildNumber|releaseVersion|GIT_COMMIT|GIT_SHA|COMMIT_SHA|commitHash|commit_sha|buildId)["'`]?\s*[:=]\s*["'`]([\w.-]{4,64})["'`]/g;
  while ((m = BID.exec(text))) {
    if (m[1] === 'buildId' && next) continue;
    if (/commit|sha/i.test(m[1]) && !/^[0-9a-f]{7,40}$/i.test(m[2])) continue;
    add('Build or commit id: ' + m[2], 0, 'Lets you match this build with a repository, release or older copies in archives', m.index);
  }
  if ((m = /Sentry\.init[\s\S]{0,300}?release\s*:\s*["']([\w.@+-]{3,80})["']/.exec(text))) add('Build or commit id: ' + m[1], 0, 'Lets you match this build with a repository, release or older copies in archives', m.index);
  return out;
}
