// D7: трекеры, запись сессий на страницах с формами, cookies трекеров и состояние согласия, персональные данные в адресах к третьим сторонам.
// Свой короткий список хостов: готовые списки (Tracker Radar, Disconnect) под лицензией CC BY-NC-SA, их не копируем.
// Снимок делается после загрузки страницы, поэтому «до согласия» доказать нельзя — находки это говорят.
import { siteOf } from './scope.js';
import { luhn, cardBrandOk } from './pii.js';

const CATS = { an: 'Analytics', ad: 'Advertising', tm: 'Tag manager', soc: 'Social pixel', sr: 'Session replay', cmp: 'Consent manager' };
const LIST = {
  an: 'google-analytics.com analytics.google.com mc.yandex.ru mc.yandex.com analytics.tiktok.com analytics.twitter.com',
  tm: 'googletagmanager.com',
  ad: 'doubleclick.net googlesyndication.com googleadservices.com bat.bing.com ads.tiktok.com static.ads-twitter.com px.ads.linkedin.com criteo.com criteo.net adsrvr.org taboola.com outbrain.com sc-static.net ct.pinterest.com',
  soc: 'connect.facebook.net snap.licdn.com',
  sr: 'clarity.ms static.hotjar.com script.hotjar.com vars.hotjar.com in.hotjar.com edge.fullstory.com rs.fullstory.com cdn.logrocket.com r.lr-ingest.io rec.smartlook.com web-sdk.smartlook.com cdn.mouseflow.com cdn.luckyorange.com cdn.inspectlet.com cdn.sessioncam.com cdnssl.clicktale.net userreplay.net',
  cmp: 'cdn.cookielaw.org consent.cookiebot.com consentcdn.cookiebot.com sdk.privacy-center.org'
};
const HOSTS = new Map();
for (const c of Object.keys(LIST)) for (const h of LIST[c].split(' ')) HOSTS.set(h, c);
export function classifyHost(host) {
  for (let h = String(host).toLowerCase(); ;) {
    if (HOSTS.has(h)) return { cat: HOSTS.get(h), name: CATS[HOSTS.get(h)] };
    const i = h.indexOf('.'); if (i < 0) return null; h = h.slice(i + 1);
  }
}

const TRACKER_COOKIE = /^(?:_ga(?:_.*)?|_gid|_gcl_au|_fbp|_fbc|_hjid|_hjSessionUser_.*|_clck|_clsk|_ym_uid|_ym_d|_ym_isad|_ttp|MUID|_uetvid|_uetsid|IDE)$/;
// consent: результаты typeof для глобальных объектов CMP из снимка (функции не вызываются)
export function consentCase(cookies, consent) {
  const trackers = cookies.filter((c) => TRACKER_COOKIE.test(c.name)).map((c) => c.name);
  if (!trackers.length) return null;
  const names = new Set(cookies.map((c) => c.name));
  const val = (n) => { const c = cookies.find((x) => x.name === n); if (!c) return ''; try { return decodeURIComponent(c.value); } catch (e) { return c.value; } };
  const opt = val('OptanonConsent'), cc = val('CookieConsent'), interacted = /interactionCount=[1-9]/.test(opt);
  // Отказ засчитывается по категории своей cookie: аналитика (C0002 / statistics) или реклама (C0004 / marketing)
  const ADS = /^(?:_fbp|_fbc|_gcl_au|IDE|MUID|_uetvid|_uetsid|_ttp)$/;
  const cat = (n) => (ADS.test(n) ? ['C0004', 'marketing'] : ['C0002', 'statistics']);
  const rejected = trackers.some((n) => { const [g, k] = cat(n); return (interacted && new RegExp(g + ':0').test(opt)) || new RegExp(k + ':false').test(cc); });
  const record = interacted || names.has('OptanonAlertBoxClosed') || !!cc || names.has('euconsent-v2');
  const cmp = Object.values(consent || {}).some((v) => v && v !== 'undefined');
  if (rejected) return { title: 'Tracker cookies present after a rejecting consent record: ' + trackers.length, risk: 2, trackers };
  if (!record && cmp) return { title: 'Tracker cookies with no visible consent decision: ' + trackers.length, risk: 2, trackers };
  if (!record) return { title: 'Tracker cookies with no consent tool: ' + trackers.length, risk: 1, trackers };
  return null;
}

const PII_PARAM = { email: 2, mail: 2, e_mail: 2, phone: 2, tel: 2, msisdn: 2, ssn: 3, inn: 3, snils: 3, first_name: 1, last_name: 1, dob: 1, birthday: 1 };
const AFTER = 'The snapshot is taken after the page loaded, so the time a cookie was set is not known';

// urls: адреса ресурсов и трафика; html: разметка; cookies: видимые cookies; referrer: действующая политика
export function trackerFindings({ urls, pageHost, html, cookies, consent, referrer }) {
  const out = [], site = siteOf(pageHost || ''), seen = new Set(), cats = {};
  const leaky = /^(?:unsafe-url|no-referrer-when-downgrade)$/i.test(referrer || '');
  let replay = null, np = 0;
  for (const raw of urls) {
    let u; try { u = new URL(raw); } catch (e) { continue; }
    const host = u.hostname.toLowerCase();
    if (siteOf(host) === site) continue;
    const c = classifyHost(host);
    if (c && !seen.has(host)) {
      seen.add(host); cats[c.name] = (cats[c.name] || 0) + 1;
      if (c.cat === 'sr') replay = replay || host;
      out.push({ kind: 'tracker', title: 'Tracker: ' + host + ' (' + c.name + ')', risk: { ad: 1, cmp: 1, sr: 2 }[c.cat] || 0, why: ['Third-party tracker loads on the page (by domain name): check the contract, consent and what data it receives'].concat(c.cat === 'tm' ? ['Loads other tags at runtime: this list is incomplete'] : []) });
    }
    for (const [k, v] of u.searchParams) {
      if (np >= 20 || !v || seen.has(host + '?' + k)) continue;
      const name = k.toLowerCase();
      let risk = PII_PARAM[name] || 0, why = 'A personal value is sent to a third party in the address';
      if (!risk && /^[^@\s]{1,64}@[^@\s]{1,255}\.[a-z]{2,24}$/i.test(v)) risk = 2;
      else if (!risk && /^\d{13,19}$/.test(v) && cardBrandOk(v) && luhn(v)) risk = 3;
      else if (!risk && /^[0-9a-f]{64}$/i.test(v)) { risk = 1; why = 'Hashed identifier, still linkable across sites'; }
      if (!risk) continue;
      seen.add(host + '?' + k); np++;
      out.push({ kind: 'privacy', title: 'Personal data in a URL to ' + host + ': ' + k, risk: Math.min(3, risk + (leaky ? 1 : 0)), why: [why].concat(leaky ? ['Referrer-Policy ' + referrer + ' also sends full addresses to other sites'] : []), snippet: '' });
    }
  }
  if (seen.size) {
    const n = Object.values(cats).reduce((a, b) => a + b, 0);
    if (n) out.push({ kind: 'privacy', title: 'Third-party trackers: ' + n + ' hosts', risk: n >= 5 || cats.Advertising ? 1 : 0, why: [Object.entries(cats).sort((a, b) => b[1] - a[1]).map(([k, v]) => k + ' ' + v).join(', ')] });
  }
  const pwd = /<input\b[^>]*type\s*=\s*["']?password/i.test(html || ''), form = pwd || /<form\b|<input\b[^>]*type\s*=\s*["']?(?:email|tel|text)/i.test(html || '');
  if (!replay && /webvisor\s*:\s*true/.test(html || '')) replay = 'Yandex Webvisor';
  if (replay && form) out.push({ kind: 'privacy', title: 'Session replay on a page with a form: ' + replay, risk: pwd ? 3 : 2, why: ['A replay script can record what visitors type; check the vendor\'s masking and whether password fields are excluded'] });
  const cc = consentCase(cookies || [], consent);
  if (cc) out.push({ kind: 'privacy', title: cc.title, risk: cc.risk, why: [cc.trackers.slice(0, 10).join(', '), AFTER] });
  return out;
}
