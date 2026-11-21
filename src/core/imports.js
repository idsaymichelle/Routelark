// Traffic import from other tools: Burp (XML "Save items"), ZAP and Caido (JSON), HAR, plain URL list.
// -> { source, requests: [{ url, method }] } or null if the format is not recognised.
const URL_RE = /^(?:https?|wss?):\/\/\S+$/i;
const pick = (o, keys) => { for (const k of keys) { const v = k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o); if (typeof v === 'string' && v) return v; } return ''; };

// base64 -> UTF-8 text; non-text or corrupt data -> ''
const b64 = (t) => { try { const bin = atob(String(t).replace(/\s+/g, '')); return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))).slice(0, 2e6); } catch (e) { return ''; } };

const unent = (x) => x.replace(/&(?:#(\d+)|#x([\da-f]+)|(amp|lt|gt|quot|apos));/gi, (m, d, x16, n) => { if (n) return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[n.toLowerCase()]; try { return String.fromCodePoint(d ? +d : parseInt(x16, 16)); } catch (e) { return m; } }); // XML entities outside CDATA
export function parseTrafficExport(text) {
  const s = String(text || '').trim();
  if (!s) return null;
  // Burp: <items burpVersion=...><item><url><![CDATA[...]]></url><method>...
  if (/^</.test(s) && /<items\b[^>]*burpVersion/.test(s.slice(0, 20000))) { // Burp may put a long DTD before the list
    const requests = [], bodies = [];
    // split instead of a lazy <item>...</item>: without a closing tag the regex goes quadratic
    // CDATA content is hidden before splitting: a response body containing "<item>" must not yield an extra request
    const cd = []; const masked = s.split('<![CDATA[').map((x, i) => { if (!i) return x; const e = x.indexOf(']]>'); if (e < 0) return x; cd.push(x.slice(0, e)); return '<![CDATA[\u0000' + (cd.length - 1) + '\u0000' + x.slice(e); }).join('');
    const unmask = (x) => x.replace(/\u0000(\d+)\u0000/g, (m, n) => cd[+n]);
    for (const piece of masked.split('<item>').slice(1)) {
      const it = unmask(piece.split('</item>')[0]);
      const url = /<url>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/url>/.exec(it), method = /<method>(?:<!\[CDATA\[)?([A-Z]+)/.exec(it);
      const uv = url && (/<url>\s*<!\[CDATA\[/.test(it) ? url[1] : unent(url[1])).trim();
      if (url && URL_RE.test(uv)) requests.push({ url: uv, method: method ? method[1] : '?' });
      for (const b of it.matchAll(/<(request|response) base64="true">(?:<!\[CDATA\[)?([A-Za-z0-9+/=\s]+)/g)) bodies.push(b64(b[2]));
    }
    return requests.length ? Object.assign({ source: 'Burp', requests }, bodies.some(Boolean) ? { bodies: bodies.filter(Boolean) } : {}) : null;
  }
  if (/^[[{]/.test(s)) {
    let j; try { j = JSON.parse(s); } catch (e) { return null; }
    if (j && j.log && Array.isArray(j.log.entries)) {
      const ents = j.log.entries.filter((e) => e && e.request && URL_RE.test(String(e.request.url))); // absolute http(s)/ws(s) only
      // Base64 bodies (binary or compressed responses) would otherwise be invisible to analysis as text
      const bodies = ents.map((e) => { const c = e.response && e.response.content; return c && c.encoding === 'base64' && typeof c.text === 'string' ? b64(c.text) : ''; }).filter(Boolean);
      return { source: 'HAR', requests: ents.map((e) => ({ url: e.request.url, method: e.request.method || '?' })), bodies };
    }
    // ZAP API (messages, alerts), Caido (HTTPQL export) and similar: an array of objects with a URL
    // ZAP (JSON report): site[].alerts[].instances[] with uri and method
    const zapSites = j && j.site && [].concat(j.site).filter((x) => x && typeof x === 'object').flatMap((x) => [].concat(x.alerts || []).filter(Boolean).flatMap((a) => [].concat(a.instances || [])));
    const list = Array.isArray(j) ? j : j && (zapSites && zapSites.length ? zapSites : j.messages || j.alerts || j.requests || j.items || j.data);
    if (!Array.isArray(list)) return null;
    const requests = [];
    for (const o of list) {
      if (!o || typeof o !== 'object') continue;
      let url = pick(o, ['url', 'uri', 'request.url', 'requestUrl']);
      const reqHeader = pick(o, ['requestHeader', 'request.raw']);
      if (!url && reqHeader) { const m = /^([A-Z]+) (\S+)/.exec(reqHeader); if (m && URL_RE.test(m[2])) url = m[2]; }
      if (!url && o.host && (o.path || o.request && o.request.path)) {
        const tls = !!(o.is_tls || o.isTls || o.port === 443), port = o.port && o.port !== (tls ? 443 : 80) ? ':' + o.port : '';
        url = (tls ? 'https://' : 'http://') + o.host + port + (o.path || o.request.path) + (o.query ? '?' + o.query : '');
      }
      if (!URL_RE.test(url)) continue;
      const method = pick(o, ['method', 'request.method']) || ((/^([A-Z]{3,7}) \S/.exec(reqHeader) || [])[1]);
      // A plain list of objects with url, no method and no request, is not traffic (e.g. an image list)
      if (!method && !reqHeader) continue;
      requests.push({ url, method: (method || '?').toUpperCase() });
    }
    return requests.length ? { source: 'JSON', requests } : null;
  }
  // URL list: every non-empty line is a URL
  const lines = s.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length && lines.every((l) => URL_RE.test(l))) return { source: 'URL list', requests: lines.map((url) => ({ url, method: '?' })) };
  return null;
}
