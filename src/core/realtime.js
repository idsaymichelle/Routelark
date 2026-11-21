// E1: каналы реального времени — WebSocket с подпротоколом, Socket.IO, SignalR, ключи Pusher/Ably/PubNub, учётные данные TURN.
// Адреса только записываются, не запрашиваются (к SignalR /negotiate не добавляется). Форматы длины ключей Pusher/PubNub не подтверждены.
const TOKEN_Q = /[?&][\w-]*(?:token|ticket|auth|jwt|key|sig)[\w-]*=/i;
export function realtimeFindings(text) {
  const out = [], seen = new Set(); let m, n = 0;
  const hit = (raw, at, via, authed) => {
    if (seen.has(raw)) return; seen.add(raw);
    out.push({ t: 'hit', raw, at, via });
    if (!authed && !TOKEN_Q.test(raw) && !/\/\/(?:localhost|127\.0\.0\.1)\b/.test(raw) && n++ < 50) out.push({ t: 'simple', title: 'Realtime endpoint without a token in the handshake: ' + raw, risk: 1, why: ['Cookie-authenticated socket: check that the server rejects a foreign Origin on the handshake (CSWSH)'], at });
  };
  const re = (r) => { r.lastIndex = 0; return r; };
  const WSP = re(/new WebSocket\(\s*(["'`])([^"'`\n]{1,400})\1(?:\s*,\s*(\[[^\]]{0,200}\]|["'`][^"'`]{1,80}["'`]))?/g); // подпротоколы необязательны
  while ((m = WSP.exec(text))) hit(m[2], m.index, 'ws', /token|jwt|bearer|auth/i.test(m[3] || ''));
  if (/socket\.io|\bio(?:\.connect)?\(\s*["'`]https?:/.test(text)) {
    const SIO = re(/(?:^|[^\w$.])io(?:\.connect)?\(\s*(?:(["'`])(https?:\/\/[^"'`\n]{1,200})\1)?\s*(,\s*\{[^}]{0,400}\})?/g);
    while ((m = SIO.exec(text))) {
      const opts = m[3] || '', path = (/path\s*:\s*(["'`])([^"'`]{1,120})\1/.exec(opts) || [])[2] || (/\bpath\s*:/.test(opts) ? '' : '/socket.io/'); // path есть, но не литерал: не выдумываем по умолчанию
      if (!m[2] && !opts) continue;
      hit((m[2] || '').replace(/\/$/, '') + path, m.index, 'ws', /auth\s*:\s*\{/.test(opts));
    }
  }
  const SR = re(/\.withUrl\(\s*(["'`])([^"'`\n]{1,400})\1/g);
  while ((m = SR.exec(text))) hit(m[2], m.index, 'ws', /accessTokenFactory/.test(text.slice(m.index, m.index + 300)));
  if ((m = /skipNegotiation\s*:\s*(?:!0|true)/.exec(text))) out.push({ t: 'simple', title: 'SignalR skips negotiation (WebSocket only)', risk: 0, why: ['The client connects straight over WebSocket; check the handshake checks on the hub'], at: m.index });
  // Ключи провайдеров
  const PU = re(/new Pusher\(\s*(["'`])([0-9a-f]{20})\1/g);
  while ((m = PU.exec(text))) {
    out.push({ t: 'simple', title: 'Pusher app key', risk: 0, why: ['Public by design: check the auth endpoint for private and presence channels'], at: m.index });
    const sec = /secret\s*:\s*(["'`])([0-9a-f]{20,})\1/.exec(text.slice(m.index, m.index + 300));
    if (sec) out.push({ t: 'secret', type: 'pusher-secret', label: 'Pusher app secret', raw: sec[2], risk: 4, conf: 'high', why: 'App secret signs channel auth: must never be in the browser', at: m.index });
  }
  const AB = re(/\b[\w-]{4,40}\.[\w-]{4,40}:[\w-]{8,80}\b/g);
  while ((m = AB.exec(text))) if (/key\s*:|Ably\.Realtime\(/.test(text.slice(Math.max(0, m.index - 200), m.index))) out.push({ t: 'secret', type: 'ably-key', label: 'Ably API key', raw: m[0], risk: 4, conf: 'medium', why: 'Ably API key in client code: clients should use token auth', at: m.index });
  const PN = re(/\b(pub|sub)-c-[0-9a-f-]{20,}\b/g);
  while ((m = PN.exec(text))) if (!/example|YOUR_/.test(text.slice(Math.max(0, m.index - 40), m.index + 60))) out.push(m[1] === 'pub' ? { t: 'simple', title: 'PubNub publish key', risk: 1, why: ['Anyone with the key can publish unless Access Manager is on'], at: m.index } : { t: 'simple', title: 'PubNub subscribe key', risk: 0, why: ['Public by design: check Access Manager for private channels'], at: m.index });
  const ICE = re(/iceServers/g);
  while ((m = ICE.exec(text))) {
    const w = text.slice(m.index, m.index + 400), c = /credential\s*:\s*(["'`])([^"'`]{4,200})\1/.exec(w);
    if (!c) continue;
    const temp = /username\s*:\s*(["'`])\d{9,}:/.test(w);
    out.push({ t: 'secret', type: 'turn-credential', label: 'TURN server credential', raw: c[2], risk: temp ? 1 : 3, conf: 'medium', why: temp ? 'Looks time-limited: check the expiry' : 'A static TURN password lets anyone relay traffic through the server', at: m.index + c.index });
  }
  return out;
}
