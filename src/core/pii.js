import { lineIndex } from '../core.js';
// D6: персональные данные с контрольными суммами (Luhn, IBAN mod 97, ИНН, СНИЛС, ОГРН). Чистый модуль, без DOM.
// Значение без ключевого слова рядом или без формата не считается: контрольная сумма сама по себе проходит у каждой десятой строки
const LAT = 'A-Za-z', CYR = 'А-Яа-яЁё';
export const KW = {
  card: new RegExp(`(?:^|[^${LAT}])(?:card|Card|cc|pan|Pan|credit|Credit|payment|Payment|cardnum|card_number)(?![a-z])|(?:^|[^${CYR}])(?:карт|Карт|платеж|Платеж)`),
  iban: new RegExp(`(?:^|[^${LAT}])(?:iban|Iban|IBAN)(?![a-z])`),
  inn: new RegExp(`(?:^|[^${LAT}])(?:inn|Inn)(?![A-Za-z])|(?:^|[^${LAT}])(?:taxId|tax_id|taxpayer)(?![a-z])|(?:^|[^${LAT}])INN(?![${LAT}])|(?:^|[^${CYR}])(?:ИНН|инн|налогоплательщ)`),
  snils: new RegExp(`(?:^|[^${LAT}])(?:snils|Snils|SNILS)(?![${LAT}])|(?:^|[^${CYR}])(?:СНИЛС|снилс)`),
  ogrn: new RegExp(`(?:^|[^${LAT}])(?:ogrn|Ogrn|OGRN)(?![${LAT}])|(?:^|[^${CYR}])(?:ОГРН|огрн)(?![${CYR}])`),
  ogrnip: new RegExp(`(?:^|[^${LAT}])(?:ogrnip|Ogrnip|OGRNIP)(?![${LAT}])|(?:^|[^${CYR}])(?:ОГРНИП|огрнип|индивидуальн)`),
  iin: new RegExp(`(?:^|[^${LAT}])(?:iin|IIN)(?![${LAT}])|(?:^|[^${CYR}])(?:ИИН|иин)(?![${CYR}])`),
  ssn: new RegExp(`(?:^|[^${LAT}])(?:ssn|Ssn|SSN|social.?security|Social.?Security)(?![${LAT}])|(?:^|[^${CYR}])соц`),
  passport: new RegExp(`(?:^|[^${LAT}])(?:passport|Passport)|(?:^|[^${CYR}])(?:паспорт|Паспорт|серия)`),
  phone: new RegExp(`(?:^|[^${LAT}])(?:tel|Tel|phone|Phone|mobile|Mobile|msisdn)(?![a-z])|(?:^|[^${CYR}])(?:телефон|моб)`),
  hash: new RegExp(`(?:^|[^${LAT}])(?:password|Password|passwd|pwd|hash|Hash)(?![a-z])`)
};

const IBAN_LEN = { AL: 28, AD: 24, AT: 20, AZ: 28, BH: 22, BY: 28, BE: 16, BA: 20, BR: 29, BG: 22, BI: 27, CR: 22, HR: 21, CY: 28, CZ: 24, DK: 18, DJ: 27, DO: 28, TL: 23, EG: 29, SV: 28, EE: 20, FK: 18, FO: 18, FI: 18, FR: 27, GE: 22, DE: 22, GI: 23, GR: 27, GL: 18, GT: 28, HN: 28, HU: 28, IS: 26, IQ: 23, IE: 22, IL: 23, IT: 27, JO: 30, KZ: 20, XK: 20, KW: 30, LV: 21, LB: 28, LY: 25, LI: 21, LT: 20, LU: 20, MT: 31, MR: 27, MU: 30, MC: 27, MD: 24, MN: 20, ME: 22, NL: 18, NI: 28, MK: 19, NO: 15, OM: 23, PK: 24, PS: 29, PL: 28, PT: 25, QA: 29, RO: 24, RU: 33, LC: 32, SM: 27, ST: 25, SA: 24, RS: 22, SC: 31, SK: 24, SI: 19, SO: 23, ES: 24, SD: 18, SE: 24, CH: 21, TN: 24, TR: 26, UA: 29, AE: 23, GB: 22, VA: 22, VG: 24, YE: 30 };
const TEST_PAN = new Set(['4111111111111111', '4242424242424242', '5555555555554444', '378282246310005', '6011111111111117', '4000000000000002', '5105105105105100', '3530111333300000']);
const SSA_SPECIMEN = new Set(['078051120', '219099999']);
const EMAIL = /\b[a-z0-9._%+-]{1,64}@(?!(?:example|test|domain|email|sentry)\.)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,5}\.[a-z]{2,24}\b/gi;
const CAP = 2000; // шагов поиска на шаблон: кандидаты без контрольной суммы не должны вытеснять настоящие

export function luhn(d) {
  let sum = 0, dbl = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (dbl) { n *= 2; if (n > 9) n -= 9; }
    sum += n; dbl = !dbl;
  }
  return sum % 10 === 0;
}
// Бренд по префиксу: без него Luhn проходит примерно в одной из десяти случайных строк
export function cardBrandOk(d) {
  const p2 = +d.slice(0, 2), p4 = +d.slice(0, 4), p6 = +d.slice(0, 6);
  if (d[0] === '4') return [13, 16, 19].includes(d.length);
  if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return d.length === 16;
  if (d.length === 15 && (p2 === 34 || p2 === 37)) return true;
  if (p4 === 6011 || p2 === 65 || (p6 >= 644000 && p6 <= 649999)) return d.length >= 16 && d.length <= 19;
  if (p4 >= 3528 && p4 <= 3589) return d.length >= 16 && d.length <= 19;
  if (p4 >= 2200 && p4 <= 2204) return d.length === 16;
  if (p2 === 62) return d.length >= 16 && d.length <= 19;
  if ((p2 === 30 && +d[2] <= 5) || p2 === 36 || p2 === 38) return d.length >= 14 && d.length <= 19; // Diners
  if (p2 === 50 || (p2 >= 56 && p2 <= 58) || p4 === 6759) return d.length >= 12 && d.length <= 19; // Maestro
  return false;
}
export function ibanOk(s) {
  const x = s.replace(/\s+/g, '').toUpperCase();
  if (IBAN_LEN[x.slice(0, 2)] !== x.length) return false;
  let m = 0;
  for (const c of x.slice(4) + x.slice(0, 4)) {
    const v = c >= 'A' ? String(c.charCodeAt(0) - 55) : c;
    for (const d of v) m = (m * 10 + +d) % 97;
  }
  return m === 1;
}
export function innOk(d) {
  const n = Array.from(d, Number);
  if (n.length === 10) return ((2 * n[0] + 4 * n[1] + 10 * n[2] + 3 * n[3] + 5 * n[4] + 9 * n[5] + 4 * n[6] + 6 * n[7] + 8 * n[8]) % 11) % 10 === n[9];
  if (n.length !== 12) return false;
  const w1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8], w2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
  let a = 0, b = 0;
  for (let i = 0; i < 10; i++) a += n[i] * w1[i];
  for (let i = 0; i < 11; i++) b += n[i] * w2[i];
  return (a % 11) % 10 === n[10] && (b % 11) % 10 === n[11];
}
// null: номер не проверяется (не выше 001-001-998)
export function snilsOk(s) {
  const d = s.replace(/\D/g, '');
  if (d.length !== 11) return false;
  if (+d.slice(0, 9) <= 1001998) return null;
  let t = 0;
  for (let i = 0; i < 9; i++) t += +d[i] * (9 - i);
  const c = t < 100 ? t : (t === 100 || t === 101) ? 0 : (t % 101) % 100;
  return c === +d.slice(9);
}
export function ogrnOk(d) { return /^\d{13}$/.test(d) && (Number(d.slice(0, 12)) % 11) % 10 === +d[12]; }
export function ogrnipOk(d) { return /^\d{15}$/.test(d) && (Number(d.slice(0, 14)) % 13) % 10 === +d[14]; }
export function ssnOk(s) {
  const m = /^(\d{3})-(\d{2})-(\d{4})$/.exec(s);
  if (!m) return false;
  const [, a, g, z] = m;
  return !(a === '000' || a === '666' || +a >= 900 || g === '00' || z === '0000');
}

// Границы без lookbehind (Safari до 16.4): префикс (?:^|[^…]) и группа 1 — само значение
const RE = {
  card: /(?:^|[^\d])((?:\d[ -]?){12,18}\d)(?!\d)/g,
  iban: /(?:^|[^A-Za-z0-9])([A-Z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,4})?)(?![A-Za-z0-9])/g,
  inn: /(?:^|[^\d])(\d{10}|\d{12})(?!\d)/g,
  snils: /(?:^|[^\d])(\d{3}[- ]?\d{3}[- ]?\d{3}[ -]?\d{2})(?!\d)/g,
  iin: /(?:^|[^\d])(\d{12})(?!\d)/g,
  ogrnip: /(?:^|[^\d])(\d{15})(?!\d)/g,
  ogrn: /(?:^|[^\d])(\d{13})(?!\d)/g,
  ssn: /(?:^|[^\d-])(\d{3}-\d{2}-\d{4})(?![\d-])/g,
  passport: /(?:^|[^\d])(\d{2}[ -]\d{2}[ -]\d{6})(?!\d)/g,
  phone: /(?:^|[^\w+])((?:\+7|8)[\s(-]{0,2}9\d{2}[\s)-]{0,2}\d{3}[\s-]?\d{2}[\s-]?\d{2}|\+\d{8,15})(?!\d)/g,
  hash: /()(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{8,}\$[A-Za-z0-9+/]{8,})/g,
  hex: /(?:^|[^0-9a-f])([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})(?![0-9a-f])/gi
};

// Hex-хеш пароля: баллы вместо «рядом есть слово password». Константы библиотек (кривые, хеши пустой строки) отсекаются
const HEX_SAFE = new Set(['d41d8cd98f00b204e9800998ecf8427e', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed', '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296']);
const PWD_KEY = /(?:^|[^A-Za-z0-9_])["'`]?((?:pass(?:word)?|passwd|pwd|pw)(?:_?hash(?:ed)?)?|pass_?hash|password_?digest|hashed_?password|hash)["'`]?\s*[:=]\s*["'`]?$/i;
const CRYPTO_CTX = /curve|elliptic|\bgRed\b|ed25519|secp\d|p-?256|modulus|\bnonce\b|\biv\b|\bprime\b|BigInteger|\bbn\.js|sha(?:1|256|512)\(|hmac/i;
const VENDOR_SRC = /(?:^|[/._-])(?:chunk|vendors?|polyfills?|runtime|framework|commons?)(?:[/._-]|$)|node_modules|\.min\.js/i;
function entropy(x) { const c = {}; for (const ch of x) c[ch] = (c[ch] || 0) + 1; let e = 0; for (const k in c) { const p = c[k] / x.length; e -= p * Math.log2(p); } return e; }
export function hexHashScore(text, raw, pos, src) {
  const v = raw.toLowerCase();
  if (HEX_SAFE.has(v)) return null; // шаг 3: известная константа
  if (new Set(v).size < 8 || entropy(v) < 3) return null; // шаг 4: не похоже на случайную строку
  const key = PWD_KEY.exec(text.slice(Math.max(0, pos - 60), pos)); // шаг 1: только значение поля с именем пароля
  if (!key) return null;
  let score = /^hash$/i.test(key[1]) ? 1 : 3;
  const why = ['Value of the field "' + key[1] + '"'];
  if (/^(?:localStorage|sessionStorage|cookie)/.test(src)) { score += 2; why.push('found in browser storage, not in library code'); } // шаг 2: источник
  else if (VENDOR_SRC.test(src)) { score -= 2; why.push('found in a library or vendor bundle'); }
  if (CRYPTO_CTX.test(text.slice(Math.max(0, pos - 300), pos + raw.length + 300))) { score -= 3; why.push('cryptography code nearby'); } // шаг 5
  if (score <= 0) return null; // шаг 6: ниже порога — не показываем
  return score >= 3 ? { risk: 2, conf: 'medium', why: ['Hex value stored as a password field: may be a password hash'].concat(why) } : { risk: 1, conf: 'low', why: ['Possibly a password hash, low confidence'].concat(why) };
}
// Все адреса почты во фрагменте, а не только найденные: иначе адреса сверх лимита видны в чужих фрагментах
export const maskEmails = (str) => String(str).replace(/\b([a-z0-9._%+-])[a-z0-9._%+-]{0,63}@([a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,5}\.[a-z]{2,24})\b/gi, (m, a, d) => (/\.(?:png|jpe?g|svg|js|css|json|tsx?|scss|less|map|html?|xml|md)$/i.test(m) ? m : a + '***@' + d));
export function maskPii(type, raw) {
  const d = raw.replace(/\D/g, '');
  if (type === 'card') return d.slice(0, 6) + '…' + d.slice(-4) + ' (' + d.length + ')';
  if (type === 'iban') { const x = raw.replace(/\s+/g, ''); return x.slice(0, 4) + '…' + x.slice(-4); }
  if (type === 'email') return raw[0] + '***@' + raw.split('@')[1];
  if (type === 'hash') return raw.slice(0, 7) + '…';
  if (type === 'phone') return '•••' + d.slice(-2);
  return '•••' + d.slice(-2) + ' (' + raw.length + ')';
}

// text: источник целиком; src: имя источника (для хранилища и cookie это имя ключа)
export function piiFindings(text, src) {
  text = String(text || '').slice(0, 2e6);
  const out = [], seen = new Set(), counts = {};
  const near = (pos, kind) => KW[kind].test(text.slice(Math.max(0, pos - 40), pos));
  const storage = /^(?:localStorage|sessionStorage|cookie)/.test(src);
  const each = (re, fn) => { re.lastIndex = 0; let m, n = 0; while ((m = re.exec(text)) && n++ < CAP) { const v = m[m.length - 1]; fn(v, m.index + m[0].length - v.length); } };
  const lineCol = lineIndex(text);
  const push = (type, label, raw, pos, conf, risk, why) => {
    const key = type + '|' + raw; if (seen.has(key)) return; seen.add(key);
    counts[type] = (counts[type] || 0) + 1;
    const at = lineCol(pos);
    out.push({ type, label, raw, confidence: conf, risk, why: Array.isArray(why) ? why : [why], file: src, line: at.line, col: at.col, via: 'pii', masked: maskPii(type, raw), snippetRaw: text.slice(Math.max(0, pos - 60), pos + raw.length + 60).replace(/\s+/g, ' ').trim() });
  };

  each(RE.card, (raw, pos) => {
    const r = raw.replace(/[ -]+$/, ''), d = r.replace(/\D/g, '');
    if (d.length < 13 || d.length > 19 || !cardBrandOk(d) || !luhn(d)) return;
    if (TEST_PAN.has(d)) return push('card', 'Payment card number (Luhn)', r, pos, 'high', 0, 'Test value, not a real number');
    const formatted = /^\d{4}([ -])\d{4}\1\d{4}\1\d{4}$/.test(r) || /^\d{4}([ -])\d{6}\2\d{5}$/.test(r);
    if (!formatted && !near(pos, 'card') && !KW.card.test(src)) return; // имя ключа хранилища тоже контекст
    push('card', 'Payment card number (Luhn)', r, pos, formatted ? 'high' : 'medium', storage ? 3 : 2, 'Check whether it is a real card and who can read this file');
  });
  each(RE.iban, (raw, pos) => {
    let x = raw.replace(/\s+/g, '');
    // Жадная группа могла захватить лишние символы: обрезаем до длины IBAN этой страны
    const L = IBAN_LEN[x.slice(0, 2)];
    if (!ibanOk(x) && L && x.length > L && ibanOk(x.slice(0, L))) { let k = 0, cut = 0; while (k < L && cut < raw.length) { if (!/\s/.test(raw[cut])) k++; cut++; } raw = raw.slice(0, cut); x = x.slice(0, L); }
    if (!ibanOk(x)) return;
    const spaced = /\s/.test(raw);
    if (!spaced && !near(pos, 'iban')) return;
    push('iban', 'IBAN (mod 97)', raw, pos, near(pos, 'iban') ? 'high' : 'medium', 2, 'IBAN: check the account owner and whether it is live');
  });
  each(RE.inn, (raw, pos) => {
    if (!innOk(raw) || !near(pos, 'inn')) return;
    const legal = raw.length === 10;
    push('inn', legal ? 'Russian INN (legal entity)' : 'Russian INN (individual)', raw, pos, 'medium', legal ? 1 : 2, 'Tax number (INN): check the owner and whether it is in public registries');
  });
  each(RE.iin, (raw, pos) => { if (near(pos, 'iin')) push('iin', 'Kazakhstan IIN', raw, pos, 'low', 1, 'Kazakhstan IIN: context only, the checksum is not verified'); });
  each(RE.snils, (raw, pos) => {
    if (snilsOk(raw) !== true) return;
    const fmt = /-/.test(raw);
    if (!fmt && !near(pos, 'snils')) return;
    push('snils', 'Russian SNILS', raw, pos, fmt ? 'high' : 'medium', 2, 'SNILS: a personal pension number, check who it belongs to');
  });
  each(RE.ogrn, (raw, pos) => { if (ogrnOk(raw) && near(pos, 'ogrn')) push('ogrn', 'Russian OGRN', raw, pos, 'medium', 1, 'OGRN: company registry number, public by law; check that it is not a personal record'); });
  each(RE.ogrnip, (raw, pos) => { if (ogrnipOk(raw) && near(pos, 'ogrnip')) push('ogrnip', 'Russian OGRNIP', raw, pos, 'medium', 2, 'OGRNIP: sole trader registry number: a personal identifier'); });
  each(RE.ssn, (raw, pos) => {
    if (!ssnOk(raw)) return;
    if (SSA_SPECIMEN.has(raw.replace(/-/g, ''))) return push('ssn', 'US SSN', raw, pos, 'low', 0, 'Advertised specimen SSN, not a real number');
    if (near(pos, 'ssn') || /ssn/i.test(src)) push('ssn', 'US SSN', raw, pos, 'low', storage ? 3 : 2, 'US SSN: passes the format rules only; check whether it is real');
  });
  each(RE.passport, (raw, pos) => { if (near(pos, 'passport') && !/^0+$/.test(raw.replace(/\D/g, ''))) push('passport', 'Russian passport number', raw, pos, 'low', 2, 'Passport number: context only, no checksum'); });
  each(RE.phone, (raw, pos) => { if (near(pos, 'phone')) push('phone', 'Phone number', raw, pos, 'low', 0, 'Phone number: context only, format not checked against carrier data'); });
  each(RE.hash, (raw, pos) => push('hash', 'Password hash', raw, pos, 'high', 3, 'Password hash in client code: a server-side hash has been sent to the browser'));
  each(RE.hex, (raw, pos) => { const sc = hexHashScore(text, raw, pos, src); if (sc) push('hash', 'Password hash', raw, pos, sc.conf, sc.risk, sc.why); });
  const mails = new Set();
  EMAIL.lastIndex = 0; let em, ne = 0;
  // Находок не больше 8, но считаются все адреса: число в сводной находке — настоящее
  while ((em = EMAIL.exec(text)) && ne++ < CAP) {
    const e = em[0].toLowerCase();
    if (!mails.has(e) && !/\.(?:png|jpe?g|svg|js|css|json|tsx?|scss|less|map|html?|xml|md)$/i.test(e)) { mails.add(e); if (mails.size > 8) { counts.email++; continue; } push('email', 'Email address', em[0], em.index, 'high', 0, 'Email address in code or data: check whether it is a personal or service mailbox'); }
  }
  // Много разных значений одного типа в одном источнике: список данных в клиентском коде
  for (const [type, n] of Object.entries(counts)) if (n >= 5) {
    const top = Math.max(...out.filter((f) => f.type === type).map((f) => f.risk));
    out.push({ type, label: 'Many distinct values', raw: '', masked: 'x' + n, confidence: 'medium', risk: Math.min(3, top + 1), why: ['Distinct values: ' + n + ' in this source'], file: src, line: 1, col: 1, via: 'pii', snippetRaw: '' });
  }
  return out;
}
