// Shodan-format favicon hash (MurmurHash3 x86 32 of base64 with a line break every 76 chars, like Python base64.encodebytes).
export function mmh3(str, seed = 0) {
  const b = new TextEncoder().encode(str); let h = seed >>> 0, i = 0;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  for (; i + 4 <= b.length; i += 4) {
    let k = b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24);
    k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2);
    h ^= k; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  let k = 0; const r = b.length & 3;
  if (r === 3) k ^= b[i + 2] << 16;
  if (r >= 2) k ^= b[i + 1] << 8;
  if (r >= 1) { k ^= b[i]; k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k; }
  h ^= b.length; h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return h | 0; // signed, like Shodan
}
export function faviconHash(bytes) {
  if (!bytes.length) return 0; // same as mmh3 of an empty string in Python
  let bin = ''; for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin).replace(/.{76}/g, '$&\n');
  return mmh3(b64.endsWith('\n') ? b64 : b64 + '\n');
}
