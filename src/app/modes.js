// Scan modes: quiet (no own requests) and full. No DOM so the rules are testable.
export const SCAN_KEYS = ['delay', 'budget', 'depth', 'cookies', 'wellKnown', 'guessMaps', 'osv', 'npmCheck', 'rules', 'allowHosts'];

// Scan settings for a mode: quiet makes no own requests - not to the site, OSV or npm
export const settingsFor = (mode, s) => (mode === 'full' ? s : Object.assign({}, s, { noRequests: true, osv: false, npmCheck: false }));

// Whether result-affecting settings changed (language and theme do not count)
export const scanChanged = (a, b) => SCAN_KEYS.some((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]));

// Saved results per mode. The generation (gen) grows on reset: a scan started before the reset will not save itself
export function modeCache() {
  const byMode = {}, gen = {};
  return {
    get: (m) => byMode[m] || null,
    stores: () => Object.values(byMode).map((e) => e.store),
    // Scan start: the running result is visible at once when returning to the mode. Returns the generation for finish
    start(m, entry) { byMode[m] = entry; return gen[m] || 0; },
    // Scan end: saved if the mode was not reset and the scan did not fail (a stopped one is saved)
    finish(m, token, entry, ok) {
      if (ok && (gen[m] || 0) === token) { byMode[m] = entry; return true; }
      if (byMode[m] && byMode[m].store === entry.store) delete byMode[m];
      return false;
    },
    // Reset one mode or both; returns the reset modes
    drop(m) { const list = m ? [m] : ['quiet', 'full']; for (const x of list) { gen[x] = (gen[x] || 0) + 1; delete byMode[x]; } return list; }
  };
}
