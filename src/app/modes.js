// Режимы скана: тихий (без своих запросов) и полный. Без DOM, чтобы правила проверялись тестом.
export const SCAN_KEYS = ['delay', 'budget', 'depth', 'cookies', 'wellKnown', 'guessMaps', 'osv', 'npmCheck', 'rules', 'allowHosts'];

// Настройки скана для режима: тихий не делает ни одного своего запроса — ни к сайту, ни к OSV и npm
export const settingsFor = (mode, s) => (mode === 'full' ? s : Object.assign({}, s, { noRequests: true, osv: false, npmCheck: false }));

// Изменились ли настройки, от которых зависят результаты (язык и тема не в счёт)
export const scanChanged = (a, b) => SCAN_KEYS.some((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]));

// Сохранённые результаты по режимам. Поколение (gen) растёт при сбросе: скан, начатый до сброса, себя не сохранит
export function modeCache() {
  const byMode = {}, gen = {};
  return {
    get: (m) => byMode[m] || null,
    stores: () => Object.values(byMode).map((e) => e.store),
    // Начало скана: идущий результат виден сразу при возврате в режим. Возвращает поколение для finish
    start(m, entry) { byMode[m] = entry; return gen[m] || 0; },
    // Конец скана: сохраняется, если режим не сбрасывали и скан не упал (остановленный — сохраняется)
    finish(m, token, entry, ok) {
      if (ok && (gen[m] || 0) === token) { byMode[m] = entry; return true; }
      if (byMode[m] && byMode[m].store === entry.store) delete byMode[m];
      return false;
    },
    // Сбросить режим или оба; возвращает сброшенные режимы
    drop(m) { const list = m ? [m] : ['quiet', 'full']; for (const x of list) { gen[x] = (gen[x] || 0) + 1; delete byMode[x]; } return list; }
  };
}
