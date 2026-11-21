// Стек по глобальным объектам страницы (передаётся window или заглушка в тестах).
export function techFromRuntime(w) {
  const out = [], get = (path) => { try { return path.split('.').reduce((o, k) => o[k], w); } catch (e) { return undefined; } };
  const add = (name, v) => { if (v != null) out.push({ name, version: typeof v === 'string' ? v : null }); };
  add('jQuery', get('jQuery.fn.jquery'));
  const us = get('_');
  // У Underscore только версии 1.x; у Lodash есть runInContext (кроме сборки core) и версии 2+
  if (us && typeof us.VERSION === 'string') add(typeof us.runInContext === 'function' || parseInt(us.VERSION, 10) >= 2 ? 'Lodash' : 'Underscore', us.VERSION);
  add('AngularJS', get('angular.version.full'));
  add('Vue', get('Vue.version'));
  add('React', get('React.version'));
  add('Moment.js', get('moment.version'));
  add('DOMPurify', get('DOMPurify.version'));
  add('Next.js', get('next.version'));
  add('Handlebars', get('Handlebars.VERSION'));
  add('Axios', get('axios.VERSION'));
  return out;
}
