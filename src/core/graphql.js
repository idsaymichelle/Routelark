// E4: операции, фрагменты, переменные и persisted-идентификаторы GraphQL из клиентского кода, черновик SDL.
// Это не интроспекция: типы полей угадываются и помечаются «# guessed». Карты persisted-запросов не запрашиваются.
const OP = /(?:^|[^\w$. \t])[ \t]*(query|mutation|subscription)\b\s*(?:([A-Za-z_]\w{0,79})\s*)?(\(\s*\$[^)]{0,600}\)\s*)?(?:@\w+(?:\s*\([^)]{0,200}\))?\s*)?\{/g; // аргументы — только переменные $x: метод JS query(a) {…} не операция
const FRAG = /(?:^|[^\w$. \t])[ \t]*fragment\s+([A-Za-z_]\w{0,79})\s+on\s+([A-Za-z_]\w{0,79})\s*(?:@\w+(?:\s*\([^)]{0,200}\))?\s*)?\{/g;
const SENSITIVE = /\b(?:delete|remove|destroy|revoke|transfer|role|admin|grant|ban)(?:s|d|ed)?\b/i; // слово целиком после разбиения camelCase: updateBanner не «ban»

// Поля первого и второго уровня тела: { a(x: $v) { b c } d } → [{name:'a', args:['x'], children:['b','c']}, {name:'d'}]
function fields(text, start) {
  const body = text.slice(start, start + 20000).replace(/\\n/g, '\n').replace(/"(?:[^"\\]|\\.)*"|#[^\n]*/g, '""');
  const out = []; let depth = 0, cur = null, i = 0;
  const re = /([A-Za-z_]\w*)\s*(?::\s*([A-Za-z_]\w*))?|[{}()]|\.\.\.\s*(?:on\s+)?[A-Za-z_]\w*/g; let m, paren = 0;
  while ((m = re.exec(body)) && i++ < 5000) {
    const tok = m[0];
    if (tok === '(') { paren++; continue; } if (tok === ')') { paren--; continue; }
    if (paren) { const after = m[1] && m[2] === undefined ? /^\s*:\s*(\$\w+)?/.exec(body.slice(m.index + m[1].length)) : null; if (cur && after && depth === 1) cur.args.push([m[1], after[1] ? after[1].slice(1) : null]); continue; }
    if (tok === '{') { depth++; continue; }
    if (tok === '}') { if (--depth <= 0) break; continue; }
    if (tok.startsWith('...')) continue;
    const name = m[2] || m[1];
    if (depth === 1) out.push(cur = { name, args: [], children: [] }); else if (depth === 2 && cur && cur.children.length < 50) cur.children.push(name);
    if (out.length >= 100) break;
  }
  return out;
}
export function graphqlFromText(text) {
  text = String(text).slice(0, 4e5);
  const ops = [], fragments = [], persisted = []; let m;
  OP.lastIndex = 0;
  while ((m = OP.exec(text)) && ops.length < 100) {
    const vars = []; const vr = /\$([A-Za-z_]\w*)\s*:\s*(\[?[\w!\[\] ]{1,40}\]?!?)/g; let v;
    while (m[3] && (v = vr.exec(m[3])) && vars.length < 20) vars.push([v[1], v[2].trim()]);
    ops.push({ kind: m[1], name: m[2] || '', vars, fields: fields(text, m.index + m[0].length - 1), at: m.index + m[0].indexOf(m[1]) });
  }
  FRAG.lastIndex = 0;
  while ((m = FRAG.exec(text)) && fragments.length < 60) fragments.push({ name: m[1], on: m[2], fields: fields(text, m.index + m[0].length - 1), at: m.index + m[0].indexOf('fragment') });
  const rel = /params\s*:\s*\{(?:[^{}]|\{[^{}]{0,100}\}){0,400}?\bid\s*:\s*(["'])([\w-]{8,64})\1(?:[^{}]|\{[^{}]{0,100}\}){0,400}?name\s*:\s*(["'])(\w{2,80})\3/g;
  while ((m = rel.exec(text)) && persisted.length < 200) persisted.push({ kind: 'relay', id: m[2], name: m[4], at: m.index });
  const apq = /persistedQuery\s*:\s*\{[^}]{0,120}?sha256Hash\s*:\s*(["'])([0-9a-f]{64})\1/g;
  while ((m = apq.exec(text)) && persisted.length < 200) persisted.push({ kind: 'apq', id: m[2], name: '', at: m.index });
  return { ops, fragments, persisted };
}
// Простые находки для Store: { title, risk, why, at }
export function graphqlFindings(text) {
  const g = graphqlFromText(text), out = [];
  for (const o of g.ops) {
    const sens = o.kind === 'mutation' && SENSITIVE.test((o.name + ' ' + o.fields.map((f) => f.name).join(' ')).replace(/([a-z])([A-Z])/g, '$1 $2'));
    out.push({ title: o.kind + ' ' + (o.name || '(anonymous: ' + o.fields.map((f) => f.name).slice(0, 3).join(', ') + ')'), risk: sens ? 2 : o.kind === 'mutation' ? 1 : 0, why: [sens ? 'Mutation with a sensitive name: check object-level authorization' : o.kind === 'mutation' ? 'GraphQL mutation: changes data, check authorization' : 'GraphQL operation in client code'].concat(o.vars.length ? ['variables: ' + o.vars.map((v) => '$' + v[0] + ': ' + v[1]).join(', ')] : []), at: o.at, op: o });
  }
  for (const f of g.fragments) out.push({ title: 'fragment ' + f.name + ' on ' + f.on, risk: 0, why: ['Fragment: shows fields of type ' + f.on], at: f.at, frag: f });
  for (const p of g.persisted) out.push({ title: 'persisted ' + (p.name || p.kind) + ' ' + p.id.slice(0, 16), risk: 0, why: ['Persisted operation id: the server runs it by id, check its authorization'], at: p.at });
  return out;
}
// Черновик SDL по собранным операциям и фрагментам
export function sdlDraft(items) {
  const types = new Map(), add = (t, name, line) => { if (name.startsWith('__')) return; /* зарезервировано спекой */ if (!types.has(t)) types.set(t, new Map()); const m = types.get(t); if (!m.has(name) && m.size < 200) m.set(name, line); };
  const root = { query: 'Query', mutation: 'Mutation', subscription: 'Subscription' };
  for (const it of items) {
    if (it.op) for (const f of it.op.fields) {
      const args = f.args.map(([a, vn]) => { const v = vn && it.op.vars.find((x) => x[0] === vn); return a + ': ' + (v ? v[1] : 'String'); });
      const tn = f.name[0].toUpperCase() + f.name.slice(1) + 'Draft';
      add(root[it.op.kind], f.name, f.name + (args.length ? '(' + args.join(', ') + ')' : '') + ': ' + (f.children.length ? tn : 'String') + ' # guessed');
      for (const c of f.children) add(tn, c, c + ': String # guessed');
    }
    if (it.frag) for (const f of it.frag.fields) add(it.frag.on, f.name, f.name + ': String # guessed');
  }
  if (!types.size) return '';
  // Схема должна быть валидной: тип Query обязателен, неизвестные типы аргументов объявляются как scalar
  if (!types.has('Query')) types.set('Query', new Map([['_placeholder', '_placeholder: String # no queries seen in client code']]));
  const body = Array.from(types, ([t, fs]) => 'type ' + t + ' {\n' + Array.from(fs.values(), (l) => '  ' + l).join('\n') + '\n}').join('\n\n');
  const used = new Set((body.match(/\(([^)]*)\)/g) || []).join(',').match(/:\s*\[?([A-Za-z_]\w*)/g) || []);
  const scalars = Array.from(used, (x) => x.replace(/^:\s*\[?/, '')).filter((n) => !/^(?:String|Int|Float|Boolean|ID)$/.test(n) && !types.has(n));
  return '# Draft from client code. Not introspection. Verify before use.\n\n' + Array.from(new Set(scalars), (n) => 'scalar ' + n + ' # input type, fields unknown\n').join('') + (scalars.length ? '\n' : '') + body + '\n';
}
