import test from 'node:test';
import assert from 'node:assert/strict';
import { prettyJs, displayText, searchTexts, fileType, isMinified } from '../src/core/files.js';
import { Store, crawl, makeScope } from '../src/core.js';

test('prettyJs: скобки и ; дают переносы, строки и регулярки не трогаются', () => {
  const out = prettyJs('function a(b){if(b){return /a\\/b[/;]/g.test("x;y{")}for(var i=0;i<3;i++){c(i)}var o={s:`t${x};`};return o}');
  assert.match(out, /^function a\(b\)\{\n  if\(b\)\{\n    return \/a\\\/b\[\/;\]\/g\.test\("x;y\{"\)\n  \}/);
  assert.match(out, /for\(var i=0;i<3;i\+\+\)\{\n    c\(i\)\n  \}/);
  assert.match(out, /`t\$\{x\};`/);
  assert.match(out, /\};\n  return o\n\}\n$/);
});

test('displayText: JSON с отступами, обычный JS как есть, минифицированный раскладывается', () => {
  assert.equal(displayText('{"a":1}', 'json'), '{\n  "a": 1\n}');
  assert.equal(displayText('var a = 1;\nvar b = 2;\n', 'js'), 'var a = 1;\nvar b = 2;\n');
  const min = 'var a=1;'.repeat(400);
  assert.ok(isMinified(min));
  assert.ok(displayText(min, 'js').split('\n').length > 300);
});

test('fileType: по расширению, по заголовку, исходники из source map', () => {
  assert.equal(fileType('https://x/a.js?v=1'), 'js');
  assert.equal(fileType('https://x/main.js.map#src/app/user.service.ts'), 'js');
  assert.equal(fileType('https://x/i18n/en.json'), 'json');
  assert.equal(fileType('https://x/logo.png'), 'image');
  assert.equal(fileType('https://x/'), 'other');
  assert.equal(fileType('https://x/', 'text/html; charset=utf-8'), 'html');
});

test('searchTexts: строки и колонки, regex, регистр, лимит, плохая регулярка', () => {
  const files = [{ url: 'a', text: 'Ab\ncd ab' }, { url: 'node_modules/x.js', text: 'ab' }];
  assert.deepEqual(searchTexts(files, 'ab').results.map((r) => [r.url, r.line, r.col]), [['a', 1, 1], ['a', 2, 4], ['node_modules/x.js', 1, 1]]);
  assert.equal(searchTexts(files, 'ab', { caseSensitive: true }).results.length, 2);
  assert.equal(searchTexts(files, 'ab', { skipVendor: true }).results.length, 2);
  assert.equal(searchTexts(files, 'a.', { regex: true }).results.length, 3);
  assert.equal(searchTexts(files, 'a.').results.length, 0);
  assert.ok(searchTexts(files, '(', { regex: true }).error);
  assert.equal(searchTexts([{ url: 'b', text: 'x'.repeat(1000) }], 'x', { max: 10 }).results.length, 10);
  assert.equal(searchTexts([{ url: 'b', text: 'abc' }], '^', { regex: true }).results.length, 0);
});

test('crawl сохраняет тексты файлов и исходники из source map', async () => {
  const store = new Store('https://app.example.org/');
  const files = {
    'https://app.example.org/app.js': 'fetch("/api/x");\n//# sourceMappingURL=app.js.map',
    'https://app.example.org/app.js.map': JSON.stringify({ version: 3, sources: ['webpack:///src/a.ts', 'webpack:///node_modules/lib/i.js'], sourcesContent: ['const u = "/api/a";', 'lib'] })
  };
  await crawl({ store, seeds: [{ url: 'https://app.example.org/app.js' }], scope: makeScope({ pageUrl: store.pageUrl }), fetchText: async (u) => ({ ok: true, status: 200, headers: { 'content-type': 'text/javascript' }, text: files[u] }) });
  // node_modules libraries are not stored; the source map itself is not either, only its sources
  assert.deepEqual(Array.from(store.texts.keys()).sort(), ['https://app.example.org/app.js', 'https://app.example.org/app.js.map#src/a.ts']);
  assert.equal(store.texts.get('https://app.example.org/app.js.map#src/a.ts').text, 'const u = "/api/a";');
});

test('wordlist: слова со страницы и путей, поля форм, ключи JSON; без стоп-слов и хешей', async () => {
  const { wordlist } = await import('../src/core/words.js');
  const s = new Store('https://shop.example.org/');
  s.addText(s.pageUrl, '<p>Checkout your basket with the coupon</p><!-- internal staging --><input name="couponCode"><img alt="Delivery truck"><script>var nope = 1</script>');
  s.addText('https://shop.example.org/openapi.json', '{"paths":{},"orderId":1,"a":2}', 'application/json');
  s.addHit({ raw: '/api/v2/basket-items/{id}?token=1', file: 'x', line: 1, col: 1, via: 'call' });
  const w = wordlist(s);
  for (const x of ['checkout', 'basket', 'coupon', 'internal', 'staging', 'delivery', 'truck', 'items', 'api']) assert.ok(w.words.includes(x), x);
  for (const x of ['the', 'with', 'your', 'nope', 'v2', 'id']) assert.ok(!w.words.includes(x), x);
  for (const x of ['couponCode', 'token', 'orderId', 'paths']) assert.ok(w.params.includes(x), x);
});

test('проверка: шаблоны не теряют пустых строк, i++/2 не регулярка, совпадение на переводе строки', () => {
  assert.match(prettyJs('a=`l1\n\n\nl2`;b=1'), /`l1\n\n\nl2`;\nb=1/);
  assert.match(prettyJs('x=i++/2;y=3/4'), /x=i\+\+\/2;\ny=3\/4/);
  const r = searchTexts([{ url: 'a', text: 'abc\nxabcx' }], '\\n', { regex: true }).results[0];
  assert.ok(r.col >= 1 && r.at >= 0, JSON.stringify(r));
  assert.equal(r.line, 1);
});

test('compareFiles: изменённые, новые и пропавшие JS-файлы; хеш сборки в имени не важен', async () => {
  const { fileHashes, compareFiles } = await import('../src/core/session.js');
  const a = new Store('https://s.test/');
  a.addText('https://s.test/main.1a2b3c4d5e.js', 'v1', 'text/javascript'); a.addText('https://s.test/old.js', 'x'); a.addText('https://s.test/same.js', 's'); a.addText('https://s.test/', '<html>');
  const prev = fileHashes(a);
  assert.equal(Object.keys(prev).length, 3); // page HTML is not tracked
  const b = new Store('https://s.test/');
  b.addText('https://s.test/main.9f8e7d6c5b.js', 'v2'); b.addText('https://s.test/same.js', 's'); b.addText('https://s.test/new.js', 'n');
  assert.deepEqual(compareFiles(prev, b), { added: ['https://s.test/new.js'], changed: ['https://s.test/main.9f8e7d6c5b.js'], removed: ['https://s.test/old.js'] });
});

test('searchTexts работает как отдельный текст функции (так он запускается в Worker)', () => {
  const f = new Function('return ' + searchTexts.toString())();
  assert.equal(f([{ url: 'node_modules/a.js', text: 'x' }, { url: 'b', text: 'x' }], 'x', { skipVendor: true }).results.length, 1);
});

test('fileKey: хеши webpack и Vite, query с токеном отбрасывается; одинаковые имена чанков не дают ложных изменений', async () => {
  const { fileKey, fileHashes, compareFiles } = await import('../src/core/session.js');
  assert.equal(fileKey('https://s.test/assets/index-BdQq_4o5.js?X-Amz-Signature=abc'), 'https://s.test/assets/index.js');
  assert.equal(fileKey('https://s.test/main.3f2a9c1b.js'), 'https://s.test/main.js');
  assert.equal(fileKey('https://s.test/vendor-lib.js'), 'https://s.test/vendor-lib.js');
  const mk = (order) => { const s = new Store('https://s.test/'); order.forEach(([u, t]) => s.addText(u, t)); return s; };
  const a = mk([['https://s.test/index-AAAA1111.js', 'one'], ['https://s.test/index-BBBB2222.js', 'two']]);
  const b = mk([['https://s.test/index-BBBB2222.js', 'two'], ['https://s.test/index-AAAA1111.js', 'one']]);
  assert.deepEqual(compareFiles(fileHashes(a), b), { added: [], changed: [], removed: [] });
  assert.ok(!JSON.stringify(fileHashes(mk([['https://s.test/a.js?token=secret', 'x']]))).includes('secret'));
});

test('displayPosition: позиция из минифицированного файла попадает на то же место в отформатированном', async () => {
  const { displayPosition } = await import('../src/core/files.js');
  const raw = 'var a=1;'.repeat(300) + 'fetch("/api/target");' + 'var b=2;'.repeat(300);
  const col = raw.indexOf('/api/target') + 1;
  const p = displayPosition(raw, 'js', 1, col), lines = displayText(raw, 'js').split('\n');
  assert.ok(lines[p.line - 1].slice(p.col - 1).startsWith('/api/target'), JSON.stringify(p));
  assert.ok(!displayText(raw, 'js').includes('\uE000'));
  assert.deepEqual(displayPosition('a\nb', 'js', 2, 1), { line: 2, col: 1 });
});

test('addText: сверх предела файлы не хранятся, но считаются', () => {
  const s = new Store('https://a.test/');
  s.addText('https://a.test/big.js', 'x'.repeat(24e6));
  s.addText('https://a.test/more.js', 'y'.repeat(2e6));
  s.addText('https://a.test/big.js', 'z');
  assert.equal(s.texts.size, 1); assert.equal(s.textsSkipped, 1);
});

test('historyEntry: все id сохраняются, подписи ограничены 5000', async () => {
  const { historyEntry } = await import('../src/core/session.js');
  const s = new Store('https://a.test/');
  for (let i = 0; i < 6000; i++) s.addSimple('custom', { title: 't' + i, file: 'x' });
  const e = historyEntry(s);
  assert.equal(e.ids.length, 6000); assert.equal(Object.keys(e.labels).length, 5000);
});

test('fileMeta: JPEG с EXIF (камера, программа, GPS), PNG с текстом, SVG с путём автора', async () => {
  const { fileMeta } = await import('../src/core/meta.js');
  // Build a tiny JPEG: SOI, APP1 Exif (TIFF little-endian, IFD0: Make, Software, GPS pointer), COM, SOF0
  const tiff = [], u16 = (v) => tiff.push(v & 255, v >> 8), u32 = (v) => tiff.push(v & 255, (v >> 8) & 255, (v >> 16) & 255, v >>> 24);
  tiff.push(0x49, 0x49); u16(42); u32(8);
  u16(3);
  const make = 'Canon\0', soft = 'Photoshop 25\0';
  const dataStart = 8 + 2 + 3 * 12 + 4;
  u16(0x010f); u16(2); u32(make.length); u32(dataStart);
  u16(0x0131); u16(2); u32(soft.length); u32(dataStart + make.length);
  const gpsOff = dataStart + make.length + soft.length;
  u16(0x8825); u16(4); u32(1); u32(gpsOff);
  u32(0);
  for (const c of make + soft) tiff.push(c.charCodeAt(0));
  // GPS IFD: LatRef N, Lat 55/1 45/1 0/1, LonRef E, Lon 37/1 36/1 0/1
  const ratOff = gpsOff + 2 + 4 * 12 + 4;
  u16(4);
  u16(1); u16(2); u32(2); tiff.push(78, 0, 0, 0);
  u16(2); u16(5); u32(3); u32(ratOff);
  u16(3); u16(2); u32(2); tiff.push(69, 0, 0, 0);
  u16(4); u16(5); u32(3); u32(ratOff + 24);
  u32(0);
  for (const [a, b] of [[55, 1], [45, 1], [0, 1], [37, 1], [36, 1], [0, 1]]) { u32(a); u32(b); }
  const app1 = [...'Exif'].map((c) => c.charCodeAt(0)).concat([0, 0], tiff);
  const com = [...'made by bob'].map((c) => c.charCodeAt(0));
  const jpg = [0xff, 0xd8, 0xff, 0xe1, (app1.length + 2) >> 8, (app1.length + 2) & 255, ...app1, 0xff, 0xfe, 0, com.length + 2, ...com, 0xff, 0xc0, 0, 11, 8, 0, 240, 1, 64, 3, 0, 0, 0, 0xff, 0xda];
  const m = fileMeta(new Uint8Array(jpg));
  assert.equal(m.format, 'JPEG');
  const f = Object.fromEntries(m.fields);
  assert.equal(f['Camera make'], 'Canon'); assert.equal(f.Software, 'Photoshop 25'); assert.equal(f.Comment, 'made by bob');
  assert.equal(f.Size, '320 × 240'); assert.equal(f['GPS location'], '55.750000, 37.600000');
  // PNG: IHDR 2x3 and tEXt Author
  const be = (v) => [v >>> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255];
  const chunk = (type, data) => [...be(data.length), ...[...type].map((c) => c.charCodeAt(0)), ...data, 0, 0, 0, 0];
  const png = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, ...chunk('IHDR', [...be(2), ...be(3), 8, 6, 0, 0, 0]), ...chunk('tEXt', [...'Author\0C:\\Users\\alice\\pic.png'].map((c) => c.charCodeAt(0))), ...chunk('IEND', [])]);
  const p = fileMeta(png);
  assert.equal(p.format, 'PNG'); assert.deepEqual(p.fields[0], ['Size', '2 × 3']); assert.deepEqual(p.paths, ['C:\\Users\\alice']);
  const svg = fileMeta(new TextEncoder().encode('<svg xmlns:inkscape="x" inkscape:version="1.3" sodipodi:docname="logo.svg" inkscape:export-filename="/home/dev/work/logo.png"><!-- internal draft --></svg>'));
  assert.equal(svg.format, 'SVG'); assert.ok(svg.paths.includes('/home/dev'));
});

test('E2: разбор WASM без компиляции', async () => {
  const { parseWasm } = await import('../src/core/wasm.js');
  const { fileMeta } = await import('../src/core/meta.js');
  const enc = (s) => [s.length, ...Buffer.from(s)];
  const sec = (id, body) => [id, body.length, ...body];
  const imp = sec(2, [1, ...enc('env'), ...enc('fetch_url'), 0, 0]);
  const exp = sec(7, [1, ...enc('main'), 0, 0]);
  const smap = sec(0, [...enc('sourceMappingURL'), ...enc('app.wasm.map')]);
  const data = sec(11, [...Buffer.from('https://api.example/v1')]);
  const bytes = new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, ...imp, ...exp, ...smap, ...data]);
  const w = parseWasm(bytes);
  assert.deepEqual([w.ok, w.imports[0].name, w.exports[0].name, w.sourceMappingURL, w.urls[0]], [true, 'fetch_url', 'main', 'app.wasm.map', 'https://api.example/v1']);
  const m = fileMeta(bytes);
  assert.equal(m.format, 'WebAssembly');
  assert.ok(m.fields.some(([k, v]) => k === 'Host functions to check' && v === 'env.fetch_url'));
  assert.equal(parseWasm(new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 2, 50])).truncated, true);
});

test('B6: метаданные Office (ZIP + deflate-raw) и шрифта', async () => {
  const { officeMeta, fontMeta } = await import('../src/core/office.js');
  const zlib = await import('node:zlib');
  const core = Buffer.from('<cp:coreProperties><dc:creator>Ivan Petrov</dc:creator><cp:lastModifiedBy>admin</cp:lastModifiedBy></cp:coreProperties>');
  const files = [['word/document.xml', Buffer.from('<w/>'), 0], ['docProps/core.xml', zlib.deflateRawSync(core), 8]];
  const parts = [], cd = []; let off = 0;
  for (const [name, data, method] of files) {
    const n = Buffer.from(name), lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(method, 8); lh.writeUInt32LE(data.length, 18); lh.writeUInt16LE(n.length, 26);
    parts.push(lh, n, data);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(method, 10); ch.writeUInt32LE(data.length, 20); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(off, 42);
    cd.push(ch, n); off += 30 + n.length + data.length;
  }
  const cdb = Buffer.concat(cd), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cdb.length, 12); end.writeUInt32LE(off, 16);
  const m = await officeMeta(new Uint8Array(Buffer.concat([...parts, cdb, end])));
  assert.equal(m.format, 'Word document');
  assert.ok(m.fields.some(([k, v]) => k === 'Author' && v === 'Ivan Petrov') && m.fields.some(([k, v]) => k === 'Last modified by' && v === 'admin'));
  // Minimal TTF with a name table: Family = "Acme Sans"
  const str = Buffer.from('\0A\0c\0m\0e\0 \0S\0a\0n\0s');
  const name = Buffer.alloc(6 + 12); name.writeUInt16BE(1, 2); name.writeUInt16BE(18, 4); name.writeUInt16BE(3, 6); name.writeUInt16BE(1, 12); name.writeUInt16BE(str.length, 14);
  const head = Buffer.alloc(12 + 16); head.writeUInt32BE(0x00010000, 0); head.writeUInt16BE(1, 4); head.write('name', 12); head.writeUInt32BE(28, 20);
  assert.deepEqual(fontMeta(new Uint8Array(Buffer.concat([head, name, str]))).fields, [['Family', 'Acme Sans']]);
});

test('C: хеш favicon в формате Shodan (MurmurHash3)', async () => {
  const { mmh3, faviconHash } = await import('../src/core/favicon.js');
  assert.equal(mmh3('hello'), 613153351);
  assert.equal(mmh3(''), 0);
  assert.equal(mmh3('The quick brown fox jumps over the lazy dog'), 776992547);
  assert.equal(typeof faviconHash(new Uint8Array([0, 1, 2, 255])), 'number');
});

test('QA 03/04: индексная карта, исходники пакетов, XSSI, одинаковые имена, IBAN, телефон, тестовые карты', async () => {
  const { parseSourceMaps, analyzeInto } = await import('../src/core.js');
  const { piiFindings } = await import('../src/core/pii.js');
  assert.equal(parseSourceMaps(JSON.stringify({ version: 3, sections: [{ offset: {}, map: { sources: ['a.js'] } }, { offset: {}, map: { sources: ['b.js'] } }] })).length, 2);
  assert.equal(parseSourceMaps(")]}'\n" + JSON.stringify({ sources: ['a'] })).length, 1);
  const s = new Store('https://a.test/'); analyzeInto(s, JSON.stringify({ version: 3, sources: ['webpack:///node_modules/lib/k.js', 'webpack:///src/x/a.ts', 'webpack:///./src/y/a.ts'], sourcesContent: ['const k = "ghp_Zq8LmN2pRt5vWx7yBc4dFg9hJk1nMa3sEu6i"', 'const a=1', 'const b=2'] }), 'https://a.test/m.js.map');
  assert.ok(s.items.some((f) => f.kind === 'secret'));
  const ty = (t) => piiFindings(t, 'a.js').map((f) => f.type + ':' + f.risk);
  assert.deepEqual(ty('IBAN DE89 3704 0044 0532 0130 00 EXTRA'), ['iban:2']);
  assert.deepEqual(ty('phone +7 (912) 345-67-89'), ['phone:0']);
  assert.deepEqual(ty('card: "4000 0000 0000 0002"'), ['card:0']);
});
