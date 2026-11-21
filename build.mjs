// node build.mjs → dist/routelark.html: один файл. Открыть его (хоть с диска) и перетащить кнопку на панель закладок.
// Закладка самодостаточна: внутри весь интерфейс и анализ. Серверов и хостинга не нужно.
// Для разработки в dist/ также лежат demo.html и demo/ (тестовая страница для npm run serve) и bookmarklet.txt.
// esbuild берётся из node_modules (npm install) или из переменной ESBUILD=/путь/к/esbuild.
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

// Chrome хранит закладки до ~2 МБ; Firefox обрезает длиннее 64 КБ и поэтому не поддерживается
const LIMIT = 1.5e6;
const bin = process.env.ESBUILD || 'node_modules/.bin/esbuild';
const common = ['--bundle', '--minify', '--charset=utf8', '--target=es2020', '--legal-comments=none'];
const esbuild = (args) => execFileSync(bin, args.concat(common), { encoding: 'utf8', maxBuffer: 64e6, stdio: ['ignore', 'pipe', 'inherit'] }).trim();

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist', { recursive: true });
cpSync('site', 'dist', { recursive: true });

const css = esbuild(['site/app.css', '--loader:.css=css']);
const icon = 'data:image/png;base64,' + readFileSync('site/icon.png').toString('base64'); // значок вкладки, встроен в файл
// Интерфейс внутри закладки: window, document и хранилища подменяются на вкладку Routelark (см. src/bookmarklet.js)
const inner = esbuild(['src/app/main.js', '--format=iife', '--define:RL_BOOKMARKLET=""']);
const loader = esbuild(['src/bookmarklet.js', '--format=iife', '--define:RL_CSS=' + JSON.stringify(css), '--define:RL_ICON=' + JSON.stringify(icon)]);
const code = '(()=>{var RL_RUN=function(window,document,location,history,localStorage,sessionStorage,setTimeout,clearTimeout){' + inner + '};' + loader + '})();';
// Lookbehind в регулярках Safari понимает только с 16.4: одна такая регулярка ломает всю закладку
if (/\(\?<[=!]/.test(code)) throw new Error('lookbehind (?<= or (?<! in code: Safari before 16.4 fails to parse it');
// Кодирование как у encodeURI плюс ? # и /. Safari (WebKit) разбирает адрес javascript: как путь и выкидывает
// «/../» и «/./» вместе с соседним кодом (например, перед регуляркой /../g), поэтому каждый / кодируется как %2F
const bookmarklet = 'javascript:' + encodeURI(code + 'void 0').replace(/[?#/]/g, encodeURIComponent);
if (/[/\s\\"<>`{}|^]/.test(bookmarklet.slice(11))) throw new Error('bookmarklet has characters Safari would change');
if (bookmarklet.length > LIMIT) throw new Error('bookmarklet is ' + bookmarklet.length + ' bytes, over ' + LIMIT);
writeFileSync('dist/bookmarklet.txt', bookmarklet);

// Страница установки: стили и код встроены, внешних файлов нет. «</script» внутри кода экранируется
const home = esbuild(['src/app/main.js', '--format=iife', '--define:RL_BOOKMARKLET=' + JSON.stringify(bookmarklet)]).replace(/<\/script/gi, '<\\/script').replace(/<!--/g, '<\\!--');
const html = readFileSync('site/index.html', 'utf8')
  .replace('<link rel="stylesheet" href="app.css">', () => '<style>' + css + '</style>')
  .replace('<link rel="icon" href="icon.png">', () => '<link rel="icon" href="' + icon + '">')
  .replace('<script src="app.js"></script>', () => '<script>' + home + '</script>');
if (!html.includes('<style>') || !html.includes(home.slice(0, 40))) throw new Error('site/index.html: placeholders not found');
writeFileSync('dist/routelark.html', html);
writeFileSync('dist/index.html', html); // для npm run serve: http://localhost:8888/
writeFileSync('dist/app.css', css); // тестовая страница demo.html берёт стили отсюда

const kb = (n) => (n / 1024).toFixed(0) + ' KB';
console.log('routelark.html  ' + kb(Buffer.byteLength(html)));
console.log('bookmarklet     ' + kb(bookmarklet.length) + ' (Chrome, Edge, Safari)');
