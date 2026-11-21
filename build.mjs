// node build.mjs -> dist/routelark.html: a single file. Open it (even from disk) and drag the button to the bookmarks bar.
// The bookmarklet is self-contained: the whole UI and analysis are inside. No servers or hosting needed.
// For development dist/ also gets demo.html and demo/ (test page for npm run serve) and bookmarklet.txt.
// esbuild runs via the JS API: the bookmarklet (~700 KB) goes through define, and such an argument does not fit a Linux command line (E2BIG)
import { buildSync } from 'esbuild';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

// Chrome keeps bookmarks up to ~2 MB; Firefox truncates anything over 64 KB, so it is not supported
const LIMIT = 1.5e6;
const common = { bundle: true, minify: true, charset: 'utf8', target: 'es2020', legalComments: 'none', write: false, logLevel: 'error' };
const esbuild = (entry, o) => buildSync(Object.assign({ entryPoints: [entry] }, common, o)).outputFiles[0].text.trim();

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist', { recursive: true });
cpSync('site', 'dist', { recursive: true });

const css = esbuild('site/app.css');
const icon = 'data:image/png;base64,' + readFileSync('site/icon.png').toString('base64');
// The UI inside the bookmarklet: window, document and storages are replaced by the Routelark tab (see src/bookmarklet.js)
const inner = esbuild('src/app/main.js', { format: 'iife', define: { RL_BOOKMARKLET: '""' } });
const loader = esbuild('src/bookmarklet.js', { format: 'iife', define: { RL_CSS: JSON.stringify(css), RL_ICON: JSON.stringify(icon) } });
const code = '(()=>{var RL_RUN=function(window,document,location,history,localStorage,sessionStorage,setTimeout,clearTimeout){' + inner + '};' + loader + '})();';
// Safari understands lookbehind in regexes only since 16.4: one such regex breaks the whole bookmarklet
if (/\(\?<[=!]/.test(code)) throw new Error('lookbehind (?<= or (?<! in code: Safari before 16.4 fails to parse it');
// Encoding like encodeURI plus ? # and /. Safari (WebKit) parses a javascript: URL as a path and drops
// "/../" and "/./" together with the neighbouring code (e.g. before the regex /../g), so every / is encoded as %2F
const bookmarklet = 'javascript:' + encodeURI(code + 'void 0').replace(/[?#/]/g, encodeURIComponent);
if (/[/\s\\"<>`{}|^]/.test(bookmarklet.slice(11))) throw new Error('bookmarklet has characters Safari would change');
if (bookmarklet.length > LIMIT) throw new Error('bookmarklet is ' + bookmarklet.length + ' bytes, over ' + LIMIT);
writeFileSync('dist/bookmarklet.txt', bookmarklet);

// Install page: styles and code are inlined, no external files. "</script" inside the code is escaped
const home = esbuild('src/app/main.js', { format: 'iife', define: { RL_BOOKMARKLET: JSON.stringify(bookmarklet) } }).replace(/<\/script/gi, '<\\/script').replace(/<!--/g, '<\\!--');
const html = readFileSync('site/index.html', 'utf8')
  .replace('<link rel="stylesheet" href="app.css">', () => '<style>' + css + '</style>')
  .replace('<link rel="icon" href="icon.png">', () => '<link rel="icon" href="' + icon + '">')
  .replace('<script src="app.js"></script>', () => '<script>' + home + '</script>');
if (!html.includes('<style>') || !html.includes(home.slice(0, 40))) throw new Error('site/index.html: placeholders not found');
writeFileSync('dist/routelark.html', html);
writeFileSync('dist/index.html', html); // for npm run serve: http://localhost:8888/
writeFileSync('dist/app.css', css); // demo.html takes its styles from here

const kb = (n) => (n / 1024).toFixed(0) + ' KB';
console.log('routelark.html  ' + kb(Buffer.byteLength(html)));
console.log('bookmarklet     ' + kb(bookmarklet.length) + ' (Chrome, Edge, Safari)');
