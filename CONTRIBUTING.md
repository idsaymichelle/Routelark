# Contributing

Thanks for helping. Small, focused pull requests are the easiest to review.

## Setup

```bash
npm install
npm test
npm run build               # dist/routelark.html
node test/site/server.mjs   # http://localhost:8888/ with the test page /demo.html and test stands
```

Node 22 or newer. The only dependency is esbuild, used for the build.

To check a change in a browser, open `http://localhost:8888/__log` next to the test page: it lists every request the scan sent, as the site sees it. A change must not add requests in Quiet mode or any request that is not GET.

## Where things live

| Path | What |
| --- | --- |
| `src/core.js`, `src/core/` | Analysis without DOM: endpoints, secrets, stack, headers, exports. Tested in node. |
| `src/bookmarklet.js` | The bookmarklet entry: opens a blank tab and starts the interface in it. |
| `src/collector.js` | Reads the target page and downloads files by the safety rules. |
| `src/app/` | The interface and scan driver. It runs in the page's context with `window` and `document` pointing to the Routelark tab. |
| `src/i18n.js` | English source strings and the Russian dictionary. |
| `site/` | The `routelark.html` shell, styles and the test page. |
| `test/` | Tests and the local test server. |

## Rules of thumb

- **A detection change needs a test.** Add a short sample to `test/` that fails without your change. For a false positive, add the sample that must stay silent.
- **Keep the safety rules.** Read `SECURITY.md` before touching `src/core/scope.js` or `src/collector.js`.
- **Core produces English.** Strings stored in findings are English; translation happens at render time through `t()`. Add the Russian text to `src/i18n.js`; dynamic strings go to `RU_PATTERNS`.
- **No site data in `innerHTML`.** The interface builds DOM with the `h()` helper and `textContent`.
- **Mind the size.** The whole tool lives in the bookmarklet, and the build prints its size. Keep it well under 1 MB.
- **Use the tab's globals.** Interface code must use `window`, `document` and `localStorage` as globals (the build points them to the Routelark tab), and must not check types with `instanceof Node` or similar: the tab's DOM comes from another realm.
- **No new dependencies** unless there is no reasonable way without one.

## Reporting wrong findings

Use the "Wrong or missing finding" issue form and include a minimal sample. Replace real secrets and hosts with placeholders of the same shape.
