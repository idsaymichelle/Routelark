# Security

## Reporting a problem in Routelark

Please report it privately through **Security → Report a vulnerability** on the repository page (GitHub private vulnerability reporting). Do not open a public issue.

Include what you did, what happened, and a small sample if you can. Do not include real secrets or data from systems you do not own.

In scope:

- a page being able to make the bookmarklet request something outside the rules below;
- another site or window being able to read data from the Routelark tab, or run script in it;
- data leaving the browser other than the two documented optional lookups.

## Safety rules the code must keep

Routelark runs on other people's pages, so these rules are part of its contract. A change that breaks one is a security bug.

1. **GET only towards the site.** The bookmarklet sends only `GET` to the scanned site. The two optional lookups go elsewhere: OSV.dev (`POST` with package name and version) and registry.npmjs.org (`HEAD`).
2. **Service files only.** JS, source maps, `.LICENSE.txt` files named in a bundle, `robots.txt`, `sitemap*.xml`, `security.txt`, the `.well-known` files `openid-configuration`, `oauth-authorization-server`, `apple-app-site-association`, `assetlinks.json` and `webauthn`, `ads.txt`, `humans.txt`, `llms.txt`, the web manifest, `/.vite/manifest.json` (only when the page looks like a Vite build) and OpenAPI/Swagger files named in the code. OIDC discovery on another host is read only when you add that host. The favicon and file metadata are read only on a button press. API endpoints are never called; data routes such as `_payload.json` or `__data.json` are listed, never requested. Cache Storage and IndexedDB are listed by name only; `caches.open` is never called because it creates a cache.
3. **Scope.** The registrable domain of the page and its subdomains, plus hosts the user adds. Neighbouring subdomains on shared hosting are out of scope.
4. **No redirects.** A file that answers with a redirect is not followed.
5. **Deny paths.** Paths with `logout`, `signout`, `delete`, `remove`, `destroy`, `revoke` are skipped, also when percent-encoded.
6. **Gentle.** One request at a time, a pause of at least 300 ms, a request budget, 25 MB and 5 minutes per scan. A host is dropped on HTTP 429 or a WAF challenge page.
7. **The page is not changed.** No patched `fetch`/XHR, no writes to the page's storage, no styles or DOM. Cookies change only when the user edits them.
   Same-origin iframes are read from the page as it is; their scripts follow rule 2. Pictures in the Files tab are shown with a normal `<img>` from the address the page itself used.
8. **No cross-window messages.** The bookmarklet and the interface run in the same page and talk through a direct in-memory channel, so no other window can inject messages. The Routelark tab is a blank page of the target site: the site's own scripts could reach it, which gives them nothing beyond their own data.
9. **Data stays in the browser.** The only outside requests are optional: `package@version` to OSV.dev and scoped package names to registry.npmjs.org, sent without a Referer (the browser still adds an `Origin` header to the OSV `POST`). Settings and scan history live only in memory while the Routelark tab is open; nothing is written to the site's storage.

These rules are enforced in `src/core/scope.js` and `src/collector.js` and covered by `test/scope.test.mjs` and `test/collector.test.mjs`.

## Limits of the all-in-one bookmarklet

The whole tool runs inside the target page, so that page's own scripts share its environment. A hostile page can tamper with what Routelark sees and shows about that same page, or read the results, which describe only itself. On sites with a strict CSP, the optional OSV.dev and npm lookups and the background search worker may be blocked; Routelark then shows a note or searches in the page instead.

## Responsible use

Use Routelark only on systems you own or have written permission to test. Findings are leads for manual review, not confirmed vulnerabilities.
