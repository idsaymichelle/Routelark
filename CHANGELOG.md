# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## 1.0.0

First public release.

- The whole tool is one bookmarklet: no server, no hosting. It opens a tab next to the page and builds the interface in it. Install it from a single `routelark.html` file. Chrome, Edge and Safari; Firefox is not supported because it cuts bookmarks over 64 KB.
- Endpoints from JS, source maps, OpenAPI/Swagger files, Next.js build manifests and GraphQL operation names, with OWASP API Top 10 risk hints.
- Secrets (AWS, GitHub, GitLab, Stripe, Slack, OpenAI, Anthropic, Telegram, Discord and more), JWT details, cloud buckets.
- Stack with known advisories, an optional OSV.dev lookup and stack hints from cookie names.
- Security headers (read or pasted), cookies with an editor, storage, risky spots in client code.
- Files: a tree of every file the scan read and every original source from source maps, a viewer that formats minified JS and JSON, picture previews, search across all files in a Worker, links from findings to their lines.
- HTML checks: forms, hidden tokens, mixed content, SRI, `target=_blank`, inline handlers, HTML comments, error pages. Same-origin iframes are scanned too.
- Comparison with the previous run, including changed JS files, live page traffic, custom rules, `/regex/` search, a target wordlist.
- Export formats with preview, session files, import from HAR, Burp, ZAP, Caido and URL lists.
- The cookie editor finds a cookie's real domain before it edits or deletes it, also in browsers that do not report cookie attributes, and warns when another cookie with the same name remains.
- Secrets are shown in full on screen with copy buttons; exports stay masked by default. Settings and history live only while the tab is open; nothing is written to the site's storage.
- Small fixes: the loader alert follows the browser language and waits longer for a slow tab, the tab releases its observer and timer on the site after it closes, OSV and npm requests carry no Referer.
- Many more checks in the same passive model: 60+ secret formats with public-by-design keys marked, personal data with checksums, cloud and identity configs, AI in the frontend, supply-chain incidents of 2025–2026, skimmer signals, framework endpoints, new client-code checks (prototype pollution, path traversal, weak origin checks, trust bypasses, OAuth, token storage), new headers and cache signals, trackers and consent, `.well-known` files, mobile apps, infrastructure hints, realtime channels, a GraphQL schema draft, browser features, WASM, service workers, Web3, dev builds, build variables and obfuscation.
- OWASP Top 10 2025, CWE, ASVS 5.0 and WSTG v4.2 references; a Compliance tab; an attack surface map with authorization by host; program scope import; HackerOne, Bugcrowd and Intigriti report drafts; 15 more export formats; favicon hash and recon links on click.
- The same code finding in several bundles is one finding with every location, and stays the same after a deploy. Session files identify secrets and personal data by a hash of the masked value and its location, never of the value itself.
- Every launch starts in a Quiet mode with no requests of its own; a switch in the header turns on the Full scan.
- QA pass on OWASP Juice Shop (313 findings by 34 testers): masking leaks in custom rules, PEM bodies, HAR query tokens and report drafts closed; scanner lists keep to the scanned site; Stop no longer overwrites history; ReDoS-prone patterns rewritten; fewer false positives in secrets, headers, Web3, infra and code checks; more libraries in Stack; keyboard focus, contrast and screen-reader fixes; the overview total now counts site findings only (no static files or third-party hosts).
- The local test server shows a live request log at `/__log`, so you can see a scan from the site's side.
- English interface with a Russian switch (the default follows the browser), a step-by-step Safari guide.
