// Only entries checked against OSV (api.osv.dev/v1/vulns/<id>), data as of 2026-11. Everything else goes through the OSV check.
export const ADVISORIES_DATE = '2026-11';
const A = [
  ['jQuery', '<3.5.0', 'CVE-2020-11022', 'XSS when passing HTML to .html()/.append()', '3.5.0', 2],
  ['jQuery', '<3.5.0', 'CVE-2020-11023', 'XSS via <option> elements', '3.5.0', 2],
  ['Lodash', '<4.17.21', 'CVE-2021-23337', 'Command injection via template', '4.17.21', 3],
  ['Axios', '<0.21.2', 'CVE-2021-3749', 'ReDoS in trim', '0.21.2', 2],
  ['Moment.js', '>=2.18.0 <2.29.4', 'CVE-2022-31129', 'ReDoS when parsing RFC 2822', '2.29.4', 3],
  ['Bootstrap', '<3.4.1', 'CVE-2019-8331', 'XSS in the tooltip/popover data-template', '3.4.1', 2],
  ['Bootstrap', '>=4.3.0 <4.3.1', 'CVE-2019-8331', 'XSS in the tooltip/popover data-template', '4.3.1', 2],
  ['Next.js', '>=10.0.0 <12.1.0', 'CVE-2022-23646', 'Image Optimization API vulnerability', '12.1.0', 2],
  ['Handlebars', '<4.7.7', 'CVE-2021-23369', 'Code execution when compiling a template', '4.7.7', 3],
  // Every id checked against OSV or GitHub Advisory (2026-11-17). Empty fixed version means that branch has no fix
  ['Next.js', '>=16.0.0 <16.2.11', 'CVE-2026-64642', 'Middleware/proxy auth bypass (App Router, Turbopack, one i18n locale)', '16.2.11', 3],
  ['Next.js', '>=12.2.0 <15.5.16', 'CVE-2026-44573', 'Middleware bypass on Pages Router i18n data route exposes SSR JSON', '15.5.16', 3],
  ['Next.js', '>=16.0.0 <16.2.5', 'CVE-2026-44573', 'Middleware bypass on Pages Router i18n data route exposes SSR JSON', '16.2.5', 3],
  ['Next.js', '>=15.2.0 <15.5.16', 'CVE-2026-44575', 'Middleware bypass via segment-prefetch (.rsc) URLs', '15.5.16', 3],
  ['Next.js', '>=16.0.0 <16.2.5', 'CVE-2026-44575', 'Middleware bypass via segment-prefetch (.rsc) URLs', '16.2.5', 3],
  ['Next.js', '>=15.4.0 <15.5.16', 'CVE-2026-44574', 'Middleware bypass via dynamic route parameter injection', '15.5.16', 3],
  ['Next.js', '>=16.0.0 <16.2.5', 'CVE-2026-44574', 'Middleware bypass via dynamic route parameter injection', '16.2.5', 3],
  ['Next.js', '>=10.0.0 <15.5.24', 'GHSA-2xp9-vwfh-vxw4', 'Unauthenticated RCE in Image Optimization API (AVIF)', '15.5.24', 4],
  ['Next.js', '>=16.0.0 <16.3.3', 'GHSA-2xp9-vwfh-vxw4', 'Unauthenticated RCE in Image Optimization API (AVIF)', '16.3.3', 4],
  ['Next.js', '>=10.0.0 <15.5.28', 'GHSA-2464-fhr4-w9xw', 'Unauthenticated RCE in Image Optimization API (SVG)', '15.5.28', 4],
  ['Next.js', '>=16.0.0 <16.4.1', 'GHSA-2464-fhr4-w9xw', 'Unauthenticated RCE in Image Optimization API (SVG)', '16.4.1', 4],
  ['Next.js', '>=13.4.0 <15.5.24', 'CVE-2026-75604', 'Unauthenticated RCE on Windows-hosted servers', '15.5.24', 4],
  ['Next.js', '>=16.0.0 <16.3.3', 'CVE-2026-75604', 'Unauthenticated RCE on Windows-hosted servers', '16.3.3', 4],
  ['Next.js', '>=16.0.0 <16.4.1', 'GHSA-673q-mjm6-r5xr', 'Unauthenticated RCE in use cache functions returning typed arrays', '16.4.1', 4],
  ['Next.js', '>=16.2.0 <16.3.6', 'GHSA-vcvr-r3jv-pc5j', 'RCE in next/og ImageResponse', '16.3.6', 4],
  ['Angular', '>=17.0.0 <=18.2.14', 'CVE-2026-32635', 'i18n attribute bindings bypass the sanitizer (no fixed line)', '', 3],
  ['Angular', '>=19.0.0 <19.2.20', 'CVE-2026-32635', 'i18n attribute bindings bypass the sanitizer', '19.2.20', 3],
  ['Angular', '>=20.0.0 <20.3.18', 'CVE-2026-32635', 'i18n attribute bindings bypass the sanitizer', '20.3.18', 3],
  ['Angular', '>=21.0.0 <21.2.4', 'CVE-2026-32635', 'i18n attribute bindings bypass the sanitizer', '21.2.4', 3],
  ['Angular', '<=18.2.14', 'CVE-2026-22610', 'Unsanitized SVG script attributes (no fixed line)', '', 3],
  ['Angular', '>=19.0.0 <19.2.18', 'CVE-2026-22610', 'Unsanitized SVG script attributes', '19.2.18', 3],
  ['Angular', '>=20.0.0 <20.3.16', 'CVE-2026-22610', 'Unsanitized SVG script attributes', '20.3.16', 3],
  ['Angular', '>=21.0.0 <21.0.7', 'CVE-2026-22610', 'Unsanitized SVG script attributes', '21.0.7', 3],
  ['Angular', '<=18.2.14', 'CVE-2026-50557', 'Namespaced svg:script and attribute sanitization bypass (no fixed line)', '', 2],
  ['Angular', '>=19.0.0 <19.2.22', 'CVE-2026-50557', 'Namespaced svg:script and attribute sanitization bypass', '19.2.22', 2],
  ['Angular', '>=20.0.0 <20.3.22', 'CVE-2026-50557', 'Namespaced svg:script and attribute sanitization bypass', '20.3.22', 2],
  ['Angular', '>=21.0.0 <21.2.15', 'CVE-2026-50557', 'Namespaced svg:script and attribute sanitization bypass', '21.2.15', 2],
  ['Angular', '<=19.2.25', 'CVE-2026-54265', 'Two-way binding sanitization bypass on sensitive DOM properties', '', 2],
  ['Angular', '>=20.0.0 <20.3.25', 'CVE-2026-54265', 'Two-way binding sanitization bypass on sensitive DOM properties', '20.3.25', 2],
  ['Angular', '>=21.0.0 <21.2.17', 'CVE-2026-54265', 'Two-way binding sanitization bypass on sensitive DOM properties', '21.2.17', 2],
  ['Angular', '>=22.0.0 <22.0.1', 'CVE-2026-54265', 'Two-way binding sanitization bypass on sensitive DOM properties', '22.0.1', 2],
  ['Angular', '<=19.2.25', 'CVE-2026-69151', 'XSS via i18n on event-handler attributes (translation file)', '', 3],
  ['Angular', '>=20.0.0 <20.3.27', 'CVE-2026-69151', 'XSS via i18n on event-handler attributes (translation file)', '20.3.27', 3],
  ['Angular', '>=21.0.0 <21.2.19', 'CVE-2026-69151', 'XSS via i18n on event-handler attributes (translation file)', '21.2.19', 3],
  ['Angular', '>=22.0.0 <22.0.1', 'CVE-2026-69151', 'XSS via i18n on event-handler attributes (translation file)', '22.0.1', 3],
  ['Angular', '<=19.2.25', 'CVE-2026-88057', 'Directive host bindings skip the sanitizer for the wrong context', '', 2],
  ['Angular', '>=20.0.0 <20.3.28', 'CVE-2026-88057', 'Directive host bindings skip the sanitizer for the wrong context', '20.3.28', 2],
  ['Angular', '>=21.0.0 <21.2.20', 'CVE-2026-88057', 'Directive host bindings skip the sanitizer for the wrong context', '21.2.20', 2],
  ['Angular', '>=22.0.0 <22.1.0', 'CVE-2026-88057', 'Directive host bindings skip the sanitizer for the wrong context', '22.1.0', 2],
  ['Nuxt', '>=4.0.0 <4.4.7', 'CVE-2026-53722', 'NuxtLink javascript: or vbscript: href XSS', '4.4.7', 2],
  ['Nuxt', '>=3.0.0 <3.21.7', 'CVE-2026-53722', 'NuxtLink javascript: or vbscript: href XSS', '3.21.7', 2],
  ['Nuxt', '<4.6.0', 'CVE-2026-114130', 'Incomplete NuxtLink fix: control character before javascript: URL', '4.6.0', 1],
  ['Nuxt', '>=4.0.0 <4.4.7', 'CVE-2026-56317', 'XSS via NoScript slot content in head components', '4.4.7', 1],
  ['Nuxt', '>=3.0.0 <3.21.7', 'CVE-2026-56317', 'XSS via NoScript slot content in head components', '3.21.7', 1],
  ['Nuxt', '>=4.4.7 <4.5.1', 'CVE-2026-71315', 'Route rules dropped on mixed-case paths, appMiddleware auth gates skipped', '4.5.1', 3],
  ['Nuxt', '>=3.21.7 <3.21.10', 'CVE-2026-71315', 'Route rules dropped on mixed-case paths, appMiddleware auth gates skipped', '3.21.10', 3],
  ['Nuxt', '>=4.0.0 <4.6.4', 'CVE-2026-128071', 'Encoded %2F in path bypasses server middleware and route rules', '4.6.4', 3],
  ['Nuxt', '>=3.0.0 <=3.21.11', 'CVE-2026-128071', 'Encoded %2F in path bypasses server middleware and route rules', '', 3],
  ['Nuxt', '>=4.0.0 <4.6.2', 'CVE-2026-114132', 'Route rules skipped for case-variant paths (redirect, headers, proxy, ssr)', '4.6.2', 2],
  ['Nuxt', '>=3.0.0 <=3.21.11', 'CVE-2026-114132', 'Route rules skipped for case-variant paths (redirect, headers, proxy, ssr)', '', 2],
  ['Nuxt', '>=4.0.0 <4.5.1', 'CVE-2026-71320', 'Server-side RCE via template injection in island props', '4.5.1', 4],
  ['Nuxt', '>=3.4.0 <3.21.10', 'CVE-2026-71320', 'Server-side RCE via template injection in island props', '3.21.10', 4],
  ['DOMPurify', '<3.3.2', 'CVE-2026-65914', 'Mutation XSS when sanitized HTML is re-inserted into xmp, noscript, iframe, noembed', '3.3.2', 2],
  ['DOMPurify', '>=3.1.3 <3.3.2', 'CVE-2026-0540', 'Rawtext elements missing from SAFE_FOR_XML: attribute sanitization bypass', '3.3.2', 2],
  ['DOMPurify', '>=2.5.3 <2.5.9', 'CVE-2026-0540', 'Rawtext elements missing from SAFE_FOR_XML: attribute sanitization bypass', '2.5.9', 2],
  ['DOMPurify', '>=3.0.1 <3.4.0', 'CVE-2026-41238', 'Prototype pollution to XSS bypass via CUSTOM_ELEMENT_HANDLING fallback', '3.4.0', 2],
  ['DOMPurify', '>=3.4.4 <3.4.5', 'CVE-2026-47423', 'XSS via selectedcontent re-clone (default config)', '3.4.5', 3],
  ['DOMPurify', '<3.4.7', 'CVE-2026-49978', 'IN_PLACE bypass via attached shadow root inside template content', '3.4.7', 2],
  ['DOMPurify', '<3.4.17', 'CVE-2026-116803', 'IN_PLACE hook removing a parent or sibling leaves executable detached subtree', '3.4.17', 3]
];
function cmp(a, b) {
  a = String(a).split('.'); b = String(b).split('.');
  for (let i = 0; i < 3; i++) { const x = parseInt(a[i] || '0', 10) || 0, y = parseInt(b[i] || '0', 10) || 0; if (x !== y) return x < y ? -1 : 1; }
  return 0;
}
function inRange(v, range) {
  return range.split(' ').every((r) => {
    const m = /^(>=|<=|<|>)?([\d.]+)$/.exec(r); if (!m) return false;
    const c = cmp(v, m[2]), op = m[1] || '=';
    return op === '<' ? c < 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : op === '>=' ? c >= 0 : c === 0;
  });
}
export function matchAdvisories(name, version) {
  if (!version || !/^\d+\.\d+/.test(version)) return [];
  return A.filter((a) => a[0] === name && inRange(version, a[1])).map((a) => ({ id: a[2], summary: a[3], fixed: a[4], risk: a[5] }));
}
const NPM = { jQuery: 'jquery', Lodash: 'lodash', Underscore: 'underscore', AngularJS: 'angular', Angular: '@angular/core', Vue: 'vue', React: 'react', 'Moment.js': 'moment', DOMPurify: 'dompurify', Nuxt: 'nuxt', 'Next.js': 'next', Handlebars: 'handlebars', Axios: 'axios', Bootstrap: 'bootstrap' };
export const npmName = (name) => NPM[name] || null;
export function osvQuery(name, version) {
  // Name from the stack table or an npm dependency name already (lowercase, as in the registry)
  const pkg = NPM[name] || (/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name) ? name : null);
  if (!pkg || !version || !/^\d+\.\d+/.test(version)) return null;
  return { url: 'https://api.osv.dev/v1/query', body: { package: { name: pkg, ecosystem: 'npm' }, version } };
}
export const osvLink = (name) => NPM[name] ? 'https://osv.dev/list?ecosystem=npm&q=' + encodeURIComponent(NPM[name]) : null;
