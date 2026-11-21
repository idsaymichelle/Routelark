// Dev builds, debug tooling and build-environment leaks. Pure functions; at runtime only reads global objects.
// Unverified markers (React banner, Next.js HMR routes, console global names) get low risk and a note.
const TEXT = [
  [/__VUE_PROD_DEVTOOLS__\s*[:=,]\s*(?:true|!0|"true")/, 'devbuild', 2, 'Vue DevTools enabled in production'],
  [/react-dom\.development|react\.development\.js/, 'devbuild', 1, 'React development build referenced'],
  [/\/_next\/webpack-hmr\b|__nextjs_original-stack-frame/, 'devbuild', 2, 'Next.js dev server endpoint in client code (marker not verified)'],
  [/\bng\.(?:probe|getComponent|getContext|getOwningComponent|applyChanges|markDirty)\s*\(/, 'devtools', 1, 'Angular debug API called in code'],
  [/\bGraphiQL\b|GraphQLPlayground|graphql-playground|SwaggerUIBundle|swagger-ui-dist/, 'devtools', 1, 'API console referenced in code'],
  [/__REDUX_DEVTOOLS_EXTENSION(?:_COMPOSE)?__/, 'devtools', 0, 'Redux DevTools hook in code']
];
const PUBLIC_OK = /PUBLISHABLE|PUBLIC_KEY|_URL$|_ENDPOINT$|_BASE$|_HOST$|_ID$|DSN$|AUTH_DOMAIN$|AUTH0_DOMAIN$|MEASUREMENT_ID$/i; // Sentry DSN and Firebase Auth domain are public by design
const SECRET_NAME = /SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN|ACCESS_KEY|API_?KEY|DSN|CREDENTIAL|AUTH/i;
const ENV_KV = /["']((?:NEXT_PUBLIC|VITE|REACT_APP)_[A-Z0-9_]+)["']\s*:/g;
const DEV_PATH = /\/Users\/[A-Za-z0-9._-]+\/|\/home\/[A-Za-z0-9._-]+\/|[A-Za-z]:\\{1,2}Users\\{1,2}[A-Za-z0-9._-]+\\{1,2}|webpack-internal:\/\/\//g;
const INTERNAL = /https?:\/\/[A-Za-z0-9.-]{1,120}\.(?:internal|corp|intranet|lan)(?::\d{1,5})?(?=[/"'\s]|$)|https?:\/\/[A-Za-z0-9.-]{0,120}(?:artifactory|nexus|verdaccio|jfrog)[A-Za-z0-9.-]{0,60}(?=[/"'\s]|$)/gi;

// Returns code findings { type, title, risk, at }
export function devbuildText(text, file) {
  const out = [], mapSrc = String(file).includes('#');
  for (const [re, type, risk, title] of TEXT) {
    const m = re.exec(text);
    if (!m || (type === 'devtools' && /\.(?:spec|test)\./.test(file))) continue;
    out.push({ type, title, risk: mapSrc && type === 'devbuild' ? 0 : risk, at: m.index });
  }
  const seen = new Set(); let m;
  ENV_KV.lastIndex = 0;
  while ((m = ENV_KV.exec(text)) && seen.size < 50) {
    const name = m[1]; if (seen.has(name) || PUBLIC_OK.test(name)) continue; seen.add(name);
    out.push(SECRET_NAME.test(name) ? { type: 'buildenv', title: 'Secret-named build variable in client code: ' + name, risk: 3, at: m.index } : { type: 'buildenv', title: 'Build variable in client code: ' + name, risk: 1, at: m.index });
  }
  for (const [re, cap, title] of [[DEV_PATH, 5, "Author's build path in code: "], [INTERNAL, 8, 'Internal host or registry in build output: ']]) {
    const s2 = new Set(); re.lastIndex = 0;
    while ((m = re.exec(text)) && s2.size < cap) if (!s2.has(m[0])) { s2.add(m[0]); out.push({ type: 'buildenv', title: title + m[0].slice(0, 80), risk: 1, at: m.index }); }
  }
  return out;
}
// Page global objects: only typeof, nothing is called
export function devtoolsFromRuntime(w) {
  const out = [], ty = (k) => { try { return typeof w[k]; } catch (e) { return 'undefined'; } };
  try { if (ty('ng') === 'object' && typeof w.ng.getComponent === 'function') out.push({ title: 'Angular debug API on the page (window.ng)', risk: 2, why: 'Dev-mode debug tools are reachable from the console: component state and services can be read' }); } catch (e) { /* foreign object */ }
  if (ty('GraphiQL') !== 'undefined') out.push({ title: 'GraphiQL console on the page', risk: 2, why: 'Interactive GraphQL console: check whether it targets production and whether introspection is open' });
  if (ty('GraphQLPlayground') !== 'undefined') out.push({ title: 'GraphQL Playground on the page', risk: 2, why: 'Interactive GraphQL console: check whether it targets production and whether introspection is open' });
  if (ty('SwaggerUIBundle') === 'function') out.push({ title: 'Swagger UI on the page', risk: 2, why: 'Lists API operations for a human to try: check whether it should be public' });
  return out;
}
