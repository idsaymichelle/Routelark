// Cloud and identity configs and AI in client code. Only reads already collected text, no requests.
// Each finding: { kind, title, risk, why: [...], at }, where at is the text position for the line and snippet.
const PH = /example|your[-_]?project|YOUR_|xxxx|placeholder/i; // for system prompt text
const PHV = /^(?:example|placeholder|x{4,}|your[-_][\w-]*)$/i; // for a value: the whole first label, not a substring (examplecorp-prod is a real name)

export function scanIdentity(text) {
  const out = [], seen = new Set();
  const add = (title, risk, why, at) => { if (seen.has(title) || PHV.test(title.slice(title.indexOf(': ') + 1).trim().replace(/^https?:\/\//, '').split(/[.\/:]/)[0])) return; seen.add(title); out.push({ kind: 'identity', title, risk, why: [why], at }); };
  let m;
  const firebase = /firebase/i.test(text);
  const db = /databaseURL\s*:\s*["'](https:\/\/[a-z0-9-]{1,63}(?:\.firebaseio\.com|(?:\.[a-z0-9-]{1,40})?\.firebasedatabase\.app))\/?["']/.exec(text);
  const pid = firebase && /projectId\s*:\s*["']([a-z0-9-]{6,30})["']/.exec(text);
  if (db || pid) add('Firebase config: ' + (pid ? pid[1] : db[1].replace(/^https:\/\//, '')), db ? 1 : 0, 'Check the Realtime Database, Firestore and Storage security rules: open rules let anyone read or write data', (db || pid).index);
  if (/supabase/i.test(text) && (m = /https:\/\/([a-z]{20})\.supabase\.co\b/.exec(text))) add('Supabase project: ' + m[1], 0, 'Check row-level security on every table the anon key can reach', m.index);
  const amplify = /aws_project_region|aws_cognito_identity_pool_id/.test(text);
  if ((m = /\b([a-z]{2}-[a-z]+-\d):([0-9a-f]{8})-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/.exec(text))) add('Cognito identity pool ' + m[1] + ':' + m[2] + '…', 1, 'Unauthenticated identities may get AWS credentials: check the role permissions of the identity pool', m.index);
  if ((m = /\b[a-z]{2}-[a-z]+-\d_[A-Za-z0-9]{9}\b/.exec(text))) add('Cognito user pool ' + m[0], 0, 'Check whether self sign-up is enabled and which attributes users can change themselves', m.index);
  if (amplify && (m = /aws_project_region/.exec(text))) add('Amplify config (aws-exports)', 1, 'Check the Cognito pools, AppSync and storage settings listed in the config', m.index);
  const auth0 = /auth0/i.test(text);
  if (auth0 && (m = /\b[a-z0-9-]{1,63}(?:\.[a-z]{2})?\.auth0\.com\b/.exec(text))) add('Auth0 tenant: ' + m[0], 0, 'Check the allowed callback URLs and which connections allow sign-up', m.index);
  if (auth0 && (m = /audience\s*:\s*["'](https?:\/\/[^"'\s]{4,200})["']/.exec(text))) add('Auth0 audience: ' + m[1], 0, 'The API that accepts these tokens: check its scopes', m.index);
  if ((m = /\/realms\/([\w.-]{1,64})\/protocol\/openid-connect\//.exec(text))) add('Keycloak realm: ' + m[1], 0, 'Check the redirect URIs and whether self-registration is enabled for the realm', m.index);
  if ((m = /\b[a-z0-9-]{1,63}\.(?:okta|oktapreview|okta-emea)\.com\b/.exec(text))) add('Okta org: ' + m[0], 0, 'Check the redirect URIs and self-service registration of the org', m.index);
  if ((auth0 || /\/realms\//.test(text)) && (m = /redirect_?uri["']?\s*[:=]\s*["'](https?:\/\/[^"'\s]{4,200})["']/i.exec(text) || /redirect_uri=(https?(?::|%3A)(?:\/|%2F){2}[^"'\s&]{4,200})/i.exec(text))) {
    let u = m[1]; try { u = decodeURIComponent(u); } catch (e) { /* keep as is */ }
    const loose = /^http:\/\/(?!(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\])(?=[:\/]|$))/.test(u) || u.includes('*'); // localhost.evil.io is not local
    add('Redirect URI: ' + u, loose ? 2 : 1, 'A loose redirect URI lets tokens go to another site: check the exact allow list on the server', m.index);
  }
  return out;
}

const PROVIDERS = /^(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|api\.cohere\.ai)$/;
// LiteLLM hints: numbers checked against GHSA; wording is "check the version", not "vulnerable"
const HINT_MCP = ['LiteLLM before 1.84.0: CVE-2026-59822, MCP auth bypass via OAuth2 passthrough (GHSA-7488-6r32-c95q). Check the version in your deployment',
  'LiteLLM 1.74.2 to before 1.83.7: CVE-2026-42271, command execution via MCP stdio test endpoints, needs a valid proxy key (GHSA-v4p8-mg3p-g94g). Check the version'];
const HINT_GW = HINT_MCP.concat('LiteLLM before 1.83.0: CVE-2026-35030 and CVE-2026-35029, JWT cache and privilege escalation. Check the version and whether JWT auth is on');

export function scanAi(text, hits, secrets, scanSecrets) {
  const out = [], seen = new Set();
  const add = (title, risk, why, at) => { if (seen.has(title)) return; seen.add(title); out.push({ kind: 'ai', title, risk, why, at }); };
  let m;
  const provKey = secrets.some((s) => s.type === 'openai' || s.type === 'anthropic');
  for (const s of secrets) if (s.type === 'openai' || s.type === 'anthropic') s.why.push('Key in client code: visible to every visitor');
  const hosts = new Set();
  for (const h of hits) { const hm = /^(?:https?|wss?):\/\/([^/:?#]+)/i.exec(h.raw || ''); if (hm) hosts.add(hm[1].toLowerCase()); }
  const provCall = [...hosts].filter((x) => PROVIDERS.test(x));
  if ((m = /dangerouslyAllowBrowser\s*:\s*(?:!0|true)/.exec(text))) {
    const who = /anthropic/i.test(text) ? ' (Anthropic)' : /openai/i.test(text) ? ' (OpenAI)' : '';
    add('Provider SDK allows browser use' + who, provKey || provCall.length ? 3 : who ? 2 : 1, ['The SDK is told to run in the browser, so its key is readable by every visitor: check where the key comes from'], m.index);
  }
  for (const x of provCall) add('Direct call to ' + x, 1, ['The page calls the model provider from the browser. Check whether the request carries a key the visitor can read'], text.indexOf(x));
  for (const x of hosts) if (!PROVIDERS.test(x) && /litellm|one-api|new-api|openwebui/.test(x)) add('LLM gateway: ' + x, 1, ['An LLM gateway is reachable from the page: check its authentication and spend limits'].concat(/litellm/.test(x) ? HINT_GW : []), text.indexOf(x));
  if (/\bmcp\b/i.test(text)) {
    const re = /["'`]((?:https?:\/\/[^"'`\s]{3,200})?\/[\w./-]{0,100}?\/(?:mcp|sse))["'`]/g;
    let n = 0;
    while ((m = re.exec(text)) && n++ < 10) add('MCP endpoint: ' + m[1], 1, ['An MCP server is reachable from the page: check its authentication and Origin validation'].concat(/litellm/i.test(text) ? HINT_MCP : []), m.index);
    if ((m = /@modelcontextprotocol\/sdk[^"'`]{0,60}/.exec(text))) add('MCP client in the page', 1, ['The page contains an MCP client: check which servers and tools it can reach'], m.index);
  }
  // OWASP LLM07: system prompt in client code
  const re = /(?:\b(?:system|systemPrompt|system_prompt|SYSTEM_PROMPT)["']?\s*[:=]\s*|role\s*:\s*["']system["']\s*,\s*content\s*:\s*)(["'`])((?:(?!\1)[^\\]|\\.){200,4000}?)\1/g;
  let n = 0;
  while ((m = re.exec(text)) && n++ < 5) {
    const body = m[2];
    if (body.includes('${') || PH.test(body.slice(0, 200))) continue;
    if (scanSecrets(body, '').length) add('System prompt contains a secret', 3, ['OWASP LLM07: secrets must not be in the system prompt. Check whether the key is still valid and rotate it'], m.index);
    else add('System prompt in client code (' + body.length + ' characters)', 1, ['OWASP LLM07: a system prompt is not a secret. Check that it does not contain internal rules, tool names or access checks the server relies on'], m.index);
  }
  return out;
}
