// E5: Web3 — адреса контрактов, chainId, подписи в духе дрейнеров, кошельковые SDK с CDN без точной версии.
// Намерение код не определяет: находка — повод проверить, что подписывает пользователь и кто получатель.
export function web3Findings(text, src) {
  const out = []; let m;
  // Только имя файла: «testnet.example» или «latest.js» в адресе — не тестовый файл
  if (/\.(?:test|spec|mock|fixture)\.|\.stories\./i.test(String(src).split(/[?#]/)[0].split('/').pop())) return out;
  const LIB_ADDR = new Set(['0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e', '0x' + '0'.repeat(40)]); // реестр ENS и нулевой адрес — из таблицы сетей ethers
  const WALLET = /wallet_addEthereumChain|wallet_switchEthereumChain|eth_chainId|switchChain|Web3Provider|BrowserProvider|ethereum\.request|sendTransaction|eth_requestAccounts/;
  const walletFile = WALLET.test(text);
  const add = (title, risk, why, at) => { if (!out.some((x) => x.title === title)) out.push({ title, risk, why, at }); };
  const seen = new Set(), CA = /\b0x[a-fA-F0-9]{40}\b/g;
  while ((m = CA.exec(text)) && seen.size < 50) { const a = m[0].toLowerCase(); if (seen.has(a) || LIB_ADDR.has(a) || !(walletFile || /abi|contract|Contract\(|chainId/.test(text.slice(Math.max(0, m.index - 600), m.index + 600)))) continue; seen.add(a); add('Contract ' + m[0], 0, ['Contract address near contract code'], m.index); }
  // chainId — только рядом с вызовом кошелька: иначе это таблица сетей библиотеки
  const CH = /\bchainId\s*[:=]\s*[`'"]?(0x[0-9a-fA-F]{1,8}|\d{1,8})\b/g; let n = 0;
  while ((m = CH.exec(text)) && n < 20) if (WALLET.test(text.slice(Math.max(0, m.index - 600), m.index + 600)) && ++n) add('chainId ' + m[1], 0, ['Blockchain network the page talks to'], m.index);
  const sig = [['setApprovalForAll(true)', /setApprovalForAll\s*\([^)]{0,120}\btrue\b/, 1], ['EIP-712 Permit', /primaryType\s*:\s*["']Permit["']/, 1], ['eth_signTypedData (not v4)', /["']eth_signTypedData(?!_v4)["']/, 1], ['very large permit deadline', /deadline\s*:\s*(?:MaxUint256|2\s*\*\*\s*256|0x[fF]{64}|\d{12,})/, 2], ['raw eth_sign', /["']eth_sign["']/, 2]];
  const hit = sig.filter(([, re]) => re.test(text)), score = hit.reduce((s, x) => s + x[2], 0);
  if (score >= 3) {
    const lib = /\b(?:ethers|viem|wagmi|@uniswap|@openzeppelin|permit2|@ethersproject)\b/.test(text);
    add('Signing code that matches a drainer pattern: manual review', lib ? 1 : 2, ['Signals: ' + hit.map((x) => x[0]).join(', '), 'Routelark does not decide intent; check what the user signs and who the spender is'].concat(lib ? ['Likely a bundled library'] : []), text.search(hit[0][1]));
  }
  const SDK = /https?:\/\/(?:cdn\.jsdelivr\.net\/npm|unpkg\.com)\/(@ledgerhq\/[\w.-]+|@walletconnect\/[\w.-]+|@web3-onboard\/[\w.-]+|@reown\/appkit[\w.-]*|@rainbow-me\/rainbowkit)(?:@([\w.-]+))?/g; // версия необязательна: без версии и @latest — тоже плавающая
  while ((m = SDK.exec(text))) if (!/^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(m[2] || '')) add('Wallet SDK from a CDN without an exact version: ' + m[1] + '@' + (m[2] || '(none)'), 1, ['The content can change under the same URL: pin an exact version and add SRI'], m.index);
  if ((m = /@ledgerhq\/connect-kit(-loader)?\b/.exec(text))) add('Ledger Connect Kit present', 1, [m[1] ? 'The loader fetches code from a URL at runtime that can change' : 'Check the lockfile for the exact version: versions 1.1.5 to 1.1.7 were reported malicious (December 2023)'], m.index);
  return out;
}
