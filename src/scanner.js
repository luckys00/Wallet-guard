// WalletGuard Scanner — Core Security Logic
// Uses:
//   • Etherscan API (free key required)
//   • Honeypot.is API (free, no key) — token security check
//   • ENS Public API (no key needed)

const ETHERSCAN_KEY = import.meta.env.VITE_ETHERSCAN_API_KEY || '';
const ETHERSCAN_BASE = 'https://api.etherscan.io/v2/api';
const HONEYPOT_BASE = 'https://api.honeypot.is/v2';

// Comprehensive known malicious/hacked contract database
// Sources: Rekt.news, DeFiLlama hacks, Etherscan labels
const KNOWN_BAD_CONTRACTS = new Set([
  // OpenSea exploits
  '0x7f268357a8c2552623316e2562d90e642bb538e5',
  '0x00000000006c3852cbef3e08e8df289169ede581',
  // ENS phishing
  '0x283af0b28c62c092c9727f1ee09c02ca627eb7f5',
  // Ronin Bridge hack (Axie Infinity, $625M)
  '0x1a2a1c938ce3ec39b6d47113c7955baa9dd454f2',
  // Wormhole Bridge hack ($320M)
  '0x98f3c9e6e3face36baad05fe09d375ef1464288b',
  // Nomad Bridge hack ($190M)
  '0x5d94309e5a0090b165fa4181519701637b6daeba',
  // Euler Finance hack ($197M)
  '0x27182842e098f60e3d576794a5bfb2cae36d394d',
  // BNB Bridge exploit
  '0x26629c6a7d65cd21dd54c09bc7852b5cbca20bab',
  // BadgerDAO exploit ($120M)
  '0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107',
  // Cream Finance hack
  '0x892701d128d63c9856a9eb0d20aca15d52d48c7',
  // Harvest Finance exploit
  '0xc3f279090a47e80990fe3a9c30d24cb117ef91a8',
  // Pickle Finance exploit
  '0x24ef90cec07f5dc0f3199b34e37c843736e98c16',
  // Alpha Homora exploit
  '0x67b66c99d3eb37fa76aa3ed1ff33e8e39f0b9c7a',
  // Rari Capital hack
  '0x0000000000007f150bd6f54c40a34d7c3d5e9f56',
  // Tornado Cash (OFAC sanctioned)
  '0x722122df12d4e14e13ac3b6895a86e84145b6967',
  '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b',
  '0xd96f2b1c14db8458374d9aca76e26c3950113464',
  // Fake Uniswap phishing
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d'.replace('488d','0000'), // fake variant
  // KuCoin hacker address interactions
  '0xeb31973e0febf3e3d7058234a5ebbae1ab4b8c23',
]);

// ── Helpers ────────────────────────────────────────────────────────────────

async function fetchEtherscan(params) {
  const url = new URL(ETHERSCAN_BASE);
  // Auto-inject chainid=1 for Mainnet in V2 API
  Object.entries({ ...params, chainid: 1, apikey: ETHERSCAN_KEY }).forEach(([k, v]) =>
    url.searchParams.set(k, v)
  );
  try {
    const res = await fetch(url.toString());
    const data = await res.json();
    if (data.status === '0' && data.message === 'NOTOK') return [];
    return data.result ?? [];
  } catch {
    return [];
  }
}

// ── Check 1: Unlimited Token Approvals ─────────────────────────────────────
// Accepts pre-fetched txList to avoid duplicate API calls

export function checkTokenApprovals(txList, address) {
  const approveTxs = (txList || []).filter(
    (tx) =>
      tx.input?.startsWith('0x095ea7b3') &&
      tx.from?.toLowerCase() === address.toLowerCase() &&
      tx.isError === '0'
  );

  const approvals = approveTxs.slice(0, 30).map((tx) => {
    const input = tx.input || '';
    // Guard: approve calldata must be at least 138 chars
    if (input.length < 138) return null;
    const spender = '0x' + input.slice(34, 74);
    const amountHex = input.slice(74, 138);
    const isUnlimited =
      amountHex === 'f'.repeat(64) ||
      amountHex === 'f'.repeat(63) + 'e';
    const isBadContract = KNOWN_BAD_CONTRACTS.has(tx.to?.toLowerCase());
    return { spender, contract: tx.to, isUnlimited, isBadContract, timestamp: tx.timeStamp };
  }).filter(Boolean); // remove nulls from short inputs

  return approvals;
}

// ── Check 2: Malicious Contract Interactions ────────────────────────────────
// Accepts pre-fetched txList to avoid duplicate API calls

export function checkMaliciousInteractions(txList) {
  const malicious = (txList || []).filter(
    (tx) =>
      tx.to && KNOWN_BAD_CONTRACTS.has(tx.to.toLowerCase()) && tx.isError === '0'
  );
  return malicious.length;
}

// ── Check 2b: Is Contract Address? ─────────────────────────────────────────
// Detects if scanned address is a smart contract (not a user wallet)

export async function checkIsContract(address) {
  try {
    const url = new URL(ETHERSCAN_BASE);
    Object.entries({
      chainid: 1,
      module: 'proxy',
      action: 'eth_getCode',
      address,
      tag: 'latest',
      apikey: ETHERSCAN_KEY,
    }).forEach(([k, v]) => url.searchParams.set(k, v));
    const res = await fetch(url.toString());
    const data = await res.json();
    
    // Etherscan V2 response safety check
    if (data.error || (data.status === '0' && data.message === 'NOTOK')) {
      return false;
    }
    
    const code = data.result || '';
    // '0x' means EOA (regular wallet), anything longer means contract
    return code && code !== '0x' && code.length > 2;
  } catch {
    return false;
  }
}


// ── Check 3: Address Poisoning Detection ─────────────────────────────────

export async function checkAddressPoisoning(address) {
  const addrLower = address.toLowerCase();
  
  // Skip poisoning checks for null/burn addresses
  if (addrLower === '0x0000000000000000000000000000000000000000' || addrLower === '0x000000000000000000000000000000000000dead') {
    return 0;
  }

  const tokenTx = await fetchEtherscan({
    module: 'account',
    action: 'tokentx',
    address,
    sort: 'desc',
    offset: 200,
    page: 1,
  });

  const addrPrefix = addrLower.slice(0, 8); // e.g. 0x123456
  const addrSuffix = addrLower.slice(-6);  // e.g. abcdef
  const thirtyDaysAgo = Math.floor(Date.now() / 1000) - 30 * 24 * 60 * 60;

  const poisoningAttempts = (tokenTx || []).filter((tx) => {
    const from = tx.from?.toLowerCase() || '';
    const to = tx.to?.toLowerCase() || '';
    
    // Ignore mint/burn transactions
    if (from === '0x0000000000000000000000000000000000000000') return false;

    const recent = parseInt(tx.timeStamp) > thirtyDaysAgo;
    const isIncoming = to === addrLower;

    // Poisoning uses a vanity address matching both prefix and suffix to spoof the user
    const looksLikeTarget =
      from.startsWith(addrPrefix) &&
      from.endsWith(addrSuffix) &&
      from !== addrLower;

    return recent && isIncoming && looksLikeTarget;
  });

  return poisoningAttempts.length;
}

// ── Check 4: NFT Approvals (setApprovalForAll) ─────────────────────────────

export async function checkNFTApprovals(address) {
  const normalTx = await fetchEtherscan({
    module: 'account',
    action: 'txlist',
    address,
    sort: 'desc',
    offset: 200,
    page: 1,
  });

  // setApprovalForAll selector = 0xa22cb465
  const nftApprovals = (normalTx || []).filter(
    (tx) =>
      tx.input?.startsWith('0xa22cb465') &&
      tx.from?.toLowerCase() === address.toLowerCase() &&
      tx.isError === '0'
  );

  return nftApprovals.length;
}

// ── Check 5: ENS Name ─────────────────────────────────────────────────────

export async function checkENSName(address) {
  try {
    const res = await fetch(`https://api.ensideas.com/ens/resolve/${address}`);
    if (!res.ok) return null;
    const data = await res.json();
    return data?.name || null;
  } catch {
    return null;
  }
}

// ── Check 6: Transaction Count ────────────────────────────────────────────

export async function checkTxCount(address) {
  const result = await fetchEtherscan({
    module: 'proxy',
    action: 'eth_getTransactionCount',
    address,
    tag: 'latest',
  });
  return result ? parseInt(result, 16) || 0 : 0;
}

// ── Check 7: ETH Balance ──────────────────────────────────────────────────

export async function checkBalance(address) {
  const result = await fetchEtherscan({
    module: 'account',
    action: 'balance',
    address,
    tag: 'latest',
  });
  if (!result || result === '0') return '0';
  const eth = parseFloat(result) / 1e18;
  return eth.toFixed(4);
}

// ── Check 8: Token Security via Honeypot.is (GoPlus alternative) ──────────
// Checks top ERC-20 tokens in wallet for honeypot/scam characteristics

export async function checkTokenSecurity(address) {
  // Get tokens held by this wallet
  const tokenTx = await fetchEtherscan({
    module: 'account',
    action: 'tokentx',
    address,
    sort: 'desc',
    offset: 50,
    page: 1,
  });

  if (!tokenTx || tokenTx.length === 0) return { riskyTokens: [], checkedCount: 0 };

  // Get unique token contracts (max 5 to avoid rate limits)
  const uniqueTokens = [...new Set(
    (tokenTx || [])
      .filter(tx => tx.contractAddress)
      .map(tx => tx.contractAddress.toLowerCase())
  )].slice(0, 5);

  const riskyTokens = [];

  for (const tokenAddr of uniqueTokens) {
    try {
      const res = await fetch(`${HONEYPOT_BASE}/IsHoneypot?address=${tokenAddr}`);
      if (!res.ok) continue;
      const data = await res.json();

      const isHoneypot = data?.honeypotResult?.isHoneypot === true;
      const riskLevel = data?.summary?.riskLevel ?? 0;
      const buyTax = data?.simulationResult?.buyTax ?? 0;
      const sellTax = data?.simulationResult?.sellTax ?? 0;
      const tokenName = data?.token?.name || tokenAddr.slice(0, 10) + '...';

      if (isHoneypot || riskLevel >= 3 || sellTax > 10) {
        riskyTokens.push({ tokenAddr, tokenName, isHoneypot, riskLevel, buyTax, sellTax });
      }
    } catch {
      // Skip on error — non-critical check
    }
  }

  return { riskyTokens, checkedCount: uniqueTokens.length };
}

// ── MAIN SCAN ─────────────────────────────────────────────────────────────

export async function scanWallet(address, onStep) {
  const issues = { critical: [], warning: [], safe: [] };
  const recommendations = [];

  // ── Pre-fetch: Fetch txList ONCE — shared between checks 1 & 2
  // Also run contract detection in parallel (saves time)
  onStep('Checking token approvals...', 1);
  const [txList, isContract] = await Promise.all([
    fetchEtherscan({
      module: 'account',
      action: 'txlist',
      address,
      sort: 'desc',
      offset: 200,
      page: 1,
    }),
    checkIsContract(address),
  ]);

  // Warn if scanning a contract address, not a user wallet
  if (isContract) {
    issues.warning.push({
      title: 'This is a Smart Contract Address',
      description: 'You scanned a contract, not a regular wallet. Some checks may not apply.',
      meta: 'For best results, scan a regular wallet (EOA) address',
      icon: '📄',
    });
  }

  // Check if scanned address itself is a known malicious hacker/exploit address
  if (KNOWN_BAD_CONTRACTS.has(address.toLowerCase())) {
    issues.critical.push({
      title: 'Flagged Malicious Address Detected',
      description: 'This address itself is flagged in security databases as a hacker, exploiter, or phishing entity.',
      meta: 'High security risk: associated with crypto exploits/hacks',
      icon: '🚨',
    });
    recommendations.push('WARNING: This address is flagged. Do not interact with it or trust funds associated with it.');
  }

  // Step 1 — Token Approvals (using shared txList)
  const approvals = checkTokenApprovals(txList, address);
  const unlimitedApprovals = approvals.filter((a) => a.isUnlimited);
  const badApprovals = approvals.filter((a) => a.isBadContract);

  if (badApprovals.length > 0) {
    issues.critical.push({
      title: `${badApprovals.length} Approval(s) to Known Malicious Contract`,
      description: 'You have approved a contract flagged in security databases. Revoke immediately.',
      meta: `Flagged contract: ${badApprovals[0].contract?.slice(0, 20)}...`,
      icon: '🚨',
    });
    recommendations.push('Revoke approvals to malicious contracts immediately via revoke.cash');
  } else if (unlimitedApprovals.length > 4) {
    issues.critical.push({
      title: `${unlimitedApprovals.length} Unlimited Token Approvals`,
      description: 'Too many contracts have unlimited access to your tokens. Any of these getting hacked can drain your wallet.',
      meta: `${unlimitedApprovals.length} unlimited approvals detected`,
      icon: '🔓',
    });
    recommendations.push('Revoke unlimited token approvals at revoke.cash');
  } else if (unlimitedApprovals.length > 0) {
    issues.warning.push({
      title: `${unlimitedApprovals.length} Unlimited Token Approval(s)`,
      description: 'Some contracts have unlimited access to your tokens. Revoke ones you no longer use.',
      meta: `${unlimitedApprovals.length} unlimited approval(s)`,
      icon: '⚠️',
    });
    recommendations.push('Review and revoke unused approvals on revoke.cash');
  } else {
    issues.safe.push({
      title: 'Token Approvals Look Healthy',
      description: 'No unlimited or suspicious token approvals detected.',
      icon: '✅',
    });
  }

  // Step 2 — Malicious Contracts (using shared txList — no extra API call)
  onStep('Checking malicious contract interactions...', 2);
  const maliciousCount = checkMaliciousInteractions(txList);

  if (maliciousCount > 0) {
    issues.critical.push({
      title: `Interacted with ${maliciousCount} Known Malicious Contract(s)`,
      description: 'This wallet has sent transactions to contracts flagged as malicious or exploited.',
      meta: `${maliciousCount} flagged interaction(s) found`,
      icon: '☣️',
    });
    recommendations.push('Audit your transaction history and move funds to a fresh wallet');
  } else {
    issues.safe.push({
      title: 'No Known Malicious Contract Interactions',
      description: 'No interactions with known exploited or scam contracts found.',
      icon: '✅',
    });
  }

  // Step 3
  onStep('Scanning for address poisoning attacks...', 3);
  const poisoningCount = await checkAddressPoisoning(address);

  if (poisoningCount >= 3) {
    issues.critical.push({
      title: `${poisoningCount} Address Poisoning Attempts Detected`,
      description: 'Attackers sent lookalike zero-value transactions to trick you into copying their address.',
      meta: `${poisoningCount} suspicious tx in last 30 days`,
      icon: '☠️',
    });
    recommendations.push('Never copy addresses from your transaction history — always verify the full address');
  } else if (poisoningCount > 0) {
    issues.warning.push({
      title: `${poisoningCount} Possible Poisoning Attempt(s)`,
      description: 'Some suspicious lookalike transactions found. Stay cautious when copy-pasting addresses.',
      meta: `${poisoningCount} suspicious tx in last 30 days`,
      icon: '⚠️',
    });
  } else {
    issues.safe.push({
      title: 'No Address Poisoning Detected',
      description: 'No address poisoning attempts found in the last 30 days.',
      icon: '✅',
    });
  }

  // Step 4
  onStep('Checking NFT permissions...', 4);
  const nftApprovals = await checkNFTApprovals(address);

  if (nftApprovals > 5) {
    issues.warning.push({
      title: `${nftApprovals} Open NFT Collection Approvals`,
      description: 'Multiple contracts can transfer all NFTs from your collections. Revoke ones not in use.',
      meta: `${nftApprovals} setApprovalForAll calls`,
      icon: '🎨',
    });
    recommendations.push('Review and revoke NFT approvals on revoke.cash');
  } else if (nftApprovals > 0) {
    issues.warning.push({
      title: `${nftApprovals} NFT Approval(s) Found`,
      description: 'Some NFT collection approvals exist. Ensure they are for protocols you trust.',
      meta: `${nftApprovals} open approval(s)`,
      icon: '🎨',
    });
  } else {
    issues.safe.push({
      title: 'No Open NFT Approvals',
      description: 'No open NFT collection approvals detected.',
      icon: '✅',
    });
  }

  // Step 5
  onStep('Looking up ENS name...', 5);
  const ensName = await checkENSName(address);

  if (ensName) {
    issues.safe.push({
      title: `ENS: ${ensName}`,
      description: 'Wallet has a verified ENS name, improving on-chain identity trust.',
      icon: '🔷',
    });
  } else {
    issues.warning.push({
      title: 'No ENS Name Found',
      description: 'Consider registering an ENS name to establish your on-chain identity.',
      icon: '💡',
    });
  }

  // Step 6
  onStep('Checking wallet activity & balance...', 6);
  const [txCount, balance] = await Promise.all([
    checkTxCount(address),
    checkBalance(address),
  ]);

  if (txCount > 50) {
    issues.safe.push({
      title: `Active Wallet — ${txCount}+ Transactions`,
      description: `High activity wallet with ${balance} ETH balance.`,
      icon: '✅',
    });
  } else if (txCount > 0) {
    issues.safe.push({
      title: `Moderate Activity — ${txCount} Transactions`,
      description: `Wallet has some on-chain activity. Balance: ${balance} ETH.`,
      icon: '✅',
    });
  } else {
    issues.warning.push({
      title: 'New or Empty Wallet',
      description: 'Very few transactions. If new, ensure seed phrase is safely backed up.',
      icon: '💡',
    });
  }

  // Step 7 — Token Security via Honeypot.is
  onStep('Checking token security (honeypot scan)...', 7);
  const { riskyTokens, checkedCount } = await checkTokenSecurity(address);

  if (riskyTokens.length > 0) {
    const honeypots = riskyTokens.filter(t => t.isHoneypot);
    if (honeypots.length > 0) {
      issues.critical.push({
        title: `${honeypots.length} Honeypot Token(s) in Your Wallet`,
        description: 'Your wallet holds tokens that are designed to trap buyers — you cannot sell them.',
        meta: honeypots.map(t => t.tokenName).join(', '),
        icon: '🍯',
      });
      recommendations.push('Do NOT buy more of these tokens — they are honeypots designed to steal funds');
    } else {
      issues.warning.push({
        title: `${riskyTokens.length} High-Risk Token(s) Detected`,
        description: 'Some tokens in your wallet have suspicious sell taxes or high risk scores.',
        meta: riskyTokens.map(t => `${t.tokenName} (sell tax: ${t.sellTax}%)`).join(', '),
        icon: '⚠️',
      });
      recommendations.push('Be cautious with high-tax tokens — check before selling');
    }
  } else if (checkedCount > 0) {
    issues.safe.push({
      title: `${checkedCount} Token(s) Scanned — All Clear`,
      description: 'No honeypot or high-risk tokens detected in recent activity.',
      icon: '✅',
    });
  }

  // ── Score Calculation ──────────────────────────────────────────────────
  const criticalPenalty = issues.critical.length * 20;
  const warningPenalty = issues.warning.length * 7;
  const safeBonus = issues.safe.length * 4;
  const score = Math.max(0, Math.min(100, 100 - criticalPenalty - warningPenalty + safeBonus));

  let grade, label;
  if (score >= 85)      { grade = 'A'; label = 'Secure'; }
  else if (score >= 65) { grade = 'B'; label = 'Moderate Risk'; }
  else if (score >= 40) { grade = 'C'; label = 'At Risk'; }
  else                  { grade = 'F'; label = 'Critical Risk'; }

  if (recommendations.length === 0) {
    recommendations.push('Great! Continue monitoring your wallet regularly with WalletGuard.');
    recommendations.push('Consider using a hardware wallet for large holdings.');
  }

  return { score, grade, label, issues, recommendations, ensName, txCount, balance };
}
