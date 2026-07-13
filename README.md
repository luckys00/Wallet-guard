# 🛡️ WalletGuard — Ethereum Wallet Security Scanner

**WalletGuard** is a free, open-source Ethereum wallet security health scanner.  
Paste any wallet address and get an instant **security score (0–100)** with detailed findings.

> Built for [The DAO Security Fund](https://thedao.fund) — Gitcoin Round, July 2026

🌐 **Live Demo:** [wallet-guard.vercel.app](https://wallet-guard.vercel.app)

---

## 🔍 What It Checks

| Check | Description |
|---|---|
| 🔓 **Token Approvals** | Detects unlimited ERC-20 spend approvals |
| ☣️ **Malicious Contracts** | Flags interactions with known exploited contracts |
| ☠️ **Address Poisoning** | Detects lookalike zero-value poisoning attacks (last 30 days) |
| 🎨 **NFT Permissions** | Checks open `setApprovalForAll` permissions |
| 🔷 **ENS Identity** | Verifies on-chain identity via ENS name |
| 📊 **Activity Score** | Wallet activity and ETH balance |

---

## 🚀 Quick Start

```bash
git clone https://github.com/luckys00/Wallet-guard.git
cd Wallet-guard
npm install
```

Create a `.env` file:
```
VITE_ETHERSCAN_API_KEY=your_free_key_from_etherscan.io
```

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173)

---

## 🛠️ Tech Stack

- **React + Vite** — Frontend framework
- **ethers.js** — Ethereum address validation
- **Etherscan API** — On-chain data (free tier)
- **ENS API** — Identity lookup
- **Vercel** — Hosting (free)

---

## 🔒 Privacy

- ✅ **Read-only** — No wallet connection required
- ✅ **No private keys** — Only public address needed
- ✅ **No tracking** — No analytics or data storage
- ✅ **Open source** — Audit the code yourself

---

## 📄 License

MIT License — Free to use, fork, and contribute.

---

## 🤝 Contributing

PRs welcome! Open an issue to discuss new security checks.

Built with ❤️ for the Ethereum security community.
