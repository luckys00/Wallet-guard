import { useState } from 'react';
import { isAddress } from 'ethers';
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';
import { scanWallet } from './scanner';
import './index.css';

// ── ENS Resolver ─────────────────────────────────────────────────────────────
async function resolveENS(name) {
  try {
    const res = await fetch(`https://api.ensideas.com/ens/resolve/${name}`);
    if (!res.ok) return null;
    const data = await res.json();
    return data?.address || null;
  } catch {
    return null;
  }
}

// ── Score Colors ────────────────────────────────────────────────────────────
function getScoreColor(score) {
  if (score >= 80) return '#10b981';
  if (score >= 60) return '#f59e0b';
  if (score >= 40) return '#ef4444';
  return '#dc2626';
}

function getScoreTextClass(score) {
  if (score >= 80) return 'text-safe';
  if (score >= 60) return 'text-warning';
  return 'text-critical';
}

// ── Loading Steps ────────────────────────────────────────────────────────────
const STEPS = [
  'Validating address...',
  'Checking token approvals...',
  'Checking malicious contract interactions...',
  'Scanning for address poisoning attacks...',
  'Checking NFT permissions...',
  'Looking up ENS name...',
  'Checking wallet activity & balance...',
  'Checking token security (honeypot scan)...',
];

// ── Empty State ──────────────────────────────────────────────────────────────
function EmptyState({ onExample }) {
  const examples = [
    { label: 'Vitalik.eth', address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' },
    { label: 'Random Wallet', address: '0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503' },
  ];

  return (
    <div className="empty-state">
      <div className="empty-icon">🛡️</div>
      <h2 className="empty-title">Scan Your Ethereum Wallet</h2>
      <p className="empty-desc">
        Enter any Ethereum wallet address above to get an instant security health report
        — approvals, poisoning attempts, NFT risks and more.
      </p>

      <div style={{ marginBottom: '24px' }}>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
          Try an example:
        </p>
        <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap' }}>
          {examples.map((ex) => (
            <button
              key={ex.address}
              onClick={() => onExample(ex.address)}
              style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--border-light)',
                borderRadius: '8px',
                padding: '8px 16px',
                color: 'var(--accent-blue)',
                fontSize: '0.82rem',
                cursor: 'pointer',
                fontFamily: 'Inter, sans-serif',
              }}
            >
              {ex.label} ↗
            </button>
          ))}
        </div>
      </div>

      <div className="feature-grid">
        {[
          { emoji: '🔓', title: 'Token Approvals', desc: 'Detect unlimited spend approvals to risky contracts' },
          { emoji: '☠️', title: 'Poisoning Attacks', desc: 'Identify address poisoning attempts in last 30 days' },
          { emoji: '🎨', title: 'NFT Permissions', desc: 'Check open setApprovalForAll permissions' },
          { emoji: '🚨', title: 'Threat Intel', desc: 'Cross-check against GoPlus security databases' },
          { emoji: '🔷', title: 'ENS Lookup', desc: 'Verify on-chain identity via ENS name' },
          { emoji: '📊', title: 'Health Score', desc: 'Get a clear 0-100 security score with grade' },
        ].map((f) => (
          <div key={f.title} className="feature-card">
            <div className="feature-emoji">{f.emoji}</div>
            <div className="feature-title">{f.title}</div>
            <div className="feature-desc">{f.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Loading State ────────────────────────────────────────────────────────────
function LoadingState({ currentStep }) {
  return (
    <div className="loading-container">
      <div className="loading-spinner" />
      <p className="loading-text">Scanning wallet security...</p>
      <div className="loading-steps">
        {STEPS.map((step, i) => (
          <div
            key={step}
            className={`loading-step ${
              i < currentStep ? 'done' : i === currentStep ? 'active' : ''
            }`}
          >
            <span>{i < currentStep ? '✓' : i === currentStep ? '⟳' : '○'}</span>
            <span>{step}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Results View ─────────────────────────────────────────────────────────────
function ResultsView({ results, address }) {
  const { score, grade, label, issues, recommendations } = results;
  const color = getScoreColor(score);
  const textClass = getScoreTextClass(score);

  const shortAddr = `${address.slice(0, 8)}...${address.slice(-6)}`;

  const shareText = `My Ethereum wallet scored ${score}/100 on @WalletGuard 🛡️ — Grade: ${grade} (${label}). Check yours:`;
  const shareUrl = `https://walletguard.vercel.app/?address=${address}`;

  return (
    <div className="results-grid">

      {/* ── LEFT: Score Card ── */}
      <div className="score-card">
        <p className="score-card-title">Security Score</p>

        <div className="score-circle-wrapper">
          <CircularProgressbar
            value={score}
            styles={buildStyles({
              pathColor: color,
              trailColor: 'var(--border)',
              strokeLinecap: 'round',
            })}
            strokeWidth={8}
          />
          <div className="score-number">
            <span className={`score-value ${textClass}`}>{score}</span>
            <span className="score-max">/100</span>
          </div>
        </div>

        <div className={`score-grade ${textClass}`}>{grade}</div>
        <div className={`score-label ${textClass}`}>{label}</div>

        <div className="wallet-address-display">{shortAddr}</div>

        <div className="score-breakdown">
          <div className="breakdown-item">
            <div className="breakdown-count text-critical">{issues.critical.length}</div>
            <div className="breakdown-label">Critical</div>
          </div>
          <div className="breakdown-item">
            <div className="breakdown-count text-warning">{issues.warning.length}</div>
            <div className="breakdown-label">Warnings</div>
          </div>
          <div className="breakdown-item">
            <div className="breakdown-count text-safe">{issues.safe.length}</div>
            <div className="breakdown-label">Passed</div>
          </div>
        </div>
      </div>

      {/* ── RIGHT: Issues + Recommendations ── */}
      <div className="issues-panel">

        {/* Critical */}
        {issues.critical.length > 0 && (
          <div>
            <p className="issue-section-title text-critical">
              🔴 Critical Issues ({issues.critical.length})
            </p>
            {issues.critical.map((issue, i) => (
              <div key={i} className="issue-card critical" style={{ marginBottom: 8 }}>
                <span className="issue-icon">{issue.icon}</span>
                <div className="issue-content">
                  <div className="issue-title">{issue.title}</div>
                  <div className="issue-description">{issue.description}</div>
                  {issue.meta && <div className="issue-meta">{issue.meta}</div>}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Warnings */}
        {issues.warning.length > 0 && (
          <div>
            <p className="issue-section-title text-warning">
              🟡 Warnings ({issues.warning.length})
            </p>
            {issues.warning.map((issue, i) => (
              <div key={i} className="issue-card warning" style={{ marginBottom: 8 }}>
                <span className="issue-icon">{issue.icon}</span>
                <div className="issue-content">
                  <div className="issue-title">{issue.title}</div>
                  <div className="issue-description">{issue.description}</div>
                  {issue.meta && <div className="issue-meta">{issue.meta}</div>}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Safe */}
        {issues.safe.length > 0 && (
          <div>
            <p className="issue-section-title text-safe">
              🟢 Passed ({issues.safe.length})
            </p>
            {issues.safe.map((issue, i) => (
              <div key={i} className="issue-card safe" style={{ marginBottom: 8 }}>
                <span className="issue-icon">{issue.icon}</span>
                <div className="issue-content">
                  <div className="issue-title">{issue.title}</div>
                  <div className="issue-description">{issue.description}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Recommendations */}
        {recommendations.length > 0 && (
          <div className="recommendations">
            <p className="rec-title">💡 Recommendations</p>
            <ul className="rec-list">
              {recommendations.map((rec, i) => (
                <li key={i} className="rec-item">
                  <span className="rec-number">{i + 1}</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Share */}
        <div className="share-section">
          <a
            href={`https://twitter.com/intent/tweet?text=${encodeURIComponent(shareText)}&url=${encodeURIComponent(shareUrl)}`}
            target="_blank"
            rel="noreferrer"
            className="share-btn"
          >
            𝕏 Share on Twitter
          </a>
          <a
            href={`https://warpcast.com/~/compose?text=${encodeURIComponent(shareText + ' ' + shareUrl)}`}
            target="_blank"
            rel="noreferrer"
            className="share-btn"
          >
            🟣 Share on Farcaster
          </a>
          <button
            className="share-btn"
            onClick={() => navigator.clipboard.writeText(`${shareText} ${shareUrl}`)}
          >
            📋 Copy Link
          </button>
        </div>

      </div>
    </div>
  );
}

// ── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [inputAddress, setInputAddress] = useState('');
  const [scanning, setScanning] = useState(false);
  const [resolving, setResolving] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  const [scannedAddress, setScannedAddress] = useState('');

  const handleScan = async (addressOverride) => {
    let input = (addressOverride || inputAddress).trim();
    if (addressOverride) setInputAddress(addressOverride);

    if (!input) { setError('Please enter a wallet address or ENS name.'); return; }

    // If ENS name (contains a dot), resolve it first
    let address = input;
    if (!isAddress(input)) {
      if (input.includes('.eth') || input.includes('.')) {
        setResolving(true);
        setError('');
        const resolved = await resolveENS(input);
        setResolving(false);
        if (!resolved) {
          setError(`Could not resolve "${input}" — try the full 0x address instead.`);
          return;
        }
        address = resolved;
        setInputAddress(address); // show resolved address in input
      } else {
        setError('Invalid address. Enter a 0x address or ENS name (e.g. vitalik.eth).');
        return;
      }
    }

    setError('');
    setResults(null);
    setScanning(true);
    setCurrentStep(0);
    setScannedAddress(address);

    try {
      const result = await scanWallet(address, (_, step) => setCurrentStep(step));
      setResults(result);
    } catch (err) {
      console.error(err);
      setError('Scan failed. API may be rate-limited. Please wait a moment and try again.');
    } finally {
      setScanning(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleScan();
  };

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-inner">
          <div className="logo">
            <div className="logo-icon">🛡️</div>
            <span className="logo-text">Wallet<span>Guard</span></span>
          </div>
          <div className="header-badge">
            <div className="dot-pulse" />
            Ethereum Mainnet Live
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="hero">
        <div className="hero-tag">
          🔒 Free & Open Source · No Wallet Connection Required
        </div>
        <h1>Is Your Ethereum Wallet Secure?</h1>
        <p>
          Instant security health scan for any Ethereum address.
          Detects token approval risks, address poisoning, NFT exposures, and more.
        </p>

        <div className="search-container">
          <div className="search-box">
            <input
              className="search-input"
              placeholder="Enter wallet address (0x...) or ENS name"
              value={inputAddress}
              onChange={(e) => setInputAddress(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={scanning || resolving}
              spellCheck={false}
            />
            <button
              className="scan-btn"
              onClick={() => handleScan()}
              disabled={scanning || resolving}
            >
              {resolving ? '⟳ Resolving ENS...' : scanning ? '⟳ Scanning...' : '🔍 Scan Wallet'}
            </button>
          </div>
          {error && (
            <p style={{ color: 'var(--critical)', fontSize: '0.82rem', marginTop: 10, textAlign: 'left', paddingLeft: 4 }}>
              ⚠️ {error}
            </p>
          )}
          <p className="search-hint">
            🔒 Read-only scan · Your private keys are never needed
          </p>
        </div>
      </section>

      {/* Stats Bar */}
      <div className="stats-bar">
        {[
          { value: '8', label: 'Security Checks' },
          { value: '2', label: 'Threat Databases' },
          { value: 'Free', label: 'Always Free' },
          { value: 'Open', label: 'Source Code' },
        ].map((s) => (
          <div key={s.label} className="stat-item">
            <div className="stat-value">{s.value}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Main Content */}
      <main className="main">
        {scanning && <LoadingState currentStep={currentStep} />}
        {!scanning && !results && (
          <EmptyState onExample={(addr) => handleScan(addr)} />
        )}
        {!scanning && results && (
          <ResultsView results={results} address={scannedAddress} />
        )}
      </main>

      {/* Footer */}
      <footer className="footer">
        <p>
          WalletGuard is open source · Built for{' '}
          <a href="https://thedao.fund" target="_blank" rel="noreferrer">
            The DAO Security Fund
          </a>{' '}
          · Powered by{' '}
          <a href="https://etherscan.io" target="_blank" rel="noreferrer">Etherscan</a>
          {' & '}
          <a href="https://honeypot.is" target="_blank" rel="noreferrer">Honeypot.is</a>
        </p>
        <p style={{ marginTop: 6 }}>
          🛡️ Read-only · No wallet connection required · Your keys stay yours
        </p>
      </footer>
    </div>
  );
}
