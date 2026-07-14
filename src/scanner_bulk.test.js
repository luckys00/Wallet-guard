import { describe, it, expect } from 'vitest';
import { scanWallet } from './scanner';

// Helper to delay execution to respect Etherscan free tier rate limits (5 req/sec)
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

describe('Bulk Wallet Scanning and Score Coverage Verification', () => {
  
  const testAddresses = [
    {
      name: 'Vitalik Buterin (Upgraded EOA)',
      address: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045',
      expectedGrade: 'B'
    },
    {
      name: 'Null Address (System Burn Wallet)',
      address: '0x0000000000000000000000000000000000000000',
      expectedGrade: 'A' // Capped at A (0 warnings now, ENS/Empty are safe checks)
    },
    {
      name: 'Tornado Cash Router (Sanctioned Contract)',
      address: '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b',
      expectedGrade: 'F'
    },
    {
      name: 'KuCoin Hacker (Malicious EOA)',
      address: '0xeb31973e0febf3e3d7058234a5ebbae1ab4b8c23',
      expectedGrade: 'F'
    },
    {
      name: 'USDT Token (Standard ERC-20 Contract)',
      address: '0xdac17f958d2ee523a2206206994597c13d831ec7',
      expectedGrade: 'B' // Only 1 warning (smart contract warning), caps at B
    },
    {
      name: 'Machi Big Brother (Active Collector EOA)',
      address: '0x020ca66c30bec2c4fe3861a94e4db4a498a35872',
      expectedGrade: 'F'
    },
    {
      name: 'Empty Wallet (Inactive EOA)',
      address: '0x4838B106fcE96472698A96c14838B106FCE96472',
      expectedGrade: 'A' // Capped at A (0 warnings now, ENS/Empty are safe checks)
    },
    {
      name: 'BadgerDAO Exploit (Hacked Contract)',
      address: '0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107',
      expectedGrade: 'F'
    },
    {
      name: 'OpenSea Old Exploit (Malicious Contract)',
      address: '0x7f268357a8c2552623316e2562d90e642bb538e5',
      expectedGrade: 'F'
    },
    {
      name: 'Clean Trader EOA (Standard user wallet)',
      address: '0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503',
      expectedGrade: 'B' // Only 1 warning (honeypot check warning), caps at B
    }
  ];

  it('runs verification scans sequentially with rate limit delays', async () => {
    console.log('Starting sequential rate-limited bulk scanner audit for 10 addresses...');
    
    for (const target of testAddresses) {
      console.log(`\n--------------------------------------------`);
      console.log(`Target: ${target.name}`);
      console.log(`Address: ${target.address}`);
      
      const result = await scanWallet(target.address, () => {});
      
      console.log(`Scan Results:`);
      console.log(`  - Score: ${result.score}/100`);
      console.log(`  - Grade: ${result.grade} (${result.label})`);
      console.log(`  - Balance: ${result.balance} ETH`);
      console.log(`  - Tx Count: ${result.txCount}`);
      console.log(`  - Critical Alerts: ${result.issues.critical.length}`);
      result.issues.critical.forEach(i => console.log(`      * [CRITICAL] ${i.title}`));
      console.log(`  - Warnings: ${result.issues.warning.length}`);
      result.issues.warning.forEach(i => console.log(`      * [WARNING] ${i.title}`));
      
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
      expect(result.grade).toBe(target.expectedGrade);

      // Wait 800ms between scans to guarantee Etherscan rate limits are NOT exceeded
      await sleep(800);
    }
  }, 240000); // 240s sequential timeout
});
