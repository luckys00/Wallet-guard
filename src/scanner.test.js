import { describe, it, expect } from 'vitest';
import { checkTokenApprovals, checkMaliciousInteractions } from './scanner';

describe('WalletGuard Scanner Logic Tests', () => {
  
  describe('checkTokenApprovals', () => {
    it('should correctly parse unlimited ERC-20 approvals', () => {
      // Mock Etherscan txList for approval (0x095ea7b3 is approve)
      // Spender is 0x0000000000007f150bd6f54c40a34d7c3d5e9f56 (Rari hack contract)
      // Amount is ffff... (unlimited)
      const mockTxList = [
        {
          input: '0x095ea7b30000000000000000000000000000000000007f150bd6f54c40a34d7c3d5e9f56ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          from: '0x1111111111111111111111111111111111111111',
          to: '0xdac17f958d2ee523a2206206994597c13d831ec7',
          isError: '0',
          timeStamp: '1620232628'
        }
      ];

      const address = '0x1111111111111111111111111111111111111111';
      const approvals = checkTokenApprovals(mockTxList, address);

      expect(approvals).toHaveLength(1);
      expect(approvals[0].isUnlimited).toBe(true);
      expect(approvals[0].spender.toLowerCase()).toBe('0x0000000000007f150bd6f54c40a34d7c3d5e9f56');
    });

    it('should ignore failed approval transactions', () => {
      const mockTxList = [
        {
          input: '0x095ea7b30000000000000000000000000000000000007f150bd6f54c40a34d7c3d5e9f56ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          from: '0x1111111111111111111111111111111111111111',
          to: '0xdac17f958d2ee523a2206206994597c13d831ec7',
          isError: '1', // failed transaction
          timeStamp: '1620232628'
        }
      ];

      const address = '0x1111111111111111111111111111111111111111';
      const approvals = checkTokenApprovals(mockTxList, address);

      expect(approvals).toHaveLength(0);
    });

    it('should guard against short/corrupt inputs', () => {
      const mockTxList = [
        {
          input: '0x095ea7b31234', // invalid short input
          from: '0x1111111111111111111111111111111111111111',
          to: '0xdac17f958d2ee523a2206206994597c13d831ec7',
          isError: '0',
          timeStamp: '1620232628'
        }
      ];

      const address = '0x1111111111111111111111111111111111111111';
      const approvals = checkTokenApprovals(mockTxList, address);

      expect(approvals).toHaveLength(0); // Safely filters out corrupt data
    });
  });

  describe('checkMaliciousInteractions', () => {
    it('should detect interactions with known bad contracts', () => {
      // Ronin Bridge hack contract address: 0x1a2a1c938ce3ec39b6d47113c7955baa9dd454f2
      const mockTxList = [
        {
          to: '0x1a2a1c938ce3ec39b6d47113c7955baa9dd454f2',
          isError: '0'
        }
      ];

      const maliciousCount = checkMaliciousInteractions(mockTxList);
      expect(maliciousCount).toBe(1);
    });

    it('should ignore regular transactions to good contracts', () => {
      const mockTxList = [
        {
          to: '0xdac17f958d2ee523a2206206994597c13d831ec7', // USDT
          isError: '0'
        }
      ];

      const maliciousCount = checkMaliciousInteractions(mockTxList);
      expect(maliciousCount).toBe(0);
    });
  });
});
