import { describe, it, expect } from 'vitest';
import { checkTokenApprovals, checkMaliciousInteractions, checkIsContract, checkAddressPoisoning } from './scanner';

describe('WalletGuard Scanner Logic (Offline Mocks)', () => {
  
  describe('checkTokenApprovals', () => {
    it('should correctly parse unlimited ERC-20 approvals', () => {
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

    it('should guard against short/corrupt inputs', () => {
      const mockTxList = [
        {
          input: '0x095ea7b31234',
          from: '0x1111111111111111111111111111111111111111',
          to: '0xdac17f958d2ee523a2206206994597c13d831ec7',
          isError: '0',
          timeStamp: '1620232628'
        }
      ];

      const address = '0x1111111111111111111111111111111111111111';
      const approvals = checkTokenApprovals(mockTxList, address);

      expect(approvals).toHaveLength(0);
    });
  });

  describe('checkMaliciousInteractions', () => {
    it('should detect interactions with known bad contracts', () => {
      const mockTxList = [
        {
          to: '0x1a2a1c938ce3ec39b6d47113c7955baa9dd454f2',
          isError: '0'
        }
      ];

      const maliciousCount = checkMaliciousInteractions(mockTxList);
      expect(maliciousCount).toBe(1);
    });
  });

  describe('checkAddressPoisoning', () => {
    it('should skip zero address checking to avoid false warnings', async () => {
      const count = await checkAddressPoisoning('0x0000000000000000000000000000000000000000');
      expect(count).toBe(0);
    });
  });
});
