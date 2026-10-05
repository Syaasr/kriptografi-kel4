import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PermutationCipher } from '../js/ciphers/permutation.js';

describe('Permutation Cipher', () => {
  const cipher = new PermutationCipher();
  const sampleKey = '3 1 4 2'; // 1-indexed: 3 1 4 2 (0-indexed: 2 0 3 1)

  describe('Text Mode', () => {
    it('encrypts and decrypts single block correctly', () => {
      // ABCD -> C A D B
      const ciphertext = cipher.encryptText('ABCD', { key: sampleKey });
      assert.equal(ciphertext, 'CADB');

      const decrypted = cipher.decryptText(ciphertext, { key: sampleKey });
      assert.equal(decrypted, 'ABCD');
    });

    it('encrypts multi-block message and handles padding with X', () => {
      // HELLOWORLD -> length 10. block size 4 -> pads to 12 with XX -> HELLOWORLDXX
      const ciphertext = cipher.encryptText('HELLOWORLD', { key: sampleKey });
      assert.equal(ciphertext.length, 12);

      const decrypted = cipher.decryptText(ciphertext, { key: sampleKey });
      assert.equal(decrypted, 'HELLOWORLDXX');
    });

    it('accepts both comma-separated and space-separated keys', () => {
      const c1 = cipher.encryptText('TEST', { key: '2 1 4 3' });
      const c2 = cipher.encryptText('TEST', { key: '2, 1, 4, 3' });
      assert.equal(c1, c2);
    });

    it('throws validation error on invalid permutation key', () => {
      assert.throws(() => cipher.encryptText('TEST', { key: '1 2 2 4' }));
      assert.throws(() => cipher.encryptText('TEST', { key: '' }));
    });
  });

  describe('Byte/Binary Mode', () => {
    it('encrypts and decrypts Uint8Array round-trip using PKCS#7 padding', () => {
      const originalBytes = new Uint8Array([5, 10, 15, 20, 25]); // length 5, block 4
      const encrypted = cipher.encryptBytes(originalBytes, { key: sampleKey });
      assert.notDeepEqual(encrypted, originalBytes);

      const decrypted = cipher.decryptBytes(encrypted, { key: sampleKey });
      assert.deepEqual(decrypted, originalBytes);
    });
  });
});
