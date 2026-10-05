import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { HillCipher } from '../js/ciphers/hill.js';

describe('Hill Cipher', () => {
  const cipher = new HillCipher();

  describe('Text Mode 2x2 Matrix', () => {
    // Key matrix from plan:
    // [ 3  3 ]
    // [ 2  5 ]
    // det = 15 - 6 = 9. gcd(9, 26) = 1. Invertible!
    // det^-1 mod 26 = 3 (since 9*3 = 27 = 1 mod 26)
    // Inv matrix: 3 * [ 5, -3; -2, 3 ] = [ 15, -9; -6, 9 ] mod 26 = [ 15, 17; 20, 9 ]
    const matrix2x2 = [
      [3, 3],
      [2, 5]
    ];

    it('encrypts and decrypts 2x2 matrix block message', () => {
      // Plaintext: 'HELP'
      // H=7, E=4 -> [3*7 + 3*4, 2*7 + 5*4] = [21 + 12, 14 + 20] = [33, 34] mod 26 = [7, 8] -> 'HI'
      // L=11, P=15 -> [3*11 + 3*15, 2*11 + 5*15] = [33 + 45, 22 + 75] = [78, 97] mod 26 = [0, 19] -> 'AT'
      // 'HELP' -> 'HIAT'
      const ciphertext = cipher.encryptText('HELP', { matrix: matrix2x2 });
      assert.equal(ciphertext, 'HIAT');

      const decrypted = cipher.decryptText(ciphertext, { matrix: matrix2x2 });
      assert.equal(decrypted, 'HELP');
    });

    it('pads odd length text with X and decrypts successfully', () => {
      const plaintext = 'HEL'; // length 3 -> padded to 4: 'HELX'
      const ciphertext = cipher.encryptText(plaintext, { matrix: matrix2x2 });
      assert.equal(ciphertext.length, 4);

      const decrypted = cipher.decryptText(ciphertext, { matrix: matrix2x2, unpad: false });
      assert.equal(decrypted, 'HELX');
    });
  });

  describe('Text Mode 3x3 Matrix', () => {
    // Invertible 3x3 matrix mod 26:
    // [ 6, 24,  1 ]
    // [ 13, 16, 10 ]
    // [ 20, 17, 15 ]
    // det = 441 = 25 mod 26. gcd(25, 26) = 1.
    const matrix3x3 = [
      [6, 24, 1],
      [13, 16, 10],
      [20, 17, 15]
    ];

    it('encrypts and decrypts 3x3 matrix message round-trip', () => {
      const plaintext = 'ACT';
      const ciphertext = cipher.encryptText(plaintext, { matrix: matrix3x3 });
      const decrypted = cipher.decryptText(ciphertext, { matrix: matrix3x3 });
      assert.equal(decrypted, 'ACT');
    });
  });

  describe('Byte/Binary Mode', () => {
    // Matrix invertible modulo 256: det must be odd!
    // [ 3, 2 ]
    // [ 5, 7 ]
    // det = 21 - 10 = 11. gcd(11, 256) = 1.
    const matrixByte = [
      [3, 2],
      [5, 7]
    ];

    it('encrypts and decrypts Uint8Array round-trip mod 256 with PKCS#7 byte padding', () => {
      const originalBytes = new Uint8Array([10, 20, 30, 40, 50]); // odd length
      const encrypted = cipher.encryptBytes(originalBytes, { matrix: matrixByte });
      assert.notDeepEqual(encrypted, originalBytes);

      const decrypted = cipher.decryptBytes(encrypted, { matrix: matrixByte });
      assert.deepEqual(decrypted, originalBytes);
    });
  });
});
