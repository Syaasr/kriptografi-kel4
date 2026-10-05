import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { AffineCipher } from '../js/ciphers/affine.js';

describe('Affine Cipher', () => {
  const cipher = new AffineCipher();

  describe('Text Mode', () => {
    it('encrypts and decrypts with valid a and b (e.g. a=5, b=8)', () => {
      // P = 'AFFINE', A=0 -> (5*0 + 8) % 26 = 8 -> I
      // F=5 -> (5*5 + 8) % 26 = 33 % 26 = 7 -> H
      // I=8 -> (5*8 + 8) % 26 = 48 % 26 = 22 -> W
      // N=13 -> (5*13 + 8) % 26 = 73 % 26 = 21 -> V
      // E=4 -> (5*4 + 8) % 26 = 28 % 26 = 2 -> C
      // 'AFFINE' -> 'IHHWVC'
      const plaintext = 'AFFINE';
      const ciphertext = cipher.encryptText(plaintext, { a: 5, b: 8 });
      assert.equal(ciphertext, 'IHHWVC');

      const decrypted = cipher.decryptText(ciphertext, { a: 5, b: 8 });
      assert.equal(decrypted, 'AFFINE');
    });

    it('encrypts and decrypts longer message round-trip', () => {
      const plaintext = 'HELLO WORLD';
      const ciphertext = cipher.encryptText(plaintext, { a: 7, b: 3 });
      const decrypted = cipher.decryptText(ciphertext, { a: 7, b: 3 });
      assert.equal(decrypted, 'HELLOWORLD');
    });

    it('rejects invalid a (not coprime to 26)', () => {
      assert.throws(() => cipher.encryptText('HELLO', { a: 2, b: 3 }));
      assert.throws(() => cipher.encryptText('HELLO', { a: 13, b: 3 }));
      assert.throws(() => cipher.encryptText('HELLO', { a: 26, b: 3 }));
    });
  });

  describe('Byte/Binary Mode', () => {
    it('encrypts and decrypts Uint8Array round-trip mod 256 (where a is coprime to 256)', () => {
      const originalBytes = new Uint8Array([0, 10, 50, 100, 150, 200, 255]);
      // a must be coprime to 256 (i.e. odd number, e.g. 5, 7, 9)
      const encrypted = cipher.encryptBytes(originalBytes, { a: 5, b: 17 });
      assert.notDeepEqual(encrypted, originalBytes);

      const decrypted = cipher.decryptBytes(encrypted, { a: 5, b: 17 });
      assert.deepEqual(decrypted, originalBytes);
    });

    it('rejects even a for binary mode', () => {
      const bytes = new Uint8Array([1, 2, 3]);
      assert.throws(() => cipher.encryptBytes(bytes, { a: 4, b: 7 }));
    });
  });
});
