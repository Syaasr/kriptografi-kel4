import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { OneTimePadCipher, generateRandomKey } from '../js/ciphers/otp.js';

describe('One-Time Pad Cipher', () => {
  const cipher = new OneTimePadCipher();

  describe('Text Mode', () => {
    it('encrypts and decrypts text using file key of sufficient length', () => {
      const plaintext = 'HELLO';
      const key = 'XMCKLMNOPQRSTUVWYZ'; // longer than HELLO
      const { ciphertext, usedLength, remainingLength } = cipher.encryptText(plaintext, { key });

      // H=7 + X=23 -> 30 mod 26 = 4 -> E
      // E=4 + M=12 -> 16 mod 26 = 16 -> Q
      // L=11 + C=2 -> 13 mod 26 = 13 -> N
      // L=11 + K=10 -> 21 mod 26 = 21 -> V
      // O=14 + L=11 -> 25 mod 26 = 25 -> Z
      assert.equal(ciphertext, 'EQNVZ');
      assert.equal(usedLength, 5);
      assert.equal(remainingLength, key.length - 5);

      const decrypted = cipher.decryptText(ciphertext, { key });
      assert.equal(decrypted.plaintext, 'HELLO');
      assert.equal(decrypted.usedLength, 5);
    });

    it('rejects key if shorter than message', () => {
      assert.throws(() => cipher.encryptText('TOOLONGMESSAGE', { key: 'SHORT' }));
    });

    it('generates random alphabet key of requested length', () => {
      const key = generateRandomKey(100);
      assert.equal(key.length, 100);
      assert.match(key, /^[A-Z]{100}$/);
    });
  });

  describe('Byte/Binary Mode', () => {
    it('encrypts and decrypts Uint8Array round-trip using byte key', () => {
      const originalBytes = new Uint8Array([10, 20, 30, 40, 50]);
      const keyBytes = new Uint8Array([99, 100, 101, 102, 103, 104, 105]); // longer than original

      const { cipherBytes, usedLength, remainingLength } = cipher.encryptBytes(originalBytes, { key: keyBytes });
      assert.equal(usedLength, 5);
      assert.equal(remainingLength, 2);
      assert.notDeepEqual(cipherBytes, originalBytes);

      const decrypted = cipher.decryptBytes(cipherBytes, { key: keyBytes });
      assert.deepEqual(decrypted.decryptedBytes, originalBytes);
    });
  });
});
