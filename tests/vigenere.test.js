import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { VigenereCipher } from '../js/ciphers/vigenere.js';

describe('Vigenere Cipher', () => {
  const cipher = new VigenereCipher();

  describe('Text Mode', () => {
    it('matches exact assignment specification test case (ATTACKATDAWN + LEMON -> LXFOPVEFRNHR)', () => {
      const plaintext = 'ATTACKATDAWN';
      const key = 'LEMON';
      const ciphertext = cipher.encryptText(plaintext, { key });
      assert.equal(ciphertext, 'LXFOPVEFRNHR');

      const decrypted = cipher.decryptText(ciphertext, { key });
      assert.equal(decrypted, 'ATTACKATDAWN');
    });

    it('ignores and removes numbers, spaces, and punctuation in ciphertext as per spec', () => {
      const plaintext = 'Attack at dawn! 123';
      const key = 'lemon';
      const ciphertext = cipher.encryptText(plaintext, { key });
      assert.equal(ciphertext, 'LXFOPVEFRNHR');

      const decrypted = cipher.decryptText(ciphertext, { key });
      assert.equal(decrypted, 'ATTACKATDAWN');
    });

    it('handles key of any length and repeats key properly', () => {
      const plaintext = 'CRYPTO';
      const key = 'AB'; // A=0, B=1 -> C+0=C, R+1=S, Y+0=Y, P+1=Q, T+0=T, O+1=P -> CSYQTP
      const ciphertext = cipher.encryptText(plaintext, { key });
      assert.equal(ciphertext, 'CSYQTP');
      assert.equal(cipher.decryptText(ciphertext, { key }), 'CRYPTO');
    });

    it('throws validation error when key is empty or has no letters', () => {
      assert.throws(() => cipher.encryptText('ATTACK', { key: '' }));
      assert.throws(() => cipher.encryptText('ATTACK', { key: '123' }));
    });
  });

  describe('Byte/Binary Mode', () => {
    it('encrypts and decrypts Uint8Array round-trip mod 256 repeating key bytes', () => {
      const originalBytes = new Uint8Array([10, 20, 30, 250, 255, 0, 100]);
      const key = 'SECRETKEY';
      const encrypted = cipher.encryptBytes(originalBytes, { key });
      assert.notDeepEqual(encrypted, originalBytes);

      const decrypted = cipher.decryptBytes(encrypted, { key });
      assert.deepEqual(decrypted, originalBytes);
    });
  });
});
