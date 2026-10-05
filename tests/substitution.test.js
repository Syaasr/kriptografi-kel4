import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SubstitutionCipher } from '../js/ciphers/substitution.js';

describe('Substitution Cipher', () => {
  const cipher = new SubstitutionCipher();
  const sampleKey = 'QWERTYUIOPASDFGHJKLZXCVBNM';

  describe('Text Mode', () => {
    it('encrypts plaintext correctly with 26-letter key', () => {
      // A->Q, B->W, C->E, D->R, E->T, etc.
      const plaintext = 'ABCDEF';
      const ciphertext = cipher.encryptText(plaintext, { key: sampleKey });
      assert.equal(ciphertext, 'QWERTY');
    });

    it('decrypts ciphertext back to plaintext', () => {
      const plaintext = 'HELLOWORLD';
      const ciphertext = cipher.encryptText(plaintext, { key: sampleKey });
      const decrypted = cipher.decryptText(ciphertext, { key: sampleKey });
      assert.equal(decrypted, plaintext);
    });

    it('cleans non-alphabet characters during text encryption', () => {
      const plaintext = 'Attack at dawn! 123';
      const ciphertext = cipher.encryptText(plaintext, { key: sampleKey });
      const decrypted = cipher.decryptText(ciphertext, { key: sampleKey });
      assert.equal(decrypted, 'ATTACKATDAWN');
    });

    it('throws validation error when key is invalid', () => {
      assert.throws(() => cipher.encryptText('ABC', { key: 'TOO_SHORT' }));
      assert.throws(() => cipher.encryptText('ABC', { key: 'AAAAAAAAAAAAAAAAAAAAAAAAAA' }));
    });
  });

  describe('Byte/Binary Mode', () => {
    it('encrypts and decrypts Uint8Array round-trip using deterministic 256-byte substitution', () => {
      const originalBytes = new Uint8Array([0, 15, 77, 128, 200, 255, 42]);
      const encrypted = cipher.encryptBytes(originalBytes, { key: sampleKey });
      assert.notDeepEqual(encrypted, originalBytes);

      const decrypted = cipher.decryptBytes(encrypted, { key: sampleKey });
      assert.deepEqual(decrypted, originalBytes);
    });
  });
});
