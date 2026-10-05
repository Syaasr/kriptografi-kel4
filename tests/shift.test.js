import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ShiftCipher } from '../js/ciphers/shift.js';

describe('Shift Cipher', () => {
  const cipher = new ShiftCipher();

  describe('Text Mode', () => {
    it('encrypts and decrypts with standard Caesar shift (k=3)', () => {
      const plaintext = 'ATTACKATDAWN';
      const key = 3;
      const ciphertext = cipher.encryptText(plaintext, { shift: key });
      assert.equal(ciphertext, 'DWWDFNDWGDZQ');

      const decrypted = cipher.decryptText(ciphertext, { shift: key });
      assert.equal(decrypted, 'ATTACKATDAWN');
    });

    it('handles negative and wrapping shifts (e.g. shift = -1 or shift = 29)', () => {
      const plaintext = 'HELLO';
      const ciphertext1 = cipher.encryptText(plaintext, { shift: -1 });
      assert.equal(ciphertext1, 'GDKKN');
      assert.equal(cipher.decryptText(ciphertext1, { shift: -1 }), 'HELLO');

      const ciphertext2 = cipher.encryptText(plaintext, { shift: 29 }); // 29 mod 26 = 3
      assert.equal(ciphertext2, 'KHOOR');
      assert.equal(cipher.decryptText(ciphertext2, { shift: 29 }), 'HELLO');
    });

    it('cleans non-alphabet characters during encryption as per spec', () => {
      const plaintext = 'Hello, World! 123';
      const ciphertext = cipher.encryptText(plaintext, { shift: 3 });
      assert.equal(ciphertext, 'KHOORZRUOG');
      assert.equal(cipher.decryptText(ciphertext, { shift: 3 }), 'HELLOWORLD');
    });

    it('throws validation error on invalid shift key', () => {
      assert.throws(() => cipher.encryptText('ABC', { shift: 'invalid' }));
      assert.throws(() => cipher.encryptText('ABC', { shift: null }));
    });
  });

  describe('Byte/Binary Mode', () => {
    it('encrypts and decrypts Uint8Array round-trip byte-by-byte mod 256', () => {
      const originalBytes = new Uint8Array([0, 1, 127, 254, 255, 42, 99]);
      const key = 17;
      const encrypted = cipher.encryptBytes(originalBytes, { shift: key });
      assert.notDeepEqual(encrypted, originalBytes);

      const decrypted = cipher.decryptBytes(encrypted, { shift: key });
      assert.deepEqual(decrypted, originalBytes);
    });
  });
});
