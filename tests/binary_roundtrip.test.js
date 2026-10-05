import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ShiftCipher } from '../js/ciphers/shift.js';
import { SubstitutionCipher } from '../js/ciphers/substitution.js';
import { AffineCipher } from '../js/ciphers/affine.js';
import { VigenereCipher } from '../js/ciphers/vigenere.js';
import { HillCipher } from '../js/ciphers/hill.js';
import { PermutationCipher } from '../js/ciphers/permutation.js';
import { OneTimePadCipher } from '../js/ciphers/otp.js';
import { packEncryptedContainer, unpackEncryptedContainer } from '../js/utils/file.js';

describe('Binary File Round-Trip Integrity (All 7 Ciphers)', () => {
  // Create a realistic binary payload (representing an image or executable header + bytes)
  const sampleBinary = new Uint8Array([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG magic
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x5C, 0x72, 0xA8,
    0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02, 0x7F, 0x80
  ]);
  const filename = 'sample_image.png';

  it('Shift Cipher preserves binary bytes with container round-trip', () => {
    const cipher = new ShiftCipher();
    const enc = cipher.encryptBytes(sampleBinary, { shift: 17 });
    const container = packEncryptedContainer(cipher.id, filename, enc);

    const unpacked = unpackEncryptedContainer(container);
    assert.equal(unpacked.originalFilename, filename);
    const dec = cipher.decryptBytes(unpacked.payloadBytes, { shift: 17 });
    assert.deepEqual(dec, sampleBinary);
  });

  it('Substitution Cipher preserves binary bytes with container round-trip', () => {
    const cipher = new SubstitutionCipher();
    const key = 'QWERTYUIOPASDFGHJKLZXCVBNM';
    const enc = cipher.encryptBytes(sampleBinary, { key });
    const container = packEncryptedContainer(cipher.id, filename, enc);

    const unpacked = unpackEncryptedContainer(container);
    assert.equal(unpacked.originalFilename, filename);
    const dec = cipher.decryptBytes(unpacked.payloadBytes, { key });
    assert.deepEqual(dec, sampleBinary);
  });

  it('Affine Cipher preserves binary bytes with container round-trip', () => {
    const cipher = new AffineCipher();
    const enc = cipher.encryptBytes(sampleBinary, { a: 7, b: 31 });
    const container = packEncryptedContainer(cipher.id, filename, enc);

    const unpacked = unpackEncryptedContainer(container);
    assert.equal(unpacked.originalFilename, filename);
    const dec = cipher.decryptBytes(unpacked.payloadBytes, { a: 7, b: 31 });
    assert.deepEqual(dec, sampleBinary);
  });

  it('Vigenere Cipher preserves binary bytes with container round-trip', () => {
    const cipher = new VigenereCipher();
    const key = 'SUPERSECRETKEY';
    const enc = cipher.encryptBytes(sampleBinary, { key });
    const container = packEncryptedContainer(cipher.id, filename, enc);

    const unpacked = unpackEncryptedContainer(container);
    assert.equal(unpacked.originalFilename, filename);
    const dec = cipher.decryptBytes(unpacked.payloadBytes, { key });
    assert.deepEqual(dec, sampleBinary);
  });

  it('Hill Cipher preserves binary bytes with container round-trip (using PKCS#7 padding)', () => {
    const cipher = new HillCipher();
    const matrix = [
      [3, 2],
      [5, 7]
    ]; // det = 11 (odd, coprime to 256)
    const enc = cipher.encryptBytes(sampleBinary, { matrix });
    const container = packEncryptedContainer(cipher.id, filename, enc);

    const unpacked = unpackEncryptedContainer(container);
    assert.equal(unpacked.originalFilename, filename);
    const dec = cipher.decryptBytes(unpacked.payloadBytes, { matrix });
    assert.deepEqual(dec, sampleBinary);
  });

  it('Permutation Cipher preserves binary bytes with container round-trip (using PKCS#7 padding)', () => {
    const cipher = new PermutationCipher();
    const key = '3 1 4 2';
    const enc = cipher.encryptBytes(sampleBinary, { key });
    const container = packEncryptedContainer(cipher.id, filename, enc);

    const unpacked = unpackEncryptedContainer(container);
    assert.equal(unpacked.originalFilename, filename);
    const dec = cipher.decryptBytes(unpacked.payloadBytes, { key });
    assert.deepEqual(dec, sampleBinary);
  });

  it('One-Time Pad Cipher preserves binary bytes with container round-trip', () => {
    const cipher = new OneTimePadCipher();
    // Key must be at least as long as payload
    const key = new Uint8Array(sampleBinary.length + 10);
    for (let i = 0; i < key.length; i++) key[i] = (i * 37 + 13) & 0xff;

    const { cipherBytes } = cipher.encryptBytes(sampleBinary, { key });
    const container = packEncryptedContainer(cipher.id, filename, cipherBytes);

    const unpacked = unpackEncryptedContainer(container);
    assert.equal(unpacked.originalFilename, filename);
    const { decryptedBytes } = cipher.decryptBytes(unpacked.payloadBytes, { key });
    assert.deepEqual(decryptedBytes, sampleBinary);
  });
});
