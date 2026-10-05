/**
 * Permutation (Transposition) Cipher implementation
 * Operates on blocks of size m using a permutation of positions.
 * Text padding: 'X'
 * Binary padding: PKCS#7
 */
import { cleanAlphabet } from '../utils/text.js';
import { validatePermutationKey } from '../utils/validation.js';

export class PermutationCipher {
  constructor() {
    this.name = 'Permutation Cipher';
    this.id = 'permutation';
  }

  /**
   * Computes inverse of permutation array.
   * If perm[j] = k, then invPerm[k] = j.
   * @param {number[]} perm 
   * @returns {number[]}
   */
  getInversePermutation(perm) {
    const inv = new Array(perm.length);
    for (let j = 0; j < perm.length; j++) {
      inv[perm[j]] = j;
    }
    return inv;
  }

  /**
   * Encrypts plaintext string using permutation key.
   * @param {string} text 
   * @param {{key: string|number[]}} options 
   * @returns {string}
   */
  encryptText(text, options = {}) {
    const val = validatePermutationKey(options.key);
    if (!val.valid) throw new Error(val.error);

    const perm = val.permutation;
    const m = perm.length;
    let cleaned = cleanAlphabet(text);

    // Padding with 'X' to multiple of m
    const remainder = cleaned.length % m;
    if (remainder !== 0) {
      cleaned = cleaned.padEnd(cleaned.length + (m - remainder), 'X');
    }

    let result = '';
    for (let i = 0; i < cleaned.length; i += m) {
      const block = cleaned.slice(i, i + m);
      for (let j = 0; j < m; j++) {
        result += block[perm[j]];
      }
    }

    return result;
  }

  /**
   * Decrypts ciphertext string using permutation key.
   * @param {string} text 
   * @param {{key: string|number[]}} options 
   * @returns {string}
   */
  decryptText(text, options = {}) {
    const val = validatePermutationKey(options.key);
    if (!val.valid) throw new Error(val.error);

    const invPerm = this.getInversePermutation(val.permutation);
    const m = invPerm.length;
    const cleaned = cleanAlphabet(text);

    if (cleaned.length % m !== 0) {
      throw new Error(`Panjang ciphertext (${cleaned.length}) harus kelipatan ukuran blok (${m}).`);
    }

    let result = '';
    for (let i = 0; i < cleaned.length; i += m) {
      const block = cleaned.slice(i, i + m);
      for (let j = 0; j < m; j++) {
        result += block[invPerm[j]];
      }
    }

    return result;
  }

  /**
   * Encrypts byte array using Permutation cipher with PKCS#7 padding.
   * @param {Uint8Array} bytes 
   * @param {{key: string|number[]}} options 
   * @returns {Uint8Array}
   */
  encryptBytes(bytes, options = {}) {
    const val = validatePermutationKey(options.key);
    if (!val.valid) throw new Error(val.error);

    const perm = val.permutation;
    const m = perm.length;

    // PKCS#7 padding
    const padLen = m - (bytes.length % m);
    const padded = new Uint8Array(bytes.length + padLen);
    padded.set(bytes, 0);
    padded.fill(padLen, bytes.length);

    const result = new Uint8Array(padded.length);
    for (let i = 0; i < padded.length; i += m) {
      for (let j = 0; j < m; j++) {
        result[i + j] = padded[i + perm[j]];
      }
    }

    return result;
  }

  /**
   * Decrypts byte array using Permutation cipher with PKCS#7 unpadding.
   * @param {Uint8Array} bytes 
   * @param {{key: string|number[]}} options 
   * @returns {Uint8Array}
   */
  decryptBytes(bytes, options = {}) {
    const val = validatePermutationKey(options.key);
    if (!val.valid) throw new Error(val.error);

    const invPerm = this.getInversePermutation(val.permutation);
    const m = invPerm.length;

    if (bytes.length % m !== 0) {
      throw new Error(`Ukuran data terenkripsi (${bytes.length}) harus kelipatan ukuran blok (${m}).`);
    }

    const decrypted = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i += m) {
      for (let j = 0; j < m; j++) {
        decrypted[i + j] = bytes[i + invPerm[j]];
      }
    }

    // Strip PKCS#7 padding
    const padLen = decrypted[decrypted.length - 1];
    if (padLen < 1 || padLen > m) {
      return decrypted;
    }
    for (let i = decrypted.length - padLen; i < decrypted.length; i++) {
      if (decrypted[i] !== padLen) {
        return decrypted;
      }
    }

    return decrypted.slice(0, decrypted.length - padLen);
  }
}
