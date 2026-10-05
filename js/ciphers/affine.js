/**
 * Affine Cipher implementation
 * Formula:
 * C = (a * P + b) mod 26
 * P = a^-1 * (C - b) mod 26
 * Requirement: gcd(a, 26) = 1
 *
 * For binary byte-by-byte (mod 256):
 * C = (a * B + b) mod 256
 * P = a^-1 * (C - b) mod 256
 * Requirement: gcd(a, 256) = 1 (a is odd)
 */
import { mod, modInverse, cleanAlphabet } from '../utils/text.js';
import { validateAffineKey } from '../utils/validation.js';

export class AffineCipher {
  constructor() {
    this.name = 'Affine Cipher';
    this.id = 'affine';
  }

  /**
   * Encrypts plaintext string using affine keys (a, b).
   * @param {string} text 
   * @param {{a: number|string, b: number|string}} options 
   * @returns {string}
   */
  encryptText(text, options = {}) {
    const val = validateAffineKey(options.a, options.b, 26);
    if (!val.valid) throw new Error(val.error);

    const { a, b } = val;
    const cleaned = cleanAlphabet(text);
    let result = '';

    for (let i = 0; i < cleaned.length; i++) {
      const p = cleaned.charCodeAt(i) - 65;
      const c = mod(a * p + b, 26);
      result += String.fromCharCode(c + 65);
    }

    return result;
  }

  /**
   * Decrypts ciphertext string using affine keys (a, b).
   * @param {string} text 
   * @param {{a: number|string, b: number|string}} options 
   * @returns {string}
   */
  decryptText(text, options = {}) {
    const val = validateAffineKey(options.a, options.b, 26);
    if (!val.valid) throw new Error(val.error);

    const { a, b } = val;
    const aInv = modInverse(a, 26);
    if (aInv === null) {
      throw new Error(`Inverse modulo 26 tidak ditemukan untuk a=${a}`);
    }

    const cleaned = cleanAlphabet(text);
    let result = '';

    for (let i = 0; i < cleaned.length; i++) {
      const c = cleaned.charCodeAt(i) - 65;
      const p = mod(aInv * (c - b), 26);
      result += String.fromCharCode(p + 65);
    }

    return result;
  }

  /**
   * Encrypts byte array byte-by-byte mod 256.
   * @param {Uint8Array} bytes 
   * @param {{a: number|string, b: number|string}} options 
   * @returns {Uint8Array}
   */
  encryptBytes(bytes, options = {}) {
    const val = validateAffineKey(options.a, options.b, 256);
    if (!val.valid) throw new Error(val.error);

    const { a, b } = val;
    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      result[i] = (a * bytes[i] + b) & 0xff;
    }
    return result;
  }

  /**
   * Decrypts byte array byte-by-byte mod 256.
   * @param {Uint8Array} bytes 
   * @param {{a: number|string, b: number|string}} options 
   * @returns {Uint8Array}
   */
  decryptBytes(bytes, options = {}) {
    const val = validateAffineKey(options.a, options.b, 256);
    if (!val.valid) throw new Error(val.error);

    const { a, b } = val;
    const aInv = modInverse(a, 256);
    if (aInv === null) {
      throw new Error(`Inverse modulo 256 tidak ditemukan untuk a=${a}`);
    }

    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      result[i] = mod(aInv * (bytes[i] - b), 256);
    }
    return result;
  }
}
