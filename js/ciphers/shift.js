/**
 * Shift Cipher (Caesar Cipher) implementation
 * Formula:
 * C = (P + k) mod 26
 * P = (C - k) mod 26
 * For binary byte-by-byte:
 * C = (B + k) mod 256
 * P = (B - k) mod 256
 */
import { mod, cleanAlphabet } from '../utils/text.js';
import { validateShiftKey } from '../utils/validation.js';

export class ShiftCipher {
  constructor() {
    this.name = 'Shift Cipher';
    this.id = 'shift';
  }

  /**
   * Encrypts plaintext string using shift key.
   * @param {string} text 
   * @param {{shift: number|string}} options 
   * @returns {string}
   */
  encryptText(text, options = {}) {
    const val = validateShiftKey(options.shift ?? options.key);
    if (!val.valid) throw new Error(val.error);

    const cleaned = cleanAlphabet(text);
    const k = val.shift;
    let result = '';

    for (let i = 0; i < cleaned.length; i++) {
      const p = cleaned.charCodeAt(i) - 65;
      const c = mod(p + k, 26);
      result += String.fromCharCode(c + 65);
    }

    return result;
  }

  /**
   * Decrypts ciphertext string using shift key.
   * @param {string} text 
   * @param {{shift: number|string}} options 
   * @returns {string}
   */
  decryptText(text, options = {}) {
    const val = validateShiftKey(options.shift ?? options.key);
    if (!val.valid) throw new Error(val.error);

    const cleaned = cleanAlphabet(text);
    const k = val.shift;
    let result = '';

    for (let i = 0; i < cleaned.length; i++) {
      const c = cleaned.charCodeAt(i) - 65;
      const p = mod(c - k, 26);
      result += String.fromCharCode(p + 65);
    }

    return result;
  }

  /**
   * Encrypts byte array byte-by-byte mod 256.
   * @param {Uint8Array} bytes 
   * @param {{shift: number|string}} options 
   * @returns {Uint8Array}
   */
  encryptBytes(bytes, options = {}) {
    const rawKey = options.shift ?? options.key;
    if (rawKey === null || rawKey === undefined || rawKey === '') {
      throw new Error('Shift key tidak boleh kosong.');
    }
    const num = Number(rawKey);
    if (!Number.isInteger(num)) throw new Error('Shift key harus berupa bilangan bulat.');

    const k = mod(num, 256);
    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      result[i] = (bytes[i] + k) & 0xff;
    }
    return result;
  }

  /**
   * Decrypts byte array byte-by-byte mod 256.
   * @param {Uint8Array} bytes 
   * @param {{shift: number|string}} options 
   * @returns {Uint8Array}
   */
  decryptBytes(bytes, options = {}) {
    const rawKey = options.shift ?? options.key;
    if (rawKey === null || rawKey === undefined || rawKey === '') {
      throw new Error('Shift key tidak boleh kosong.');
    }
    const num = Number(rawKey);
    if (!Number.isInteger(num)) throw new Error('Shift key harus berupa bilangan bulat.');

    const k = mod(num, 256);
    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      result[i] = mod(bytes[i] - k, 256);
    }
    return result;
  }
}
