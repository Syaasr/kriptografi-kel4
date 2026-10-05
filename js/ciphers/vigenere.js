/**
 * Vigenere Cipher implementation
 * Rules:
 * - 26 alphabet letters (A=0..Z=25)
 * - Only alphabet characters are encrypted
 * - Numbers, spaces, and punctuation are ignored/discarded when ciphertext is produced
 * - Key of arbitrary length, repeated over the cleaned plaintext
 * 
 * Formula:
 * C_i = (P_i + K_i) mod 26
 * P_i = (C_i - K_i + 26) mod 26
 * 
 * Binary Mode:
 * Byte-by-byte mod 256 using repeated key bytes.
 */
import { mod, cleanAlphabet } from '../utils/text.js';
import { validateVigenereKey } from '../utils/validation.js';

export class VigenereCipher {
  constructor() {
    this.name = 'Vigenere Cipher';
    this.id = 'vigenere';
  }

  /**
   * Encrypts plaintext string using Vigenere key.
   * @param {string} text 
   * @param {{key: string}} options 
   * @returns {string}
   */
  encryptText(text, options = {}) {
    const val = validateVigenereKey(options.key);
    if (!val.valid) throw new Error(val.error);

    const key = val.key;
    const cleaned = cleanAlphabet(text);
    let result = '';

    for (let i = 0; i < cleaned.length; i++) {
      const p = cleaned.charCodeAt(i) - 65;
      const k = key.charCodeAt(i % key.length) - 65;
      const c = mod(p + k, 26);
      result += String.fromCharCode(c + 65);
    }

    return result;
  }

  /**
   * Decrypts ciphertext string using Vigenere key.
   * @param {string} text 
   * @param {{key: string}} options 
   * @returns {string}
   */
  decryptText(text, options = {}) {
    const val = validateVigenereKey(options.key);
    if (!val.valid) throw new Error(val.error);

    const key = val.key;
    const cleaned = cleanAlphabet(text);
    let result = '';

    for (let i = 0; i < cleaned.length; i++) {
      const c = cleaned.charCodeAt(i) - 65;
      const k = key.charCodeAt(i % key.length) - 65;
      const p = mod(c - k, 26);
      result += String.fromCharCode(p + 65);
    }

    return result;
  }

  /**
   * Encrypts byte array byte-by-byte mod 256.
   * @param {Uint8Array} bytes 
   * @param {{key: string|Uint8Array}} options 
   * @returns {Uint8Array}
   */
  encryptBytes(bytes, options = {}) {
    let keyBytes;
    if (options.key instanceof Uint8Array) {
      keyBytes = options.key;
    } else {
      const val = validateVigenereKey(options.key);
      if (!val.valid) throw new Error(val.error);
      keyBytes = new TextEncoder().encode(val.key);
    }

    if (keyBytes.length === 0) {
      throw new Error('Key Vigenere tidak boleh kosong.');
    }

    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      result[i] = (bytes[i] + keyBytes[i % keyBytes.length]) & 0xff;
    }
    return result;
  }

  /**
   * Decrypts byte array byte-by-byte mod 256.
   * @param {Uint8Array} bytes 
   * @param {{key: string|Uint8Array}} options 
   * @returns {Uint8Array}
   */
  decryptBytes(bytes, options = {}) {
    let keyBytes;
    if (options.key instanceof Uint8Array) {
      keyBytes = options.key;
    } else {
      const val = validateVigenereKey(options.key);
      if (!val.valid) throw new Error(val.error);
      keyBytes = new TextEncoder().encode(val.key);
    }

    if (keyBytes.length === 0) {
      throw new Error('Key Vigenere tidak boleh kosong.');
    }

    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      result[i] = mod(bytes[i] - keyBytes[i % keyBytes.length], 256);
    }
    return result;
  }
}
