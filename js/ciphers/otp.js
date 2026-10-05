/**
 * One-Time Pad (OTP) Cipher implementation
 * Rules:
 * - 26 alphabet letters (A=0..Z=25)
 * - Key read from random letter text file (or byte stream for binary mode)
 * - Key length must be >= message length
 * - Only the first N key characters/bytes are used (N = message length)
 * - Remaining key characters are unused
 * 
 * Formula:
 * C_i = (P_i + K_i) mod 26
 * P_i = (C_i - K_i) mod 26
 */
import { mod, cleanAlphabet } from '../utils/text.js';
import { validateOTPKey } from '../utils/validation.js';

/**
 * Generates a cryptographically strong random uppercase alphabet key.
 * @param {number} length 
 * @returns {string}
 */
export function generateRandomKey(length = 1000) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let result = '';
  // Use crypto.getRandomValues if in browser/Node
  const randomBytes = new Uint8Array(length);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(randomBytes);
    for (let i = 0; i < length; i++) {
      result += chars[randomBytes[i] % 26];
    }
  } else {
    for (let i = 0; i < length; i++) {
      result += chars[Math.floor(Math.random() * 26)];
    }
  }
  return result;
}

export class OneTimePadCipher {
  constructor() {
    this.name = 'One-Time Pad';
    this.id = 'otp';
  }

  /**
   * Encrypts plaintext string using OTP key.
   * @param {string} text 
   * @param {{key: string}} options 
   * @returns {{ciphertext: string, usedLength: number, remainingLength: number, totalKeyLength: number}}
   */
  encryptText(text, options = {}) {
    const rawKey = options.key || '';
    const cleanKey = cleanAlphabet(rawKey);
    const cleaned = cleanAlphabet(text);

    const val = validateOTPKey(cleanKey, cleaned.length);
    if (!val.valid) throw new Error(val.error);

    let ciphertext = '';
    for (let i = 0; i < cleaned.length; i++) {
      const p = cleaned.charCodeAt(i) - 65;
      const k = cleanKey.charCodeAt(i) - 65;
      const c = mod(p + k, 26);
      ciphertext += String.fromCharCode(c + 65);
    }

    return {
      ciphertext,
      usedLength: cleaned.length,
      remainingLength: cleanKey.length - cleaned.length,
      totalKeyLength: cleanKey.length
    };
  }

  /**
   * Decrypts ciphertext string using OTP key.
   * @param {string} text 
   * @param {{key: string}} options 
   * @returns {{plaintext: string, usedLength: number, remainingLength: number, totalKeyLength: number}}
   */
  decryptText(text, options = {}) {
    const rawKey = options.key || '';
    const cleanKey = cleanAlphabet(rawKey);
    const cleaned = cleanAlphabet(text);

    const val = validateOTPKey(cleanKey, cleaned.length);
    if (!val.valid) throw new Error(val.error);

    let plaintext = '';
    for (let i = 0; i < cleaned.length; i++) {
      const c = cleaned.charCodeAt(i) - 65;
      const k = cleanKey.charCodeAt(i) - 65;
      const p = mod(c - k, 26);
      plaintext += String.fromCharCode(p + 65);
    }

    return {
      plaintext,
      usedLength: cleaned.length,
      remainingLength: cleanKey.length - cleaned.length,
      totalKeyLength: cleanKey.length
    };
  }

  /**
   * Encrypts byte array using OTP key stream.
   * @param {Uint8Array} bytes 
   * @param {{key: Uint8Array|string}} options 
   * @returns {{cipherBytes: Uint8Array, usedLength: number, remainingLength: number, totalKeyLength: number}}
   */
  encryptBytes(bytes, options = {}) {
    let keyBytes;
    if (options.key instanceof Uint8Array) {
      keyBytes = options.key;
    } else if (typeof options.key === 'string') {
      keyBytes = new TextEncoder().encode(options.key);
    } else {
      throw new Error('Key OTP tidak valid.');
    }

    const val = validateOTPKey(keyBytes, bytes.length);
    if (!val.valid) throw new Error(val.error);

    const cipherBytes = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      cipherBytes[i] = (bytes[i] + keyBytes[i]) & 0xff;
    }

    return {
      cipherBytes,
      usedLength: bytes.length,
      remainingLength: keyBytes.length - bytes.length,
      totalKeyLength: keyBytes.length
    };
  }

  /**
   * Decrypts byte array using OTP key stream.
   * @param {Uint8Array} bytes 
   * @param {{key: Uint8Array|string}} options 
   * @returns {{decryptedBytes: Uint8Array, usedLength: number, remainingLength: number, totalKeyLength: number}}
   */
  decryptBytes(bytes, options = {}) {
    let keyBytes;
    if (options.key instanceof Uint8Array) {
      keyBytes = options.key;
    } else if (typeof options.key === 'string') {
      keyBytes = new TextEncoder().encode(options.key);
    } else {
      throw new Error('Key OTP tidak valid.');
    }

    const val = validateOTPKey(keyBytes, bytes.length);
    if (!val.valid) throw new Error(val.error);

    const decryptedBytes = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      decryptedBytes[i] = mod(bytes[i] - keyBytes[i], 256);
    }

    return {
      decryptedBytes,
      usedLength: bytes.length,
      remainingLength: keyBytes.length - bytes.length,
      totalKeyLength: keyBytes.length
    };
  }
}
