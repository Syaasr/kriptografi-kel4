/**
 * Monoalphabetic Substitution Cipher implementation
 * Text:
 * Alphabet A-Z is mapped directly to a 26-letter permutation key.
 * Binary:
 * Deterministic bijective 256-byte S-box generated via key schedule.
 */
import { cleanAlphabet } from '../utils/text.js';
import { validateSubstitutionKey } from '../utils/validation.js';

export class SubstitutionCipher {
  constructor() {
    this.name = 'Substitution Cipher';
    this.id = 'substitution';
  }

  /**
   * Generates a 256-byte substitution table and its inverse from a key string.
   * @private
   * @param {string} keyStr 
   * @returns {{sBox: Uint8Array, invSBox: Uint8Array}}
   */
  _generateByteSBox(keyStr) {
    const sBox = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      sBox[i] = i;
    }

    const keyBytes = new TextEncoder().encode(keyStr || 'DEFAULT_SUBSTITUTION_KEY');
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + sBox[i] + keyBytes[i % keyBytes.length]) & 0xff;
      const temp = sBox[i];
      sBox[i] = sBox[j];
      sBox[j] = temp;
    }

    const invSBox = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      invSBox[sBox[i]] = i;
    }

    return { sBox, invSBox };
  }

  /**
   * Encrypts plaintext string using 26-letter substitution key.
   * @param {string} text 
   * @param {{key: string}} options 
   * @returns {string}
   */
  encryptText(text, options = {}) {
    const val = validateSubstitutionKey(options.key);
    if (!val.valid) throw new Error(val.error);

    const key = val.key;
    const cleaned = cleanAlphabet(text);
    let result = '';

    for (let i = 0; i < cleaned.length; i++) {
      const idx = cleaned.charCodeAt(i) - 65;
      result += key[idx];
    }

    return result;
  }

  /**
   * Decrypts ciphertext string using 26-letter substitution key.
   * @param {string} text 
   * @param {{key: string}} options 
   * @returns {string}
   */
  decryptText(text, options = {}) {
    const val = validateSubstitutionKey(options.key);
    if (!val.valid) throw new Error(val.error);

    const key = val.key;
    const cleaned = cleanAlphabet(text);
    let result = '';

    for (let i = 0; i < cleaned.length; i++) {
      const char = cleaned[i];
      const idx = key.indexOf(char);
      if (idx === -1) {
        throw new Error(`Karakter ${char} tidak ditemukan pada key substitusi.`);
      }
      result += String.fromCharCode(idx + 65);
    }

    return result;
  }

  /**
   * Encrypts byte array byte-by-byte using 256-byte S-box.
   * @param {Uint8Array} bytes 
   * @param {{key: string}} options 
   * @returns {Uint8Array}
   */
  encryptBytes(bytes, options = {}) {
    const val = validateSubstitutionKey(options.key);
    if (!val.valid) throw new Error(val.error);

    const { sBox } = this._generateByteSBox(val.key);
    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      result[i] = sBox[bytes[i]];
    }
    return result;
  }

  /**
   * Decrypts byte array byte-by-byte using 256-byte inverse S-box.
   * @param {Uint8Array} bytes 
   * @param {{key: string}} options 
   * @returns {Uint8Array}
   */
  decryptBytes(bytes, options = {}) {
    const val = validateSubstitutionKey(options.key);
    if (!val.valid) throw new Error(val.error);

    const { invSBox } = this._generateByteSBox(val.key);
    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      result[i] = invSBox[bytes[i]];
    }
    return result;
  }
}
