/**
 * Hill Cipher implementation
 * Matrix operations modulo 26 for text, modulo 256 for binary bytes.
 * Supports 2x2 and 3x3 key matrices.
 * Text padding: 'X'
 * Binary padding: PKCS#7
 */
import { mod, modInverse, cleanAlphabet } from '../utils/text.js';
import { validateHillMatrix, matrixDeterminant } from '../utils/validation.js';

export class HillCipher {
  constructor() {
    this.name = 'Hill Cipher';
    this.id = 'hill';
  }

  /**
   * Computes inverse of matrix modulo m.
   * @param {number[][]} matrix 
   * @param {number} m 
   * @returns {number[][]}
   */
  getInverseMatrix(matrix, m) {
    const n = matrix.length;
    const det = matrixDeterminant(matrix);
    const detMod = mod(det, m);
    const invDet = modInverse(detMod, m);
    if (invDet === null) {
      throw new Error(`Determinant ${detMod} tidak memiliki modular inverse modulo ${m}.`);
    }

    if (n === 2) {
      return [
        [mod(invDet * matrix[1][1], m), mod(invDet * -matrix[0][1], m)],
        [mod(invDet * -matrix[1][0], m), mod(invDet * matrix[0][0], m)]
      ];
    }

    if (n === 3) {
      const c00 = +(matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]);
      const c01 = -(matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]);
      const c02 = +(matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]);

      const c10 = -(matrix[0][1] * matrix[2][2] - matrix[0][2] * matrix[2][1]);
      const c11 = +(matrix[0][0] * matrix[2][2] - matrix[0][2] * matrix[2][0]);
      const c12 = -(matrix[0][0] * matrix[2][1] - matrix[0][1] * matrix[2][0]);

      const c20 = +(matrix[0][1] * matrix[1][2] - matrix[0][2] * matrix[1][1]);
      const c21 = -(matrix[0][0] * matrix[1][2] - matrix[0][2] * matrix[1][0]);
      const c22 = +(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]);

      // Adjugate is transpose of cofactors:
      return [
        [mod(invDet * c00, m), mod(invDet * c10, m), mod(invDet * c20, m)],
        [mod(invDet * c01, m), mod(invDet * c11, m), mod(invDet * c21, m)],
        [mod(invDet * c02, m), mod(invDet * c12, m), mod(invDet * c22, m)]
      ];
    }

    throw new Error(`Dimensi matriks ${n}x${n} belum didukung.`);
  }

  /**
   * Multiplies an n-vector by n-matrix modulo m: result = (M * v) mod m.
   * @private
   * @param {number[][]} matrix 
   * @param {number[]} vec 
   * @param {number} m 
   * @returns {number[]}
   */
  _multiplyMatrixVector(matrix, vec, m) {
    const n = matrix.length;
    const res = new Array(n);
    for (let r = 0; r < n; r++) {
      let sum = 0;
      for (let c = 0; c < n; c++) {
        sum += matrix[r][c] * vec[c];
      }
      res[r] = mod(sum, m);
    }
    return res;
  }

  /**
   * Encrypts plaintext string using Hill matrix.
   * @param {string} text 
   * @param {{matrix: number[][]}} options 
   * @returns {string}
   */
  encryptText(text, options = {}) {
    const val = validateHillMatrix(options.matrix, 26);
    if (!val.valid) throw new Error(val.error);

    const matrix = val.matrix;
    const n = matrix.length;
    let cleaned = cleanAlphabet(text);

    // Padding with 'X' to multiple of n
    const remainder = cleaned.length % n;
    if (remainder !== 0) {
      cleaned = cleaned.padEnd(cleaned.length + (n - remainder), 'X');
    }

    let result = '';
    for (let i = 0; i < cleaned.length; i += n) {
      const block = [];
      for (let j = 0; j < n; j++) {
        block.push(cleaned.charCodeAt(i + j) - 65);
      }
      const cipherBlock = this._multiplyMatrixVector(matrix, block, 26);
      for (let j = 0; j < n; j++) {
        result += String.fromCharCode(cipherBlock[j] + 65);
      }
    }

    return result;
  }

  /**
   * Decrypts ciphertext string using Hill matrix.
   * @param {string} text 
   * @param {{matrix: number[][], unpad?: boolean}} options 
   * @returns {string}
   */
  decryptText(text, options = {}) {
    const val = validateHillMatrix(options.matrix, 26);
    if (!val.valid) throw new Error(val.error);

    const invMatrix = this.getInverseMatrix(val.matrix, 26);
    const n = invMatrix.length;
    const cleaned = cleanAlphabet(text);

    if (cleaned.length % n !== 0) {
      throw new Error(`Panjang ciphertext Hill (${cleaned.length}) harus kelipatan ukuran matriks (${n}).`);
    }

    let result = '';
    for (let i = 0; i < cleaned.length; i += n) {
      const block = [];
      for (let j = 0; j < n; j++) {
        block.push(cleaned.charCodeAt(i + j) - 65);
      }
      const plainBlock = this._multiplyMatrixVector(invMatrix, block, 26);
      for (let j = 0; j < n; j++) {
        result += String.fromCharCode(plainBlock[j] + 65);
      }
    }

    return result;
  }

  /**
   * Encrypts byte array using Hill matrix modulo 256 with PKCS#7 padding.
   * @param {Uint8Array} bytes 
   * @param {{matrix: number[][]}} options 
   * @returns {Uint8Array}
   */
  encryptBytes(bytes, options = {}) {
    const val = validateHillMatrix(options.matrix, 256);
    if (!val.valid) throw new Error(val.error);

    const matrix = val.matrix;
    const n = matrix.length;

    // PKCS#7 padding
    const padLen = n - (bytes.length % n);
    const padded = new Uint8Array(bytes.length + padLen);
    padded.set(bytes, 0);
    padded.fill(padLen, bytes.length);

    const result = new Uint8Array(padded.length);
    for (let i = 0; i < padded.length; i += n) {
      const block = [];
      for (let j = 0; j < n; j++) {
        block.push(padded[i + j]);
      }
      const cipherBlock = this._multiplyMatrixVector(matrix, block, 256);
      for (let j = 0; j < n; j++) {
        result[i + j] = cipherBlock[j];
      }
    }

    return result;
  }

  /**
   * Decrypts byte array using Hill matrix modulo 256 with PKCS#7 unpadding.
   * @param {Uint8Array} bytes 
   * @param {{matrix: number[][]}} options 
   * @returns {Uint8Array}
   */
  decryptBytes(bytes, options = {}) {
    const val = validateHillMatrix(options.matrix, 256);
    if (!val.valid) throw new Error(val.error);

    const invMatrix = this.getInverseMatrix(val.matrix, 256);
    const n = invMatrix.length;

    if (bytes.length % n !== 0) {
      throw new Error(`Ukuran data terenkripsi (${bytes.length}) harus kelipatan ukuran blok (${n}).`);
    }

    const decrypted = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i += n) {
      const block = [];
      for (let j = 0; j < n; j++) {
        block.push(bytes[i + j]);
      }
      const plainBlock = this._multiplyMatrixVector(invMatrix, block, 256);
      for (let j = 0; j < n; j++) {
        decrypted[i + j] = plainBlock[j];
      }
    }

    // Strip PKCS#7 padding
    const padLen = decrypted[decrypted.length - 1];
    if (padLen < 1 || padLen > n) {
      return decrypted; // fallback if padding unparseable
    }
    for (let i = decrypted.length - padLen; i < decrypted.length; i++) {
      if (decrypted[i] !== padLen) {
        return decrypted;
      }
    }

    return decrypted.slice(0, decrypted.length - padLen);
  }
}
