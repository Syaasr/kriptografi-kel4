/**
 * Validation utilities for cipher keys and parameters.
 */
import { mod, gcd, cleanAlphabet, modInverse } from './text.js';

/**
 * Validates Shift cipher key.
 * @param {number|string} key 
 * @returns {{valid: boolean, shift?: number, error?: string}}
 */
export function validateShiftKey(key) {
  if (key === null || key === undefined || key === '') {
    return { valid: false, error: 'Shift key tidak boleh kosong.' };
  }
  const num = Number(key);
  if (!Number.isInteger(num)) {
    return { valid: false, error: 'Shift key harus berupa bilangan bulat.' };
  }
  return { valid: true, shift: mod(num, 26) };
}

/**
 * Validates Substitution cipher key (must be 26 unique alphabet letters).
 * @param {string} key 
 * @returns {{valid: boolean, key?: string, error?: string}}
 */
export function validateSubstitutionKey(key) {
  if (!key || typeof key !== 'string') {
    return { valid: false, error: 'Key substitusi tidak boleh kosong.' };
  }
  const clean = key.toUpperCase().trim();
  if (clean.length !== 26) {
    return { valid: false, error: `Key substitusi harus memiliki tepat 26 huruf (saat ini ${clean.length}).` };
  }
  if (!/^[A-Z]{26}$/.test(clean)) {
    return { valid: false, error: 'Key substitusi hanya boleh berisi huruf alfabet A-Z.' };
  }
  const set = new Set(clean);
  if (set.size !== 26) {
    return { valid: false, error: 'Setiap huruf dalam key substitusi harus unik (tidak boleh ada duplikasi).' };
  }
  return { valid: true, key: clean };
}

/**
 * Validates Affine cipher keys (a and b).
 * @param {number|string} a 
 * @param {number|string} b 
 * @param {number} modulus Default 26
 * @returns {{valid: boolean, a?: number, b?: number, error?: string}}
 */
export function validateAffineKey(a, b, modulus = 26) {
  if (a === null || a === undefined || a === '' || b === null || b === undefined || b === '') {
    return { valid: false, error: 'Nilai a dan b tidak boleh kosong.' };
  }
  const numA = Number(a);
  const numB = Number(b);
  if (!Number.isInteger(numA) || !Number.isInteger(numB)) {
    return { valid: false, error: 'Nilai a dan b harus berupa bilangan bulat.' };
  }
  const g = gcd(numA, modulus);
  if (g !== 1) {
    return {
      valid: false,
      error: `Nilai a (${numA}) tidak valid. gcd(a, ${modulus}) harus 1 (coprime), tetapi diperoleh ${g}.`
    };
  }
  return {
    valid: true,
    a: mod(numA, modulus),
    b: mod(numB, modulus)
  };
}

/**
 * Validates Vigenere cipher key.
 * @param {string} key 
 * @returns {{valid: boolean, key?: string, error?: string}}
 */
export function validateVigenereKey(key) {
  if (!key || typeof key !== 'string') {
    return { valid: false, error: 'Key Vigenere tidak boleh kosong.' };
  }
  const clean = cleanAlphabet(key);
  if (clean.length === 0) {
    return { valid: false, error: 'Key Vigenere harus memiliki setidaknya 1 huruf alfabet.' };
  }
  return { valid: true, key: clean };
}

/**
 * Calculates determinant of 2x2 or 3x3 matrix.
 * @param {number[][]} matrix 
 * @returns {number}
 */
export function matrixDeterminant(matrix) {
  const n = matrix.length;
  if (n === 2) {
    return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
  }
  if (n === 3) {
    return (
      matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) -
      matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]) +
      matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0])
    );
  }
  throw new Error(`Determinant not implemented for dimension ${n}`);
}

/**
 * Validates Hill cipher matrix.
 * @param {number[][]} matrix 
 * @param {number} modulus Default 26
 * @returns {{valid: boolean, det?: number, matrix?: number[][], error?: string}}
 */
export function validateHillMatrix(matrix, modulus = 26) {
  if (!Array.isArray(matrix) || matrix.length < 2) {
    return { valid: false, error: 'Matrix Hill tidak valid.' };
  }
  const n = matrix.length;
  for (let r = 0; r < n; r++) {
    if (!Array.isArray(matrix[r]) || matrix[r].length !== n) {
      return { valid: false, error: 'Matrix Hill harus berupa matriks persegi.' };
    }
    for (let c = 0; c < n; c++) {
      if (!Number.isInteger(Number(matrix[r][c]))) {
        return { valid: false, error: 'Semua elemen matrix Hill harus berupa bilangan bulat.' };
      }
    }
  }

  const det = matrixDeterminant(matrix);
  const detMod = mod(det, modulus);
  const inv = modInverse(detMod, modulus);

  if (inv === null) {
    return {
      valid: false,
      error: `Determinant matrix (${detMod}) tidak memiliki inverse modulo ${modulus}. gcd(det, ${modulus}) = ${gcd(detMod, modulus)}.`
    };
  }

  return { valid: true, det: detMod, matrix };
}

/**
 * Validates Permutation cipher key (e.g. "3 1 4 2" or "3,1,4,2").
 * Supports both 1-indexed (1..m) and 0-indexed (0..m-1) formats.
 * Returns normalized 0-indexed permutation array.
 * @param {string|number[]} key 
 * @returns {{valid: boolean, permutation?: number[], size?: number, error?: string}}
 */
export function validatePermutationKey(key) {
  if (!key) {
    return { valid: false, error: 'Key permutasi tidak boleh kosong.' };
  }
  let tokens = [];
  if (Array.isArray(key)) {
    tokens = key.map(Number);
  } else if (typeof key === 'string') {
    tokens = key.trim().split(/[\s,]+/).filter(Boolean).map(Number);
  } else {
    return { valid: false, error: 'Format key permutasi tidak valid.' };
  }

  if (tokens.length < 2) {
    return { valid: false, error: 'Key permutasi harus memiliki minimal 2 elemen.' };
  }

  for (const t of tokens) {
    if (!Number.isInteger(t)) {
      return { valid: false, error: 'Semua elemen key permutasi harus berupa bilangan bulat.' };
    }
  }

  const minVal = Math.min(...tokens);
  const maxVal = Math.max(...tokens);
  const n = tokens.length;

  let zeroIndexed = [];
  if (minVal === 1 && maxVal === n) {
    // 1-indexed permutation (1..n)
    zeroIndexed = tokens.map((v) => v - 1);
  } else if (minVal === 0 && maxVal === n - 1) {
    // 0-indexed permutation (0..n-1)
    zeroIndexed = [...tokens];
  } else {
    return {
      valid: false,
      error: `Key permutasi harus berisi angka unik berurutan 1..${n} atau 0..${n - 1}.`
    };
  }

  // Check uniqueness
  const set = new Set(zeroIndexed);
  if (set.size !== n) {
    return { valid: false, error: 'Key permutasi tidak boleh mengandung elemen duplikat.' };
  }

  return { valid: true, permutation: zeroIndexed, size: n };
}

/**
 * Validates OTP key against message length.
 * @param {string|Uint8Array} key 
 * @param {number} requiredLength 
 * @returns {{valid: boolean, error?: string}}
 */
export function validateOTPKey(key, requiredLength) {
  if (!key) {
    return { valid: false, error: 'File key One-Time Pad belum dipilih.' };
  }
  const keyLen = typeof key === 'string' ? key.length : key.byteLength;
  if (keyLen < requiredLength) {
    return {
      valid: false,
      error: `Key OTP (${keyLen} karakter/byte) lebih pendek daripada panjang pesan (${requiredLength} karakter/byte).`
    };
  }
  return { valid: true };
}
