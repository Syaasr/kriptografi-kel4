/**
 * Text and mathematical helper utilities for classical ciphers.
 */

/**
 * Positive mathematical modulo: ((n % m) + m) % m
 * @param {number} n 
 * @param {number} m 
 * @returns {number}
 */
export function mod(n, m) {
  return ((n % m) + m) % m;
}

/**
 * Computes greatest common divisor using Euclidean algorithm.
 * @param {number} a 
 * @param {number} b 
 * @returns {number}
 */
export function gcd(a, b) {
  let x = Math.abs(a);
  let y = Math.abs(b);
  while (y !== 0) {
    const temp = y;
    y = x % y;
    x = temp;
  }
  return x;
}

/**
 * Computes modular multiplicative inverse of a modulo m using Extended Euclidean Algorithm.
 * Returns null if modular inverse does not exist (i.e. gcd(a, m) !== 1).
 * @param {number} a 
 * @param {number} m 
 * @returns {number|null}
 */
export function modInverse(a, m) {
  let t0 = 0;
  let t1 = 1;
  let r0 = m;
  let r1 = mod(a, m);

  if (r1 === 0) return null;

  while (r1 > 0) {
    const q = Math.floor(r0 / r1);
    const r2 = r0 - q * r1;
    const t2 = t0 - q * t1;

    r0 = r1;
    r1 = r2;
    t0 = t1;
    t1 = t2;
  }

  if (r0 !== 1) {
    return null; // Inverse does not exist
  }

  return mod(t0, m);
}

/**
 * Cleans string: keeps only A-Z letters and converts to uppercase.
 * @param {string} text 
 * @returns {string}
 */
export function cleanAlphabet(text) {
  if (!text) return '';
  return text.toUpperCase().replace(/[^A-Z]/g, '');
}

/**
 * Removes all whitespace characters.
 * @param {string} text 
 * @returns {string}
 */
export function formatContinuous(text) {
  if (!text) return '';
  return text.replace(/\s+/g, '');
}

/**
 * Formats uppercase text into chunks of 5 characters separated by space.
 * @param {string} text 
 * @returns {string}
 */
export function formatGroupsOf5(text) {
  const continuous = formatContinuous(text);
  if (!continuous) return '';
  const chunks = [];
  for (let i = 0; i < continuous.length; i += 5) {
    chunks.push(continuous.slice(i, i + 5));
  }
  return chunks.join(' ');
}

/**
 * Validates if string consists solely of A-Za-z letters and is non-empty.
 * @param {string} text 
 * @returns {boolean}
 */
export function isAlphabetOnly(text) {
  if (!text || typeof text !== 'string') return false;
  return /^[A-Za-z]+$/.test(text);
}
