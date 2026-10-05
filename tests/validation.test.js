import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateShiftKey,
  validateSubstitutionKey,
  validateAffineKey,
  validateVigenereKey,
  validateHillMatrix,
  validatePermutationKey,
  validateOTPKey,
} from '../js/utils/validation.js';

describe('Key & Parameter Validation', () => {
  describe('Shift Key Validation', () => {
    it('accepts valid integers and returns normalized shift 0-25', () => {
      assert.deepEqual(validateShiftKey(3), { valid: true, shift: 3 });
      assert.deepEqual(validateShiftKey('5'), { valid: true, shift: 5 });
      assert.deepEqual(validateShiftKey(-1), { valid: true, shift: 25 });
      assert.deepEqual(validateShiftKey(29), { valid: true, shift: 3 });
    });

    it('rejects invalid inputs', () => {
      assert.equal(validateShiftKey('').valid, false);
      assert.equal(validateShiftKey('abc').valid, false);
      assert.equal(validateShiftKey(null).valid, false);
      assert.equal(validateShiftKey(NaN).valid, false);
    });
  });

  describe('Substitution Key Validation', () => {
    it('accepts valid 26-letter permutation', () => {
      const validKey = 'QWERTYUIOPASDFGHJKLZXCVBNM';
      const result = validateSubstitutionKey(validKey);
      assert.equal(result.valid, true);
      assert.equal(result.key, validKey);
    });

    it('rejects keys that are not 26 unique letters', () => {
      assert.equal(validateSubstitutionKey('QWERTY').valid, false); // too short
      assert.equal(validateSubstitutionKey('QWERTYUIOPASDFGHJKLZXCVBNMA').valid, false); // too long
      assert.equal(validateSubstitutionKey('AAAAAAAAAAAAAAAAAAAAAAAAAA').valid, false); // duplicate
      assert.equal(validateSubstitutionKey('QWERTYUIOPASDFGHJKLZXCVBN1').valid, false); // non-letter
    });
  });

  describe('Affine Key Validation', () => {
    it('accepts valid a and b where gcd(a, 26) === 1', () => {
      const result = validateAffineKey(5, 8, 26);
      assert.equal(result.valid, true);
      assert.equal(result.a, 5);
      assert.equal(result.b, 8);
    });

    it('rejects a when gcd(a, 26) !== 1', () => {
      assert.equal(validateAffineKey(2, 5, 26).valid, false);
      assert.equal(validateAffineKey(13, 1, 26).valid, false);
      assert.equal(validateAffineKey(26, 3, 26).valid, false);
    });

    it('rejects non-numeric a or b', () => {
      assert.equal(validateAffineKey('', 5, 26).valid, false);
      assert.equal(validateAffineKey(5, 'xyz', 26).valid, false);
    });
  });

  describe('Vigenere Key Validation', () => {
    it('accepts valid alphabet keys and cleans them', () => {
      const res = validateVigenereKey('lemon');
      assert.equal(res.valid, true);
      assert.equal(res.key, 'LEMON');
    });

    it('rejects empty or non-alphabetic keys', () => {
      assert.equal(validateVigenereKey('').valid, false);
      assert.equal(validateVigenereKey('   ').valid, false);
      assert.equal(validateVigenereKey('12345').valid, false);
    });
  });

  describe('Hill Matrix Validation', () => {
    it('accepts valid invertible 2x2 matrix modulo 26', () => {
      // Matrix: [3, 3; 2, 5] -> det = 15 - 6 = 9. gcd(9, 26) = 1.
      const res = validateHillMatrix([[3, 3], [2, 5]], 26);
      assert.equal(res.valid, true);
      assert.equal(res.det, 9);
    });

    it('rejects non-invertible matrix modulo 26', () => {
      // Matrix: [2, 4; 1, 2] -> det = 0.
      assert.equal(validateHillMatrix([[2, 4], [1, 2]], 26).valid, false);
      // Matrix: [2, 1; 4, 3] -> det = 6 - 4 = 2. gcd(2, 26) = 2.
      assert.equal(validateHillMatrix([[2, 1], [4, 3]], 26).valid, false);
    });
  });

  describe('Permutation Key Validation', () => {
    it('accepts valid permutation strings like "3 1 4 2" or "3,1,4,2"', () => {
      const res1 = validatePermutationKey('3 1 4 2');
      assert.equal(res1.valid, true);
      assert.deepEqual(res1.permutation, [2, 0, 3, 1]); // 0-based internal representation

      const res2 = validatePermutationKey('3, 1, 4, 2');
      assert.equal(res2.valid, true);
      assert.deepEqual(res2.permutation, [2, 0, 3, 1]);
    });

    it('accepts 0-indexed permutation "2 0 3 1"', () => {
      const res = validatePermutationKey('2 0 3 1');
      assert.equal(res.valid, true);
      assert.deepEqual(res.permutation, [2, 0, 3, 1]);
    });

    it('rejects permutations with duplicates or gaps', () => {
      assert.equal(validatePermutationKey('1 2 2 4').valid, false);
      assert.equal(validatePermutationKey('1 5').valid, false);
      assert.equal(validatePermutationKey('').valid, false);
    });
  });

  describe('OTP Key Validation', () => {
    it('accepts key of sufficient length', () => {
      assert.equal(validateOTPKey('ABCDE', 5).valid, true);
      assert.equal(validateOTPKey('ABCDEFGH', 5).valid, true);
    });

    it('rejects key shorter than message length', () => {
      const res = validateOTPKey('ABC', 5);
      assert.equal(res.valid, false);
      assert.match(res.error, /shorter|panjang/i);
    });
  });
});
