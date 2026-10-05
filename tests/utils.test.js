import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  mod,
  gcd,
  modInverse,
  cleanAlphabet,
  formatContinuous,
  formatGroupsOf5,
  isAlphabetOnly,
} from '../js/utils/text.js';

describe('Text & Math Utilities', () => {
  it('correctly calculates mathematical modulo for positive and negative numbers', () => {
    assert.equal(mod(5, 26), 5);
    assert.equal(mod(26, 26), 0);
    assert.equal(mod(27, 26), 1);
    assert.equal(mod(-1, 26), 25);
    assert.equal(mod(-27, 26), 25);
    assert.equal(mod(-52, 26), 0);
  });

  it('calculates greatest common divisor (gcd)', () => {
    assert.equal(gcd(26, 1), 1);
    assert.equal(gcd(26, 3), 1);
    assert.equal(gcd(26, 2), 2);
    assert.equal(gcd(26, 13), 13);
    assert.equal(gcd(54, 24), 6);
  });

  it('calculates modular inverse when gcd(a, m) === 1', () => {
    assert.equal(modInverse(1, 26), 1);
    assert.equal(modInverse(3, 26), 9); // (3 * 9) % 26 = 27 % 26 = 1
    assert.equal(modInverse(5, 26), 21); // (5 * 21) % 26 = 105 = 4*26 + 1
    assert.equal(modInverse(7, 26), 15); // (7 * 15) % 26 = 105 = 1
    assert.equal(modInverse(9, 26), 3);
    assert.equal(modInverse(11, 26), 19);
    assert.equal(modInverse(15, 26), 7);
    assert.equal(modInverse(17, 26), 23);
    assert.equal(modInverse(19, 26), 11);
    assert.equal(modInverse(21, 26), 5);
    assert.equal(modInverse(23, 26), 17);
    assert.equal(modInverse(25, 26), 25);
  });

  it('returns null or throws for numbers without modular inverse', () => {
    assert.equal(modInverse(2, 26), null);
    assert.equal(modInverse(4, 26), null);
    assert.equal(modInverse(13, 26), null);
  });

  it('cleans alphabet text (uppercase, letters only)', () => {
    assert.equal(cleanAlphabet('Hello, World! 123'), 'HELLOWORLD');
    assert.equal(cleanAlphabet('attack at dawn'), 'ATTACKATDAWN');
    assert.equal(cleanAlphabet(''), '');
  });

  it('formats text as continuous (no whitespace)', () => {
    assert.equal(formatContinuous('LXFOP VEFRN HR'), 'LXFOPVEFRNHR');
    assert.equal(formatContinuous('hello \n\t world'), 'helloworld');
  });

  it('formats text in groups of 5 uppercase letters', () => {
    assert.equal(formatGroupsOf5('LXFOPVEFRNHR'), 'LXFOP VEFRN HR');
    assert.equal(formatGroupsOf5('HELLOWORLD'), 'HELLO WORLD');
    assert.equal(formatGroupsOf5('ABC'), 'ABC');
    assert.equal(formatGroupsOf5(''), '');
  });

  it('checks if string is alphabet only', () => {
    assert.equal(isAlphabetOnly('HELLO'), true);
    assert.equal(isAlphabetOnly('Hello'), true);
    assert.equal(isAlphabetOnly('Hello123'), false);
    assert.equal(isAlphabetOnly('Hello World'), false);
    assert.equal(isAlphabetOnly(''), false);
  });
});
