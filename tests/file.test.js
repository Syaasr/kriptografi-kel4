import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  packEncryptedContainer,
  unpackEncryptedContainer,
  isContainerFile
} from '../js/utils/file.js';

describe('File Packaging & Container Utilities', () => {
  const sampleData = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]); // PNG header bytes
  const originalFilename = 'my-photo.png';
  const cipherId = 'vigenere';

  it('packs and unpacks encrypted container preserving metadata and payload', () => {
    const container = packEncryptedContainer(cipherId, originalFilename, sampleData);
    assert.equal(isContainerFile(container), true);

    const unpacked = unpackEncryptedContainer(container, 'fallback.bin');
    assert.equal(unpacked.hasMetadata, true);
    assert.equal(unpacked.originalFilename, 'my-photo.png');
    assert.equal(unpacked.cipherId, 'vigenere');
    assert.deepEqual(unpacked.payloadBytes, sampleData);
  });

  it('unpacks raw non-container binary file using fallback filename', () => {
    const rawBytes = new Uint8Array([1, 2, 3, 4, 5]);
    assert.equal(isContainerFile(rawBytes), false);

    const unpacked = unpackEncryptedContainer(rawBytes, 'restored.jpg');
    assert.equal(unpacked.hasMetadata, false);
    assert.equal(unpacked.originalFilename, 'restored.jpg');
    assert.deepEqual(unpacked.payloadBytes, rawBytes);
  });
});
