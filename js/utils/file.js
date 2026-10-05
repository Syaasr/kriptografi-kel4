/**
 * File utilities for reading, packaging container with metadata,
 * unpacking container, and triggering browser downloads.
 */

// Magic identifier for encrypted container file: 'CRYP'
const CONTAINER_MAGIC = new Uint8Array([0x43, 0x52, 0x59, 0x50]);
const CONTAINER_VERSION = 1;

/**
 * Checks if a byte buffer starts with the CRYP container magic header.
 * @param {Uint8Array} bytes 
 * @returns {boolean}
 */
export function isContainerFile(bytes) {
  if (!bytes || bytes.length < 8) return false;
  return (
    bytes[0] === CONTAINER_MAGIC[0] &&
    bytes[1] === CONTAINER_MAGIC[1] &&
    bytes[2] === CONTAINER_MAGIC[2] &&
    bytes[3] === CONTAINER_MAGIC[3]
  );
}

/**
 * Packs encrypted payload and metadata into a binary container format:
 * [0..3]   Magic 'CRYP'
 * [4]      Version (1)
 * [5]      Cipher ID string length (L_c)
 * [6..]    Cipher ID UTF-8 bytes
 * [...]    Filename length (2 bytes Uint16 BE)
 * [...]    Filename UTF-8 bytes
 * [...]    Payload length (4 bytes Uint32 BE)
 * [...]    Encrypted payload bytes
 * 
 * @param {string} cipherId 
 * @param {string} originalFilename 
 * @param {Uint8Array} encryptedBytes 
 * @returns {Uint8Array}
 */
export function packEncryptedContainer(cipherId, originalFilename, encryptedBytes) {
  const encoder = new TextEncoder();
  const cipherBytes = encoder.encode(cipherId || 'generic');
  const filenameBytes = encoder.encode(originalFilename || 'unknown.dat');

  const totalLength =
    4 + // magic
    1 + // version
    1 + cipherBytes.length + // cipher id
    2 + filenameBytes.length + // filename
    4 + // payload length
    encryptedBytes.length;

  const buffer = new Uint8Array(totalLength);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  // Magic
  buffer.set(CONTAINER_MAGIC, offset);
  offset += 4;

  // Version
  buffer[offset++] = CONTAINER_VERSION;

  // Cipher ID
  buffer[offset++] = cipherBytes.length;
  buffer.set(cipherBytes, offset);
  offset += cipherBytes.length;

  // Filename
  view.setUint16(offset, filenameBytes.length, false);
  offset += 2;
  buffer.set(filenameBytes, offset);
  offset += filenameBytes.length;

  // Payload length
  view.setUint32(offset, encryptedBytes.length, false);
  offset += 4;

  // Payload
  buffer.set(encryptedBytes, offset);

  return buffer;
}

/**
 * Unpacks an encrypted container or falls back to raw payload.
 * @param {Uint8Array} bytes 
 * @param {string} fallbackFilename 
 * @returns {{hasMetadata: boolean, originalFilename: string, cipherId?: string, payloadBytes: Uint8Array}}
 */
export function unpackEncryptedContainer(bytes, fallbackFilename = 'restored-file.dat') {
  if (!isContainerFile(bytes)) {
    return {
      hasMetadata: false,
      originalFilename: fallbackFilename,
      payloadBytes: bytes
    };
  }

  try {
    const decoder = new TextDecoder();
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 4; // skip magic

    const version = bytes[offset++];
    if (version !== CONTAINER_VERSION) {
      return {
        hasMetadata: false,
        originalFilename: fallbackFilename,
        payloadBytes: bytes
      };
    }

    const cipherLen = bytes[offset++];
    const cipherId = decoder.decode(bytes.slice(offset, offset + cipherLen));
    offset += cipherLen;

    const filenameLen = view.getUint16(offset, false);
    offset += 2;
    const originalFilename = decoder.decode(bytes.slice(offset, offset + filenameLen));
    offset += filenameLen;

    const payloadLen = view.getUint32(offset, false);
    offset += 4;

    const payloadBytes = bytes.slice(offset, offset + payloadLen);

    return {
      hasMetadata: true,
      originalFilename: originalFilename || fallbackFilename,
      cipherId,
      payloadBytes
    };
  } catch {
    // If parsing fails for any reason, treat as raw bytes
    return {
      hasMetadata: false,
      originalFilename: fallbackFilename,
      payloadBytes: bytes
    };
  }
}

/**
 * Reads File object as ArrayBuffer in browser.
 * @param {File|Blob} file 
 * @returns {Promise<ArrayBuffer>}
 */
export function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error || new Error('Gagal membaca file.'));
    reader.readAsArrayBuffer(file);
  });
}

/**
 * Reads File object as Text in browser.
 * @param {File|Blob} file 
 * @returns {Promise<string>}
 */
export function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error || new Error('Gagal membaca file sebagai teks.'));
    reader.readAsText(file);
  });
}

/**
 * Downloads a Blob or Uint8Array as a file in the browser.
 * @param {Blob|Uint8Array|string} data 
 * @param {string} filename 
 * @param {string} mimeType 
 */
export function downloadFile(data, filename, mimeType = 'application/octet-stream') {
  let blob;
  if (data instanceof Blob) {
    blob = data;
  } else if (typeof data === 'string') {
    blob = new Blob([data], { type: mimeType });
  } else {
    // Uint8Array or ArrayBuffer
    blob = new Blob([data], { type: mimeType });
  }

  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename || 'download.dat';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
}
