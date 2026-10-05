/**
 * Main Controller for Web Cryptography Tool
 * Technical Utility & Laboratory Pattern (Online Domain Tools inspired)
 */
import { ShiftCipher } from './ciphers/shift.js';
import { SubstitutionCipher } from './ciphers/substitution.js';
import { AffineCipher } from './ciphers/affine.js';
import { VigenereCipher } from './ciphers/vigenere.js';
import { HillCipher } from './ciphers/hill.js';
import { PermutationCipher } from './ciphers/permutation.js';
import { OneTimePadCipher, generateRandomKey } from './ciphers/otp.js';

import {
  cleanAlphabet,
  formatContinuous,
  formatGroupsOf5,
  gcd,
  mod
} from './utils/text.js';

import {
  readFileAsArrayBuffer,
  readFileAsText,
  downloadFile,
  packEncryptedContainer,
  unpackEncryptedContainer
} from './utils/file.js';

import { matrixDeterminant } from './utils/validation.js';

// Instantiate Ciphers
const ciphers = {
  shift: new ShiftCipher(),
  substitution: new SubstitutionCipher(),
  affine: new AffineCipher(),
  vigenere: new VigenereCipher(),
  hill: new HillCipher(),
  permutation: new PermutationCipher(),
  otp: new OneTimePadCipher()
};

// Documentation information for each cipher
const cipherDocs = {
  shift: {
    title: 'How does Shift Cipher work?',
    html: `
      <p><strong>Shift Cipher (Caesar Cipher)</strong> menggeser setiap karakter alfabet sejauh nilai kunci <code>k</code>.</p>
      <p>Rumus Enkripsi: <code>Cᵢ = (Pᵢ + k) mod 26</code></p>
      <p>Rumus Dekripsi: <code>Pᵢ = (Cᵢ - k) mod 26</code></p>
      <p>Untuk file biner, pergeseran dilakukan byte-by-byte modulo 256: <code>C = (B + k) mod 256</code>.</p>
    `
  },
  substitution: {
    title: 'How does Substitution Cipher work?',
    html: `
      <p><strong>Substitution Cipher</strong> memetakan setiap huruf A-Z ke permutasi 26 huruf alfabet yang unik.</p>
      <p>Enkripsi: <code>Cᵢ = Key[Pᵢ]</code> | Dekripsi: <code>Pᵢ = Alphabet[Key.indexOf(Cᵢ)]</code></p>
      <p>Untuk mode biner, kunci menghasilkan tabel S-Box 256-byte dan invers S-Box yang bijektif.</p>
    `
  },
  affine: {
    title: 'How does Affine Cipher work?',
    html: `
      <p><strong>Affine Cipher</strong> menggabungkan operasi perkalian dan pergeseran linear.</p>
      <p>Rumus Enkripsi: <code>Cᵢ = (a · Pᵢ + b) mod 26</code></p>
      <p>Rumus Dekripsi: <code>Pᵢ = a⁻¹ · (Cᵢ - b) mod 26</code></p>
      <p>Syarat Matematis: <code>gcd(a, 26) = 1</code>. Nilai <code>a</code> yang valid: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.</p>
    `
  },
  vigenere: {
    title: 'How does Vigenere Cipher work?',
    html: `
      <p><strong>Vigenere Cipher</strong> adalah kriptosistem polialfabetik dengan kunci kata yang diulang sepanjang teks.</p>
      <p>Rumus Enkripsi: <code>Cᵢ = (Pᵢ + Kᵢ) mod 26</code></p>
      <p>Rumus Dekripsi: <code>Pᵢ = (Cᵢ - Kᵢ + 26) mod 26</code></p>
      <p>Khusus tugas ini: hanya karakter alfabet A-Z yang dienkripsi. Angka, spasi, dan tanda baca diabaikan pada output.</p>
    `
  },
  hill: {
    title: 'How does Hill Cipher work?',
    html: `
      <p><strong>Hill Cipher</strong> mengenkripsi blok karakter menggunakan perkalian matriks modulo 26.</p>
      <p>Rumus Enkripsi: <code>C = (K · P) mod 26</code></p>
      <p>Rumus Dekripsi: <code>P = (K⁻¹ · C) mod 26</code></p>
      <p>Syarat Invertibilitas: <code>gcd(det(K), 26) = 1</code>. Jika panjang teks bukan kelipatan blok, teks otomatis dipadding dengan 'X'.</p>
    `
  },
  permutation: {
    title: 'How does Permutation Cipher work?',
    html: `
      <p><strong>Permutation Cipher (Transposisi Blok)</strong> mengubah posisi urutan karakter dalam setiap blok.</p>
      <p>Kunci menyatakan urutan indeks permutasi (misal: <code>3 1 4 2</code>).</p>
      <p>Enkripsi: <code>C[j] = P[π[j]]</code> | Dekripsi menggunakan invers permutasi: <code>P[k] = C[π⁻¹[k]]</code>.</p>
    `
  },
  otp: {
    title: 'How does One-Time Pad work?',
    html: `
      <p><strong>One-Time Pad (OTP)</strong> menggunakan kunci acak dari file yang panjangnya &ge; panjang pesan.</p>
      <p>Rumus Enkripsi: <code>Cᵢ = (Pᵢ + Kᵢ) mod 26</code> | Dekripsi: <code>Pᵢ = (Cᵢ - Kᵢ + 26) mod 26</code></p>
      <p>Kunci yang digunakan hanya sepanjang pesan yang diproses, sisa kunci tidak digunakan.</p>
    `
  }
};

// Application State
const state = {
  inputType: 'text', // 'text' | 'file'
  selectedCipher: 'vigenere',
  outputFormat: 'continuous', // 'continuous' | 'groups5'
  
  // File mode state
  selectedFile: null,
  selectedFileBytes: null,
  processedFileBytes: null,
  outputFilename: '',

  // OTP key file state
  otpKeyData: null,
  otpKeyFilename: '',

  // Text mode result cache
  lastPlaintext: '',
  lastCiphertextRaw: '',
  lastOperation: 'encrypt'
};

// DOM Elements
const elements = {
  inputTypeSelect: document.getElementById('inputTypeSelect'),
  rowInputText: document.getElementById('rowInputText'),
  rowInputFile: document.getElementById('rowInputFile'),
  rowOutputFormat: document.getElementById('rowOutputFormat'),
  cipherSelect: document.getElementById('cipherSelect'),

  // Text inputs
  textInput: document.getElementById('textInput'),
  textCharCount: document.getElementById('textCharCount'),
  btnSampleText: document.getElementById('btnSampleText'),
  btnClearText: document.getElementById('btnClearText'),

  // File inputs
  fileInput: document.getElementById('fileInput'),
  fileDropzone: document.getElementById('fileDropzone'),
  fileInfoBox: document.getElementById('fileInfoBox'),
  fileName: document.getElementById('fileName'),
  fileSize: document.getElementById('fileSize'),
  fileType: document.getElementById('fileType'),

  // Parameter rows
  paramPanels: {
    shift: document.getElementById('paramShift'),
    substitution: document.getElementById('paramSubstitution'),
    affine: document.getElementById('paramAffine'),
    vigenere: document.getElementById('paramVigenere'),
    hill: document.getElementById('paramHill'),
    permutation: document.getElementById('paramPermutation'),
    otp: document.getElementById('paramOTP')
  },

  // Parameter controls
  shiftKey: document.getElementById('shiftKey'),
  substitutionKey: document.getElementById('substitutionKey'),
  subKeyLen: document.getElementById('subKeyLen'),
  btnGenSubKey: document.getElementById('btnGenSubKey'),
  btnResetSubKey: document.getElementById('btnResetSubKey'),

  affineA: document.getElementById('affineA'),
  affineB: document.getElementById('affineB'),

  vigenereKey: document.getElementById('vigenereKey'),

  btnHill2x2: document.getElementById('btnHill2x2'),
  btnHill3x3: document.getElementById('btnHill3x3'),
  hill2x2Container: document.getElementById('hill2x2Container'),
  hill3x3Container: document.getElementById('hill3x3Container'),
  btnSampleHillMatrix: document.getElementById('btnSampleHillMatrix'),
  hillDetStatus: document.getElementById('hillDetStatus'),

  permutationKey: document.getElementById('permutationKey'),
  permSizeBadge: document.getElementById('permSizeBadge'),

  otpKeyFileInput: document.getElementById('otpKeyFileInput'),
  btnSelectOtpKeyFile: document.getElementById('btnSelectOtpKeyFile'),
  btnGenerateOtpKey: document.getElementById('btnGenerateOtpKey'),
  otpKeyFileName: document.getElementById('otpKeyFileName'),
  otpKeyLength: document.getElementById('otpKeyLength'),
  otpCharsUsed: document.getElementById('otpCharsUsed'),
  otpCharsRemaining: document.getElementById('otpCharsRemaining'),

  // Format Radios
  formatContinuous: document.getElementById('formatContinuous'),
  formatGroups5: document.getElementById('formatGroups5'),

  // Action Buttons
  btnEncrypt: document.getElementById('btnEncrypt'),
  btnDecrypt: document.getElementById('btnDecrypt'),

  // Status Bar
  statusBar: document.getElementById('statusBar'),
  statusIcon: document.getElementById('statusIcon'),
  statusMessage: document.getElementById('statusMessage'),

  // Result Sections
  textResultSection: document.getElementById('textResultSection'),
  fileResultSection: document.getElementById('fileResultSection'),
  resultPlaintext: document.getElementById('resultPlaintext'),
  resultCiphertext: document.getElementById('resultCiphertext'),
  btnCopyResult: document.getElementById('btnCopyResult'),
  btnDownloadResult: document.getElementById('btnDownloadResult'),

  fileOperationStatus: document.getElementById('fileOperationStatus'),
  resultFileNameDisplay: document.getElementById('resultFileNameDisplay'),
  resultFileSizeDisplay: document.getElementById('resultFileSizeDisplay'),
  customOutputFilename: document.getElementById('customOutputFilename'),
  hexPreviewContent: document.getElementById('hexPreviewContent'),
  btnDownloadProcessedFile: document.getElementById('btnDownloadProcessedFile'),

  // Expandable Documentation
  docTitleSummary: document.getElementById('docTitleSummary'),
  docContent: document.getElementById('docContent')
};

let hillCurrentDim = 2;

// Utility: Status Bar message
function setStatus(message, type = 'ready') {
  elements.statusBar.className = `status-bar status-${type}`;
  if (type === 'success') {
    elements.statusIcon.textContent = '✓';
  } else if (type === 'error') {
    elements.statusIcon.textContent = '✕';
  } else if (type === 'info') {
    elements.statusIcon.textContent = 'ℹ️';
  } else {
    elements.statusIcon.textContent = 'ℹ️';
  }
  elements.statusMessage.textContent = message;
}

// Utility: Format byte size
function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Utility: Generate Hex Preview for binary data
function generateHexPreview(bytes, maxBytes = 128) {
  if (!bytes || bytes.length === 0) return 'No data available.';
  const len = Math.min(bytes.length, maxBytes);
  let output = '';
  for (let i = 0; i < len; i += 16) {
    const offset = i.toString(16).padStart(8, '0');
    let hexPart = '';
    let asciiPart = '';
    for (let j = 0; j < 16; j++) {
      if (i + j < len) {
        const b = bytes[i + j];
        hexPart += b.toString(16).padStart(2, '0').toUpperCase() + ' ';
        asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      } else {
        hexPart += '   ';
      }
    }
    output += `${offset}  ${hexPart} |${asciiPart}|\n`;
  }
  if (bytes.length > maxBytes) {
    output += `... (${bytes.length - maxBytes} more bytes hidden in preview)`;
  }
  return output;
}

// Switch Input Type (Text vs File)
function setInputType(type) {
  state.inputType = type;
  elements.inputTypeSelect.value = type;
  if (type === 'text') {
    elements.rowInputText.style.display = 'grid';
    elements.rowInputFile.style.display = 'none';
    elements.rowOutputFormat.style.display = 'grid';
    elements.textResultSection.style.display = 'block';
    elements.fileResultSection.style.display = 'none';
  } else {
    elements.rowInputText.style.display = 'none';
    elements.rowInputFile.style.display = 'grid';
    elements.rowOutputFormat.style.display = 'none';
    elements.textResultSection.style.display = 'none';
    elements.fileResultSection.style.display = 'block';
  }
  setStatus('Ready. Select parameters and click Encrypt or Decrypt.', 'ready');
}

// Switch Active Cipher
function setCipher(cipherId) {
  state.selectedCipher = cipherId;
  for (const [id, panel] of Object.entries(elements.paramPanels)) {
    panel.style.display = id === cipherId ? 'grid' : 'none';
  }

  // Update expandable documentation
  const doc = cipherDocs[cipherId];
  if (doc) {
    elements.docTitleSummary.textContent = doc.title;
    elements.docContent.innerHTML = doc.html;
  }
  setStatus(`Selected: ${ciphers[cipherId]?.name || cipherId}. Ready for operation.`, 'ready');
}

// Matrix helper: Read values from DOM
function getHillMatrix(dim = hillCurrentDim) {
  if (dim === 2) {
    return [
      [Number(document.getElementById('hill2_00')?.value || 0), Number(document.getElementById('hill2_01')?.value || 0)],
      [Number(document.getElementById('hill2_10')?.value || 0), Number(document.getElementById('hill2_11')?.value || 0)]
    ];
  } else {
    return [
      [Number(document.getElementById('hill3_00')?.value || 0), Number(document.getElementById('hill3_01')?.value || 0), Number(document.getElementById('hill3_02')?.value || 0)],
      [Number(document.getElementById('hill3_10')?.value || 0), Number(document.getElementById('hill3_11')?.value || 0), Number(document.getElementById('hill3_12')?.value || 0)],
      [Number(document.getElementById('hill3_20')?.value || 0), Number(document.getElementById('hill3_21')?.value || 0), Number(document.getElementById('hill3_22')?.value || 0)]
    ];
  }
}

// Matrix helper: Update determinant status
function updateHillMatrixStatus() {
  try {
    const matrix = getHillMatrix(hillCurrentDim);
    const det = matrixDeterminant(matrix);
    const detMod = mod(det, 26);
    const g = gcd(detMod, 26);

    if (g === 1) {
      elements.hillDetStatus.textContent = `det = ${det} (mod 26 = ${detMod}, gcd = 1, Invertible ✓)`;
      elements.hillDetStatus.style.color = '#15803d';
    } else {
      elements.hillDetStatus.textContent = `det = ${det} (mod 26 = ${detMod}, gcd = ${g}, Not Invertible ✕)`;
      elements.hillDetStatus.style.color = '#dc2626';
    }
  } catch (e) {
    elements.hillDetStatus.textContent = `Error: ${e.message}`;
    elements.hillDetStatus.style.color = '#dc2626';
  }
}

// Collect Parameters for Selected Cipher
function collectParameters() {
  const cipherId = state.selectedCipher;
  switch (cipherId) {
    case 'shift': {
      return { shift: elements.shiftKey.value.trim() };
    }
    case 'substitution': {
      return { key: elements.substitutionKey.value.trim().toUpperCase() };
    }
    case 'affine': {
      return {
        a: elements.affineA.value.trim(),
        b: elements.affineB.value.trim()
      };
    }
    case 'vigenere': {
      return { key: elements.vigenereKey.value.trim() };
    }
    case 'hill': {
      const matrix = getHillMatrix(hillCurrentDim);
      return { matrix };
    }
    case 'permutation': {
      return { key: elements.permutationKey.value.trim() };
    }
    case 'otp': {
      if (!state.otpKeyData) {
        throw new Error('Please choose an OTP key file using [Choose Key File] button first.');
      }
      return { key: state.otpKeyData };
    }
    default:
      throw new Error(`Cipher ${cipherId} not recognized.`);
  }
}

// Update Result Display for Text Mode
function renderTextResult(plaintext, ciphertextRaw) {
  state.lastPlaintext = plaintext;
  state.lastCiphertextRaw = ciphertextRaw;

  elements.resultPlaintext.textContent = plaintext || '(empty)';
  const formatted = state.outputFormat === 'groups5'
    ? formatGroupsOf5(ciphertextRaw)
    : formatContinuous(ciphertextRaw);
  elements.resultCiphertext.textContent = formatted || '(empty)';
}

// Handle Text Encryption / Decryption
function handleTextOperation(isEncrypt) {
  const inputMessage = elements.textInput.value;
  if (!inputMessage.trim()) {
    setStatus('Input message cannot be empty.', 'error');
    return;
  }

  try {
    const cipher = ciphers[state.selectedCipher];
    const options = collectParameters();

    if (isEncrypt) {
      if (state.selectedCipher === 'otp') {
        const res = cipher.encryptText(inputMessage, options);
        renderTextResult(cleanAlphabet(inputMessage), res.ciphertext);
        elements.otpCharsUsed.textContent = res.usedLength;
        elements.otpCharsRemaining.textContent = res.remainingLength;
      } else {
        const ciphertext = cipher.encryptText(inputMessage, options);
        renderTextResult(cleanAlphabet(inputMessage), ciphertext);
      }
      setStatus('Encryption completed successfully.', 'success');
    } else {
      if (state.selectedCipher === 'otp') {
        const res = cipher.decryptText(inputMessage, options);
        renderTextResult(res.plaintext, cleanAlphabet(inputMessage));
        elements.otpCharsUsed.textContent = res.usedLength;
        elements.otpCharsRemaining.textContent = res.remainingLength;
      } else {
        const decrypted = cipher.decryptText(inputMessage, options);
        renderTextResult(decrypted, cleanAlphabet(inputMessage));
      }
      setStatus('Decryption completed successfully.', 'success');
    }
  } catch (err) {
    setStatus(err.message || 'Error processing text.', 'error');
  }
}

// Handle File Encryption / Decryption
async function handleFileOperation(isEncrypt) {
  if (!state.selectedFile || !state.selectedFileBytes) {
    setStatus('No file selected. Please choose or drag a file to the dropzone.', 'error');
    return;
  }

  try {
    const cipher = ciphers[state.selectedCipher];
    const options = collectParameters();

    if (isEncrypt) {
      // Binary Encryption
      let cipherBytes;
      if (state.selectedCipher === 'otp') {
        const res = cipher.encryptBytes(state.selectedFileBytes, options);
        cipherBytes = res.cipherBytes;
        elements.otpCharsUsed.textContent = res.usedLength;
        elements.otpCharsRemaining.textContent = res.remainingLength;
      } else {
        cipherBytes = cipher.encryptBytes(state.selectedFileBytes, options);
      }

      // Pack into metadata container
      const container = packEncryptedContainer(cipher.id, state.selectedFile.name, cipherBytes);
      state.processedFileBytes = container;
      state.outputFilename = `${state.selectedFile.name}.enc`;

      elements.fileOperationStatus.textContent = 'Encryption Completed Successfully ✓';
      elements.resultFileNameDisplay.textContent = state.outputFilename;
      elements.resultFileSizeDisplay.textContent = formatBytes(container.byteLength);
      elements.hexPreviewContent.textContent = generateHexPreview(container);

      setStatus(`File "${state.selectedFile.name}" encrypted successfully (${formatBytes(container.byteLength)}). Ready for download.`, 'success');
    } else {
      // Binary Decryption
      const unpacked = unpackEncryptedContainer(state.selectedFileBytes, state.selectedFile.name.replace(/\.enc$/i, ''));
      
      let decryptedBytes;
      if (state.selectedCipher === 'otp') {
        const res = cipher.decryptBytes(unpacked.payloadBytes, options);
        decryptedBytes = res.decryptedBytes;
        elements.otpCharsUsed.textContent = res.usedLength;
        elements.otpCharsRemaining.textContent = res.remainingLength;
      } else {
        decryptedBytes = cipher.decryptBytes(unpacked.payloadBytes, options);
      }

      state.processedFileBytes = decryptedBytes;
      const targetFilename = elements.customOutputFilename.value.trim() || unpacked.originalFilename || 'restored_file.dat';
      state.outputFilename = targetFilename;
      elements.customOutputFilename.value = targetFilename;

      elements.fileOperationStatus.textContent = 'Decryption Completed Successfully ✓';
      elements.resultFileNameDisplay.textContent = targetFilename;
      elements.resultFileSizeDisplay.textContent = formatBytes(decryptedBytes.byteLength);
      elements.hexPreviewContent.textContent = generateHexPreview(decryptedBytes);

      setStatus(`File decrypted successfully into "${targetFilename}" (${formatBytes(decryptedBytes.byteLength)}). Ready for download.`, 'success');
    }
  } catch (err) {
    setStatus(err.message || 'Error processing file.', 'error');
  }
}

// Set up UI Event Listeners
function setupEventListeners() {
  // Input type dropdown
  elements.inputTypeSelect.addEventListener('change', (e) => {
    setInputType(e.target.value);
  });

  // Cipher selection dropdown
  elements.cipherSelect.addEventListener('change', (e) => {
    setCipher(e.target.value);
  });

  // Text character count listener
  elements.textInput.addEventListener('input', () => {
    elements.textCharCount.textContent = `${elements.textInput.value.length} chars`;
  });

  // Sample and Clear Text buttons
  elements.btnSampleText.addEventListener('click', () => {
    elements.textInput.value = 'ATTACKATDAWN';
    elements.textCharCount.textContent = `${elements.textInput.value.length} chars`;
  });

  elements.btnClearText.addEventListener('click', () => {
    elements.textInput.value = '';
    elements.textCharCount.textContent = '0 chars';
    elements.resultPlaintext.textContent = '-';
    elements.resultCiphertext.textContent = '-';
    setStatus('Text input cleared.', 'ready');
  });

  // Format Radio toggles
  elements.formatContinuous.addEventListener('change', () => {
    state.outputFormat = 'continuous';
    renderTextResult(state.lastPlaintext, state.lastCiphertextRaw);
  });
  elements.formatGroups5.addEventListener('change', () => {
    state.outputFormat = 'groups5';
    renderTextResult(state.lastPlaintext, state.lastCiphertextRaw);
  });

  // Shift Cipher Presets
  document.querySelectorAll('[data-shift]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      elements.shiftKey.value = e.target.getAttribute('data-shift');
    });
  });

  // Substitution Cipher Helpers
  elements.btnGenSubKey.addEventListener('click', () => {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
    for (let i = letters.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [letters[i], letters[j]] = [letters[j], letters[i]];
    }
    const shuffled = letters.join('');
    elements.substitutionKey.value = shuffled;
    elements.subKeyLen.textContent = '26 unique alphabet characters ✓';
  });

  elements.btnResetSubKey.addEventListener('click', () => {
    elements.substitutionKey.value = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    elements.subKeyLen.textContent = '26 unique alphabet characters ✓';
  });

  elements.substitutionKey.addEventListener('input', (e) => {
    const clean = e.target.value.toUpperCase().replace(/[^A-Z]/g, '');
    e.target.value = clean;
    const set = new Set(clean);
    elements.subKeyLen.textContent = `${clean.length}/26 characters (${set.size} unique)`;
  });

  // Hill Cipher Dimension Toggles
  elements.btnHill2x2.addEventListener('click', () => {
    hillCurrentDim = 2;
    elements.btnHill2x2.style.fontWeight = 'bold';
    elements.btnHill3x3.style.fontWeight = 'normal';
    elements.hill2x2Container.style.display = 'block';
    elements.hill3x3Container.style.display = 'none';
    updateHillMatrixStatus();
  });

  elements.btnHill3x3.addEventListener('click', () => {
    hillCurrentDim = 3;
    elements.btnHill2x2.style.fontWeight = 'normal';
    elements.btnHill3x3.style.fontWeight = 'bold';
    elements.hill2x2Container.style.display = 'none';
    elements.hill3x3Container.style.display = 'block';
    updateHillMatrixStatus();
  });

  elements.btnSampleHillMatrix.addEventListener('click', () => {
    if (hillCurrentDim === 2) {
      document.getElementById('hill2_00').value = 3;
      document.getElementById('hill2_01').value = 3;
      document.getElementById('hill2_10').value = 2;
      document.getElementById('hill2_11').value = 5;
    } else {
      document.getElementById('hill3_00').value = 6;
      document.getElementById('hill3_01').value = 24;
      document.getElementById('hill3_02').value = 1;
      document.getElementById('hill3_10').value = 13;
      document.getElementById('hill3_11').value = 16;
      document.getElementById('hill3_12').value = 10;
      document.getElementById('hill3_20').value = 20;
      document.getElementById('hill3_21').value = 17;
      document.getElementById('hill3_22').value = 15;
    }
    updateHillMatrixStatus();
  });

  // Monitor Hill input changes
  document.querySelectorAll('.matrix-cell-input').forEach((cell) => {
    cell.addEventListener('input', updateHillMatrixStatus);
  });

  // Permutation Presets
  document.querySelectorAll('[data-perm]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      const val = e.target.getAttribute('data-perm');
      elements.permutationKey.value = val;
      const count = val.split(' ').length;
      elements.permSizeBadge.textContent = `Block size: ${count}`;
    });
  });

  // File Dropzone & Selection
  elements.fileDropzone.addEventListener('click', () => {
    elements.fileInput.click();
  });

  elements.fileDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    elements.fileDropzone.classList.add('dragover');
  });

  elements.fileDropzone.addEventListener('dragleave', () => {
    elements.fileDropzone.classList.remove('dragover');
  });

  elements.fileDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    elements.fileDropzone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processSelectedFile(e.dataTransfer.files[0]);
    }
  });

  elements.fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      processSelectedFile(e.target.files[0]);
    }
  });

  async function processSelectedFile(file) {
    state.selectedFile = file;
    elements.fileName.textContent = file.name;
    elements.fileSize.textContent = `${formatBytes(file.size)} (${file.size.toLocaleString()} bytes)`;
    elements.fileType.textContent = file.type || 'application/octet-stream';
    elements.fileInfoBox.style.display = 'block';

    try {
      const buffer = await readFileAsArrayBuffer(file);
      state.selectedFileBytes = new Uint8Array(buffer);
      
      const unpacked = unpackEncryptedContainer(state.selectedFileBytes, file.name.replace(/\.enc$/i, ''));
      if (unpacked.hasMetadata) {
        elements.customOutputFilename.value = unpacked.originalFilename;
        setStatus(`Encrypted container detected. Original filename: "${unpacked.originalFilename}".`, 'info');
      } else {
        elements.customOutputFilename.value = file.name.replace(/\.enc$/i, '');
        setStatus(`File "${file.name}" loaded (${formatBytes(file.size)}). Ready for operation.`, 'ready');
      }
    } catch (err) {
      setStatus(`Failed reading file: ${err.message}`, 'error');
    }
  }

  // OTP Key File Handlers
  elements.btnSelectOtpKeyFile.addEventListener('click', () => {
    elements.otpKeyFileInput.click();
  });

  elements.otpKeyFileInput.addEventListener('change', async (e) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      state.otpKeyFilename = file.name;
      try {
        const text = await readFileAsText(file);
        const buffer = await readFileAsArrayBuffer(file);
        state.otpKeyData = state.inputType === 'text' ? cleanAlphabet(text) : new Uint8Array(buffer);
        const len = state.inputType === 'text' ? state.otpKeyData.length : buffer.byteLength;

        elements.otpKeyFileName.textContent = file.name;
        elements.otpKeyLength.textContent = len.toLocaleString();
        elements.otpCharsUsed.textContent = '0';
        elements.otpCharsRemaining.textContent = len.toLocaleString();
        setStatus(`OTP key file "${file.name}" loaded successfully (${len.toLocaleString()} characters/bytes).`, 'success');
      } catch (err) {
        setStatus(`Failed reading OTP key file: ${err.message}`, 'error');
      }
    }
  });

  elements.btnGenerateOtpKey.addEventListener('click', () => {
    const key = generateRandomKey(5000);
    downloadFile(key, 'otp_random_key_5000.txt', 'text/plain');
    setStatus('Generated and downloaded 5,000-character random OTP key file.', 'info');
  });

  // Action Buttons (Encrypt / Decrypt)
  elements.btnEncrypt.addEventListener('click', () => {
    if (state.inputType === 'text') {
      handleTextOperation(true);
    } else {
      handleFileOperation(true);
    }
  });

  elements.btnDecrypt.addEventListener('click', () => {
    if (state.inputType === 'text') {
      handleTextOperation(false);
    } else {
      handleFileOperation(false);
    }
  });

  // Result Actions (Copy & Download)
  elements.btnCopyResult.addEventListener('click', async () => {
    const textToCopy = elements.resultCiphertext.textContent;
    if (!textToCopy || textToCopy === '(empty)' || textToCopy === '-') {
      setStatus('No output available to copy.', 'error');
      return;
    }
    try {
      await navigator.clipboard.writeText(textToCopy);
      const originalText = elements.btnCopyResult.textContent;
      elements.btnCopyResult.textContent = '✓ Copied!';
      setTimeout(() => {
        elements.btnCopyResult.textContent = originalText;
      }, 2000);
      setStatus('Ciphertext copied to clipboard.', 'success');
    } catch {
      setStatus('Failed to copy to clipboard.', 'error');
    }
  });

  elements.btnDownloadResult.addEventListener('click', () => {
    const text = elements.resultCiphertext.textContent;
    if (!text || text === '(empty)' || text === '-') {
      setStatus('No output available to download.', 'error');
      return;
    }
    const filename = `${state.selectedCipher}_output.txt`;
    downloadFile(text, filename, 'text/plain');
    setStatus(`Downloaded output as "${filename}".`, 'success');
  });

  elements.btnDownloadProcessedFile.addEventListener('click', () => {
    if (!state.processedFileBytes) {
      setStatus('No processed file available for download.', 'error');
      return;
    }
    const filename = elements.customOutputFilename.value.trim() || state.outputFilename || 'processed_file.dat';
    downloadFile(state.processedFileBytes, filename);
    setStatus(`Downloaded processed file as "${filename}".`, 'success');
  });
}

// Initialize on DOM ready
window.addEventListener('DOMContentLoaded', () => {
  setCipher('vigenere');
  setInputType('text');
  updateHillMatrixStatus();
  setupEventListeners();
  elements.textCharCount.textContent = `${elements.textInput.value.length} chars`;
});
