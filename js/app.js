/**
 * Main Controller for Web Cryptography Tool
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
  otpKeyData: null, // string for text, Uint8Array for binary
  otpKeyFilename: '',

  // Text mode result cache
  lastPlaintext: '',
  lastCiphertextRaw: '',
  lastOperation: 'encrypt'
};

// DOM Elements
const elements = {
  alertBox: document.getElementById('alertBox'),
  alertMessage: document.getElementById('alertMessage'),
  tabText: document.getElementById('tabText'),
  tabFile: document.getElementById('tabFile'),
  cipherSelect: document.getElementById('cipherSelect'),
  cipherBadge: document.getElementById('cipherBadge'),

  // Text inputs
  textInputContainer: document.getElementById('textInputContainer'),
  textInput: document.getElementById('textInput'),
  textCharCount: document.getElementById('textCharCount'),
  btnSampleText: document.getElementById('btnSampleText'),
  btnClearText: document.getElementById('btnClearText'),

  // File inputs
  fileInputContainer: document.getElementById('fileInputContainer'),
  fileDropzone: document.getElementById('fileDropzone'),
  fileInput: document.getElementById('fileInput'),
  fileInfoBadge: document.getElementById('fileInfoBadge'),
  fileName: document.getElementById('fileName'),
  fileSize: document.getElementById('fileSize'),
  fileType: document.getElementById('fileType'),

  // Parameter panels
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

  // Format options
  formatOptionGroup: document.getElementById('formatOptionGroup'),
  formatContinuous: document.getElementById('formatContinuous'),
  formatGroups5: document.getElementById('formatGroups5'),

  // Action buttons
  btnEncrypt: document.getElementById('btnEncrypt'),
  btnDecrypt: document.getElementById('btnDecrypt'),

  // Result displays
  textResultContainer: document.getElementById('textResultContainer'),
  fileResultContainer: document.getElementById('fileResultContainer'),
  resultPlaintext: document.getElementById('resultPlaintext'),
  resultCiphertext: document.getElementById('resultCiphertext'),
  btnCopyResult: document.getElementById('btnCopyResult'),
  btnDownloadResult: document.getElementById('btnDownloadResult'),

  fileOperationStatus: document.getElementById('fileOperationStatus'),
  resultFileNameDisplay: document.getElementById('resultFileNameDisplay'),
  resultFileSizeDisplay: document.getElementById('resultFileSizeDisplay'),
  customOutputFilename: document.getElementById('customOutputFilename'),
  btnDownloadProcessedFile: document.getElementById('btnDownloadProcessedFile')
};

let hillCurrentDim = 2;

// Utility functions
function showAlert(message, type = 'error') {
  elements.alertBox.className = `alert alert-${type} show`;
  elements.alertMessage.textContent = message;
  elements.alertBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function clearAlert() {
  elements.alertBox.className = 'alert';
  elements.alertMessage.textContent = '';
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Switch Input Type (Text vs File)
function setInputType(type) {
  state.inputType = type;
  if (type === 'text') {
    elements.tabText.classList.add('active');
    elements.tabFile.classList.remove('active');
    elements.textInputContainer.style.display = 'flex';
    elements.fileInputContainer.style.display = 'none';
    elements.formatOptionGroup.style.display = 'flex';
    elements.textResultContainer.style.display = 'block';
    elements.fileResultContainer.style.display = 'none';
  } else {
    elements.tabText.classList.remove('active');
    elements.tabFile.classList.add('active');
    elements.textInputContainer.style.display = 'none';
    elements.fileInputContainer.style.display = 'block';
    elements.formatOptionGroup.style.display = 'none';
    elements.textResultContainer.style.display = 'none';
    elements.fileResultContainer.style.display = 'block';
  }
  clearAlert();
}

// Switch Active Cipher
function setCipher(cipherId) {
  state.selectedCipher = cipherId;
  for (const [id, panel] of Object.entries(elements.paramPanels)) {
    panel.style.display = id === cipherId ? 'block' : 'none';
  }
  elements.cipherBadge.textContent = cipherId === 'otp' ? 'Stream / Pad' : 'Modulo 26';
  clearAlert();
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
        throw new Error('Silakan pilih file kunci OTP terlebih dahulu menggunakan tombol [Pilih File Key].');
      }
      return { key: state.otpKeyData };
    }
    default:
      throw new Error(`Cipher ${cipherId} tidak dikenal.`);
  }
}

// Update Result Display for Text Mode
function renderTextResult(plaintext, ciphertextRaw) {
  state.lastPlaintext = plaintext;
  state.lastCiphertextRaw = ciphertextRaw;

  elements.resultPlaintext.textContent = plaintext || '(kosong)';
  const formatted = state.outputFormat === 'groups5'
    ? formatGroupsOf5(ciphertextRaw)
    : formatContinuous(ciphertextRaw);
  elements.resultCiphertext.textContent = formatted || '(kosong)';
}

// Handle Text Encryption / Decryption
function handleTextOperation(isEncrypt) {
  clearAlert();
  const inputMessage = elements.textInput.value;
  if (!inputMessage.trim()) {
    showAlert('Pesan input tidak boleh kosong. Ketik pesan Anda terlebih dahulu.');
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
      showAlert('Enkripsi teks berhasil diselesaikan.', 'success');
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
      showAlert('Dekripsi teks berhasil diselesaikan.', 'success');
    }
  } catch (err) {
    showAlert(err.message || 'Terjadi kesalahan saat memproses teks.');
  }
}

// Handle File Encryption / Decryption
async function handleFileOperation(isEncrypt) {
  clearAlert();
  if (!state.selectedFile || !state.selectedFileBytes) {
    showAlert('File belum dipilih. Silakan pilih atau seret file ke area dropzone.');
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

      // Pack into metadata-preserving container
      const container = packEncryptedContainer(cipher.id, state.selectedFile.name, cipherBytes);
      state.processedFileBytes = container;
      state.outputFilename = `${state.selectedFile.name}.enc`;

      elements.fileOperationStatus.textContent = 'Enkripsi Berhasil Diselesaikan ✅';
      elements.resultFileNameDisplay.textContent = state.outputFilename;
      elements.resultFileSizeDisplay.textContent = formatBytes(container.byteLength);

      showAlert(`File "${state.selectedFile.name}" berhasil dienkripsi! Klik tombol unduh di bawah.`, 'success');
    } else {
      // Binary Decryption
      // Check if file is container format
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

      elements.fileOperationStatus.textContent = 'Dekripsi Berhasil Diselesaikan ✅';
      elements.resultFileNameDisplay.textContent = targetFilename;
      elements.resultFileSizeDisplay.textContent = formatBytes(decryptedBytes.byteLength);

      showAlert(`File berhasil didekripsi menjadi "${targetFilename}" (${formatBytes(decryptedBytes.byteLength)}). Siap diunduh!`, 'success');
    }
  } catch (err) {
    showAlert(err.message || 'Terjadi kesalahan saat memproses file.');
  }
}

// Matrix Helpers
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

// Matrix Determinant & UI Update
function updateHillMatrixStatus() {
  try {
    const matrix = getHillMatrix(hillCurrentDim);
    const det = matrixDeterminant(matrix);
    const detMod = mod(det, 26);
    const g = gcd(detMod, 26);

    if (g === 1) {
      elements.hillDetStatus.textContent = `det = ${det} (mod 26 = ${detMod}, gcd = 1, Invertible ✅)`;
      elements.hillDetStatus.style.color = '#34d399';
    } else {
      elements.hillDetStatus.textContent = `det = ${det} (mod 26 = ${detMod}, gcd = ${g}, TIDAK Memiliki Inverse ❌)`;
      elements.hillDetStatus.style.color = '#f87171';
    }
  } catch (e) {
    elements.hillDetStatus.textContent = `Error: ${e.message}`;
    elements.hillDetStatus.style.color = '#f87171';
  }
}

// Set up Event Listeners
function setupEventListeners() {
  // Input Type Tabs
  elements.tabText.addEventListener('click', () => setInputType('text'));
  elements.tabFile.addEventListener('click', () => setInputType('file'));

  // Cipher selection dropdown
  elements.cipherSelect.addEventListener('change', (e) => {
    setCipher(e.target.value);
  });

  // Text character count listener
  elements.textInput.addEventListener('input', () => {
    elements.textCharCount.textContent = `${elements.textInput.value.length} karakter`;
  });

  // Sample and Clear Text buttons
  elements.btnSampleText.addEventListener('click', () => {
    elements.textInput.value = 'ATTACKATDAWN';
    elements.textCharCount.textContent = `${elements.textInput.value.length} karakter`;
  });

  elements.btnClearText.addEventListener('click', () => {
    elements.textInput.value = '';
    elements.textCharCount.textContent = '0 karakter';
    elements.resultPlaintext.textContent = '-';
    elements.resultCiphertext.textContent = '-';
    clearAlert();
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
    elements.subKeyLen.textContent = '26 / 26 huruf unik ✅';
  });

  elements.btnResetSubKey.addEventListener('click', () => {
    elements.substitutionKey.value = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    elements.subKeyLen.textContent = '26 / 26 huruf unik ✅';
  });

  elements.substitutionKey.addEventListener('input', (e) => {
    const clean = e.target.value.toUpperCase().replace(/[^A-Z]/g, '');
    e.target.value = clean;
    const set = new Set(clean);
    elements.subKeyLen.textContent = `${clean.length}/26 huruf (${set.size} unik)`;
  });

  // Hill Cipher Dimension Toggles
  elements.btnHill2x2.addEventListener('click', () => {
    hillCurrentDim = 2;
    elements.btnHill2x2.classList.add('active');
    elements.btnHill3x3.classList.remove('active');
    elements.hill2x2Container.style.display = 'block';
    elements.hill3x3Container.style.display = 'none';
    updateHillMatrixStatus();
  });

  elements.btnHill3x3.addEventListener('click', () => {
    hillCurrentDim = 3;
    elements.btnHill2x2.classList.remove('active');
    elements.btnHill3x3.classList.add('active');
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
  document.querySelectorAll('.matrix-cell').forEach((cell) => {
    cell.addEventListener('input', updateHillMatrixStatus);
  });

  // Permutation Presets
  document.querySelectorAll('[data-perm]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      const val = e.target.getAttribute('data-perm');
      elements.permutationKey.value = val;
      const count = val.split(' ').length;
      elements.permSizeBadge.textContent = `Ukuran blok: ${count}`;
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
    elements.fileSize.textContent = formatBytes(file.size);
    elements.fileType.textContent = file.type || 'Binary / Unspecified';
    elements.fileInfoBadge.classList.add('show');

    try {
      const buffer = await readFileAsArrayBuffer(file);
      state.selectedFileBytes = new Uint8Array(buffer);
      
      // If encrypted container, auto-suggest restored filename
      const unpacked = unpackEncryptedContainer(state.selectedFileBytes, file.name.replace(/\.enc$/i, ''));
      if (unpacked.hasMetadata) {
        elements.customOutputFilename.value = unpacked.originalFilename;
        showAlert(`File container terdeteksi! Nama file asli: "${unpacked.originalFilename}".`, 'info');
      } else {
        elements.customOutputFilename.value = file.name.replace(/\.enc$/i, '');
      }
    } catch (err) {
      showAlert(`Gagal membaca file: ${err.message}`);
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
        // Clean alphabet letters for text mode
        state.otpKeyData = state.inputType === 'text' ? cleanAlphabet(text) : new Uint8Array(buffer);
        const len = state.inputType === 'text' ? state.otpKeyData.length : buffer.byteLength;

        elements.otpKeyFileName.textContent = file.name;
        elements.otpKeyLength.textContent = len;
        elements.otpCharsUsed.textContent = '0';
        elements.otpCharsRemaining.textContent = len;
        showAlert(`File kunci OTP "${file.name}" berhasil dimuat (${len} karakter/byte).`, 'success');
      } catch (err) {
        showAlert(`Gagal membaca file key OTP: ${err.message}`);
      }
    }
  });

  elements.btnGenerateOtpKey.addEventListener('click', () => {
    const key = generateRandomKey(5000);
    downloadFile(key, 'otp_random_key_5000.txt', 'text/plain');
    showAlert('File kunci acak OTP 5000 huruf telah diunduh! Gunakan file tersebut sebagai file kunci.', 'info');
  });

  // Action Buttons
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

  // Result Actions
  elements.btnCopyResult.addEventListener('click', async () => {
    const textToCopy = elements.resultCiphertext.textContent;
    if (!textToCopy || textToCopy === '(kosong)' || textToCopy === '-') {
      showAlert('Belum ada output untuk disalin.');
      return;
    }
    try {
      await navigator.clipboard.writeText(textToCopy);
      const originalText = elements.btnCopyResult.textContent;
      elements.btnCopyResult.textContent = '✅ Tersalin!';
      setTimeout(() => {
        elements.btnCopyResult.textContent = originalText;
      }, 2000);
    } catch {
      showAlert('Gagal menyalin ke clipboard.');
    }
  });

  elements.btnDownloadResult.addEventListener('click', () => {
    const text = elements.resultCiphertext.textContent;
    if (!text || text === '(kosong)' || text === '-') {
      showAlert('Belum ada output untuk diunduh.');
      return;
    }
    const filename = `${state.selectedCipher}_output.txt`;
    downloadFile(text, filename, 'text/plain');
  });

  elements.btnDownloadProcessedFile.addEventListener('click', () => {
    if (!state.processedFileBytes) {
      showAlert('Belum ada file yang berhasil diproses.');
      return;
    }
    const filename = elements.customOutputFilename.value.trim() || state.outputFilename || 'processed_file.dat';
    downloadFile(state.processedFileBytes, filename);
  });
}

// Initialize on DOMContentLoaded
window.addEventListener('DOMContentLoaded', () => {
  setCipher('vigenere');
  setInputType('text');
  updateHillMatrixStatus();
  setupEventListeners();
  elements.textCharCount.textContent = `${elements.textInput.value.length} karakter`;
});
