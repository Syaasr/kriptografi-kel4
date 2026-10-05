# Web Cryptography Tool

Aplikasi berbasis web untuk enkripsi dan dekripsi pesan teks serta file biner menggunakan 7 algoritma kriptosistem klasik. Dikembangkan sebagai pemenuhan Tugas Mata Kuliah Kriptografi Program Studi Informatika, Fakultas MIPA, Universitas Sebelas Maret (UNS) Semester Ganjil 2026/2027.

Aplikasi ini dibangun murni menggunakan **Vanilla JavaScript (ES Modules)**, **HTML5**, dan **CSS3 modern** tanpa ketergantungan pada pustaka kriptografi eksternal maupun server backend. Semua pemrosesan enkripsi dan dekripsi dijalankan 100% secara lokal di sisi klien (*client-side*) dalam peramban web (*browser*).

---

## Daftar Fitur

Aplikasi mengimplementasikan 7 cipher kriptografi klasik sesuai spesifikasi tugas:

1. **Shift Cipher (Caesar Cipher)** — 26 huruf alfabet & byte-by-byte modulo 256.
2. **Substitution Cipher** — Pemetaan substitusi monoalfabetik 26 huruf & S-Box 256-byte.
3. **Affine Cipher** — Enkripsi linear modulo 26 ($C = (aP + b) \pmod{26}$) & modulo 256.
4. **Vigenere Cipher** — Polialfabetik dengan kunci berulang sepanjang pesan teks alfabet (mengabaikan karakter non-alfabet pada output sesuai spesifikasi).
5. **Hill Cipher** — Enkripsi matriks modulo 26 dan modulo 256 (mendukung ukuran matriks $2 \times 2$ dan $3 \times 3$) disertai pemeriksaan determinan dan invers modular.
6. **Permutation (Transposition) Cipher** — Transposisi posisi blok dengan format kunci fleksibel (misal `3 1 4 2` atau `3, 1, 4, 2`).
7. **One-Time Pad (OTP)** — Enkripsi stream menggunakan kunci acak dari file teks/biner dengan panjang $\ge$ panjang pesan. Disertai fitur generator kunci acak otomatis.

### Fitur Antarmuka & Utilitas Tambahan
- **Dua Mode Masukan**:
  - **Text Message**: Mengetik plaintext/ciphertext langsung dengan penghitung karakter dan preset teks contoh.
  - **File Mode (Text & Binary)**: Drag-and-drop file picker untuk memproses dokumen, gambar, arsip, maupun file biner lainnya byte-by-byte.
- **Dua Opsi Format Output Teks**:
  - *Tanpa Spasi (Continuous)*: Contoh `LXFOPVEFRNHR`.
  - *Kelompok 5 Huruf (Groups of 5)*: Contoh `LXFOP VEFRN HR`.
- **Ekspor & Salin Cepat**:
  - Salin hasil ke papan klip (*clipboard*) dengan notifikasi visual.
  - Unduh hasil teks sebagai file `.txt`.
  - Unduh file biner terenkripsi (`.enc` / `.dat`) atau file hasil dekripsi dengan nama asli yang dipulihkan secara otomatis.
- **Integritas Metadata File**: Menyimpan metadata nama file asli dalam format kontainer biner sehingga nama dan ekstensi file asli dapat dipulihkan secara otomatis saat didekripsi.
- **Validasi Input Ramah Pengguna**: Pesan error informatif untuk kunci yang tidak memenuhi syarat matematis (misal determinan Hill atau nilai $a$ pada Affine yang tidak coprime).

---

## Penjelasan Algoritma & Rumus Matematis

### 1. Shift Cipher (Caesar)
- **Alfabet (26 karakter)**: $A=0, B=1, \dots, Z=25$.
- **Rumus Enkripsi**:
  $$C_i = (P_i + k) \pmod{26}$$
- **Rumus Dekripsi**:
  $$P_i = (C_i - k) \pmod{26}$$
- **Mode Biner**: Pemrosesan setiap byte nilai $0..255$ menggunakan modulo 256 ($C = (B + k) \pmod{256}$).

### 2. Substitution Cipher
- **Konsep**: Setiap huruf $A..Z$ dipetakan secara satu-ke-satu (*bijektif*) ke permutasi 26 huruf alfabet yang dimasukkan pengguna (misal: `QWERTYUIOPASDFGHJKLZXCVBNM`).
- **Enkripsi**: $C_i = \text{Key}[P_i]$.
- **Dekripsi**: $P_i = \text{Alfabet}[\text{Posisi } C_i \text{ dalam Key}]$.
- **Mode Biner**: Menghasilkan tabel substitusi S-Box 256-byte deterministik dan tabel invers S-Box dari string kunci pengguna.

### 3. Affine Cipher
- **Rumus Enkripsi**:
  $$C_i = (a \cdot P_i + b) \pmod{26}$$
- **Rumus Dekripsi**:
  $$P_i = a^{-1} \cdot (C_i - b) \pmod{26}$$
  dengan $a^{-1}$ adalah invers perkalian modular dari $a$ modulo 26, yaitu $(a \cdot a^{-1}) \equiv 1 \pmod{26}$.
- **Syarat Validasi**: $\gcd(a, 26) = 1$. Nilai $a$ yang valid pada modulo 26 adalah: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, dan 25.
- **Mode Biner**: Modulo 256 dengan syarat $\gcd(a, 256) = 1$ ($a$ harus berupa bilangan ganjil).

### 4. Vigenere Cipher
- **Rumus Enkripsi**:
  $$C_i = (P_i + K_{i \pmod m}) \pmod{26}$$
- **Rumus Dekripsi**:
  $$P_i = (C_i - K_{i \pmod m} + 26) \pmod{26}$$
- **Ketentuan Tugas**: Hanya karakter alfabet yang dienkripsi. Karakter angka, spasi, dan tanda baca diabaikan/dibersihkan dari ciphertext. Panjang kunci bebas dan diulang sepanjang pesan.
- **Contoh Tugas**:
  - Plaintext: `ATTACKATDAWN`
  - Key: `LEMON`
  - Ciphertext: `LXFOPVEFRNHR`

### 5. Hill Cipher
- **Enkripsi Matriks Blok**:
  $$\mathbf{C} = (\mathbf{K} \cdot \mathbf{P}) \pmod{26}$$
- **Dekripsi Matriks Blok**:
  $$\mathbf{P} = (\mathbf{K}^{-1} \cdot \mathbf{C}) \pmod{26}$$
  $$\mathbf{K}^{-1} = (\det(\mathbf{K})^{-1} \cdot \text{Adj}(\mathbf{K})) \pmod{26}$$
- **Syarat Validasi**: $\gcd(\det(\mathbf{K}), 26) = 1$.
- **Ukuran Matriks**: Mendukung matriks kunci $2 \times 2$ dan $3 \times 3$.
- **Aturan Padding**:
  - Teks: Jika panjang teks bukan kelipatan ukuran blok matriks $n$, teks dipadding dengan huruf `'X'`.
  - Biner: Menggunakan skema padding standar PKCS#7 sehingga panjang dan byte asli dipulihkan secara sempurna saat didekripsi.

### 6. Permutation (Transposition) Cipher
- **Konsep**: Mengubah susunan/urutan posisi huruf dalam blok berukuran $m$.
- **Kunci**: Urutan permutasi posisi indeks (mendukung 1-indexed seperti `3 1 4 2` maupun 0-indexed `2 0 3 1`).
- **Enkripsi**: Blok output $C[j] = P[\pi[j]]$ untuk $j = 0..m-1$.
- **Dekripsi**: Menggunakan permutasi invers $\pi^{-1}$: $P[k] = C[\pi^{-1}[k]]$.
- **Padding**: Huruf `'X'` untuk teks dan PKCS#7 untuk file biner.

### 7. One-Time Pad (OTP)
- **Rumus**:
  $$C_i = (P_i + K_i) \pmod{26}, \quad P_i = (C_i - K_i + 26) \pmod{26}$$
- **Ketentuan Tugas**:
  - Kunci dibaca langsung dari file teks atau file biner eksternal yang diunggah pengguna.
  - Karakter kunci yang digunakan hanya sebanyak panjang karakter pesan ($N$).
  - Sisa kunci yang tidak terpakai dibiarkan dan ditampilkan informasinya pada UI (*Key length*, *Characters used*, *Characters remaining*).

---

## Pemrosesan File & Integritas File Biner

Aplikasi mendukung enkripsi dan dekripsi file teks maupun file biner (gambar JPEG/PNG, dokumen PDF/Word, audio, file `.zip`, dsb.):

1. **Pembacaan Byte Murni**: File dibaca menggunakan JavaScript `FileReader` sebagai `ArrayBuffer` mentah yang dikonversi menjadi `Uint8Array`. File tidak dibaca sebagai string UTF-8 agar seluruh byte header file biner (nilai $0..255$) tetap utuh.
2. **Format Kontainer Terenkripsi**:
   Hasil enkripsi dikemas dalam format kontainer biner terstruktur:
   - `[0..3]` : Magic header `CRYP` (`0x43, 0x52, 0x59, 0x50`)
   - `[4]`    : Versi kontainer (`0x01`)
   - `[5]`    : Panjang string identifier cipher ($L_c$)
   - `[6..]`  : UTF-8 byte identifier cipher
   - `[...]`  : Panjang nama file asli (2 byte Uint16 Big-Endian)
   - `[...]`  : UTF-8 byte nama file asli
   - `[...]`  : Panjang payload terenkripsi (4 byte Uint32 Big-Endian)
   - `[...]`  : Payload data terenkripsi
3. **Pemulihan Otomatis Saat Dekripsi**:
   Saat pengguna mendekripsi file kontainer, aplikasi mendeteksi header `CRYP`, mengekstrak nama file asli, dan secara otomatis menetapkan nama output file yang didekripsi ke nama aslinya. Jika file yang diunggah adalah file biner mentah tanpa kontainer, pengguna dapat mengetikkan nama/ekstensi file output yang diinginkan.
4. **Verifikasi Integritas Byte**:
   Hasil dekripsi menjamin kesamaan byte 100%:
   $$\text{Original Bytes} \equiv \text{Decrypted Bytes}$$

---

## Struktur Direktori Project

```text
crypto-tool/
├── index.html              # Antarmuka web utama
├── package.json            # Konfigurasi Node.js ESM & skrip test
├── README.md               # Dokumentasi lengkap
├── .agents/skills/         # Kustomisasi skill lokal
│   └── crypto-tool/
│       └── SKILL.md
├── css/
│   └── style.css           # Desain CSS mandiri & responsif
├── js/
│   ├── app.js              # Controller utama aplikasi web
│   ├── ciphers/            # Implementasi independen 7 algoritma cipher
│   │   ├── shift.js
│   │   ├── substitution.js
│   │   ├── affine.js
│   │   ├── vigenere.js
│   │   ├── hill.js
│   │   ├── permutation.js
│   │   └── otp.js
│   └── utils/              # Modul pembantu
│       ├── text.js         # Operasi matematika modular & pemformatan teks
│       ├── file.js         # Pengemasan kontainer biner & File API
│       └── validation.js   # Validasi kunci, matriks, dan permutasi
└── tests/                  # Rangkaian pengujian otomatis (Node.js Test Runner)
    ├── utils.test.js
    ├── validation.test.js
    ├── shift.test.js
    ├── substitution.test.js
    ├── affine.test.js
    ├── vigenere.test.js
    ├── hill.test.js
    ├── permutation.test.js
    ├── otp.test.js
    ├── file.test.js
    └── binary_roundtrip.test.js
```

---

## Petunjuk Menjalankan Aplikasi

### Kebutuhan Sistem
- Browser modern (Google Chrome, Mozilla Firefox, Microsoft Edge, Safari, Opera).
- (Opsional untuk testing/local server) Node.js versi 18+ dan Python 3.

### Cara 1: Membuka Langsung di Browser
Buka file `index.html` langsung menggunakan web browser pilihan Anda (klik ganda `index.html` atau *drag & drop* ke jendela peramban).

### Cara 2: Menjalankan Local Web Server
Gunakan server lokal berbasis Python atau Node:

```bash
# Menjalankan local server dengan Python
python3 -m http.server 8000

# Atau menggunakan npm
npm run serve
```

Buka URL berikut di browser:
```text
http://localhost:8000
```

---

## Menjalankan Automated Test Suite

Aplikasi dilengkapi dengan rangkaian unit test dan round-trip test otomatis mencakup seluruh 7 cipher (mode teks dan biner) menggunakan native test runner Node.js:

```bash
npm test
```

Seluruh 66 test case mencakup:
- Validasi matematika modulo, FPB ($\gcd$), dan invers modular.
- Validasi format kunci untuk setiap cipher.
- Enkripsi dan dekripsi teks per algoritma.
- Round-trip integrity file biner untuk semua 7 cipher.
- Pengemasan dan pembongkaran kontainer metadata biner.

---

## Anggota Kelompok

Proyek tugas ini disusun oleh:

- **[Nama Anggota 1]** — NIM: [M05XXXXX]
- **[Nama Anggota 2]** — NIM: [M05XXXXX]
- **[Nama Anggota 3]** — NIM: [M05XXXXX]
- **[Nama Anggota 4]** — NIM: [M05XXXXX]

---

*Program Studi Informatika &bull; Fakultas Matematika dan Ilmu Pengetahuan Alam &bull; Universitas Sebelas Maret*
