# PLAN.md --- Web Cryptography Tool

## 1. Tujuan Project

Buat aplikasi web GUI untuk tugas mata kuliah Kriptografi UNS Semester
Ganjil 2026/2027.

Aplikasi adalah **Cryptography Tool** berbasis web yang
mengimplementasikan 7 kriptosistem sederhana:

1.  Shift Cipher --- 26 huruf alfabet
2.  Substitution Cipher --- 26 huruf alfabet
3.  Affine Cipher --- 26 huruf alfabet
4.  Vigenere Cipher --- 26 huruf alfabet
5.  Hill Cipher --- 26 huruf alfabet
6.  Permutation Cipher --- 26 huruf alfabet
7.  One-Time Pad

Bahasa utama: **Vanilla JavaScript**, HTML, dan CSS. Jangan menggunakan
backend jika tidak diperlukan.

> Penting: implementasikan algoritma sendiri berdasarkan rumus/konsep
> kriptografi. Jangan menyalin source code dari website atau repository
> lain.

------------------------------------------------------------------------

## 2. Acuan Spesifikasi Tugas

Program harus:

-   menerima pesan yang diketik pengguna;
-   menerima file, termasuk file teks maupun file biner;
-   dapat melakukan enkripsi;
-   dapat melakukan dekripsi;
-   untuk pesan teks, menampilkan plaintext dan ciphertext;
-   menyediakan tampilan ciphertext:
    -   tanpa spasi;
    -   dikelompokkan setiap 5 huruf;
-   dapat menyimpan/mengunduh ciphertext ke file;
-   key dimasukkan oleh pengguna dan panjangnya bebas;
-   file biner diproses byte-by-byte, termasuk byte header;
-   file yang telah dienkripsi tidak harus dapat dibuka langsung sebagai
    file aslinya;
-   setelah didekripsi, file harus dapat digunakan kembali;
-   format file ciphertext boleh menggunakan ekstensi seperti `.dat`;
-   boleh menyimpan metadata nama/ekstensi file asli agar proses
    dekripsi lebih mudah.

Khusus Vigenere, tugas menetapkan bahwa yang dienkripsi hanya karakter
alfabet. Angka, spasi, dan tanda baca diabaikan/dibuang ketika
ciphertext ditampilkan atau disimpan.

Untuk One-Time Pad, key berasal dari file teks berisi huruf-huruf yang
dibangkitkan secara acak. Key yang digunakan sepanjang karakter pesan,
sedangkan sisa key tidak digunakan.

------------------------------------------------------------------------

## 3. Target UI

Buat UI yang terinspirasi dari contoh antarmuka pada soal, tetapi
**jangan menyalin desain secara persis**.

Konsep layout:

``` text
┌──────────────────────────────────────────────────────────┐
│                  CRYPTOGRAPHY TOOL                        │
│       Simple Cryptography Implementation Web App          │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Input Type                                               │
│  [ Text ▼ ]                                               │
│                                                          │
│  Cipher                                                   │
│  [ Vigenere Cipher ▼ ]                                   │
│                                                          │
│  Input Message / File                                    │
│  ┌────────────────────────────────────────────────────┐  │
│  │                                                    │  │
│  │  Type your plaintext or ciphertext here...         │  │
│  │                                                    │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  [ Choose File ]                                         │
│                                                          │
│  Key                                                      │
│  ┌────────────────────────────────────────────────────┐  │
│  │ LEMON                                              │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  Output Format                                           │
│  ○ Continuous     ○ Groups of 5                         │
│                                                          │
│  [ Encrypt ]                         [ Decrypt ]         │
│                                                          │
├──────────────────────────────────────────────────────────┤
│  RESULT                                                   │
│                                                          │
│  Plaintext / Input                                       │
│  ┌────────────────────────────────────────────────────┐  │
│  │ ATTACKATDAWN                                       │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  Ciphertext / Output                                     │
│  ┌────────────────────────────────────────────────────┐  │
│  │ LXFOPVEFRNHR                                       │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  [ Copy ]                     [ Download ]               │
└──────────────────────────────────────────────────────────┘
```

### Prinsip visual

-   Modern, bersih, profesional, dan sederhana.
-   Tidak perlu terlalu banyak animasi.
-   Fokus pada usability.
-   Responsive untuk desktop dan laptop.
-   Gunakan card/panel dengan hierarchy yang jelas.
-   Cipher dan mode operasi mudah ditemukan.
-   Tombol Encrypt dan Decrypt harus menjadi CTA utama.
-   Hasil harus mudah dibaca dan mudah disalin.
-   Jangan menggunakan desain yang identik dengan screenshot referensi.
-   Gunakan CSS sendiri.

------------------------------------------------------------------------

## 4. Struktur Project

Gunakan struktur modular:

``` text
crypto-tool/
├── index.html
├── README.md
├── css/
│   └── style.css
└── js/
    ├── app.js
    ├── ciphers/
    │   ├── shift.js
    │   ├── substitution.js
    │   ├── affine.js
    │   ├── vigenere.js
    │   ├── hill.js
    │   ├── permutation.js
    │   └── otp.js
    └── utils/
        ├── text.js
        ├── file.js
        └── validation.js
```

Jika diperlukan, boleh menyesuaikan struktur selama pemisahan tanggung
jawab tetap jelas.

------------------------------------------------------------------------

## 5. Arsitektur Program

Gunakan pendekatan modular.

UI tidak boleh mengetahui detail implementasi setiap cipher.

Setiap cipher idealnya menyediakan interface:

``` javascript
encrypt(input, key)
decrypt(input, key)
```

Untuk cipher yang memiliki parameter khusus, parameter dapat diberikan
melalui object/options.

Contoh:

``` javascript
cipher.encrypt(input, {
    key,
    ...
});
```

`app.js` bertugas sebagai controller:

``` text
UI
 ↓
app.js
 ↓
selected cipher
 ↓
encrypt/decrypt
 ↓
format output
 ↓
UI
```

------------------------------------------------------------------------

## 6. Cipher yang Harus Diimplementasikan

### 6.1 Shift Cipher

Gunakan alfabet 26 karakter:

``` text
A = 0
B = 1
...
Z = 25
```

Rumus:

``` text
C = (P + k) mod 26
P = (C - k) mod 26
```

UI harus menyediakan input nilai shift/key.

Validasi: - shift harus berupa bilangan; - normalisasi shift ke rentang
0--25.

------------------------------------------------------------------------

### 6.2 Substitution Cipher

Gunakan pemetaan alfabet 26 karakter.

Contoh konsep:

``` text
Plain : ABCDEFGHIJKLMNOPQRSTUVWXYZ
Cipher: QWERTYUIOPASDFGHJKLZXCVBNM
```

Key harus merepresentasikan permutasi 26 huruf.

Validasi: - key harus memiliki tepat 26 huruf alfabet; - setiap huruf
harus muncul tepat satu kali; - case dinormalisasi.

Sediakan: - encrypt; - decrypt; - validasi key yang jelas.

------------------------------------------------------------------------

### 6.3 Affine Cipher

Gunakan:

``` text
C = (aP + b) mod 26
```

Dekripsi:

``` text
P = a⁻¹(C - b) mod 26
```

Validasi bahwa `gcd(a, 26) = 1`, sehingga inverse modulo tersedia.

Nilai `a` yang valid harus coprime terhadap 26.

UI menyediakan: - parameter `a`; - parameter `b`.

------------------------------------------------------------------------

### 6.4 Vigenere Cipher

Gunakan alfabet 26 huruf.

Pemetaan:

``` text
A = 0
B = 1
...
Z = 25
```

Enkripsi:

``` text
Cᵢ = (Pᵢ + Kᵢ) mod 26
```

Dekripsi:

``` text
Pᵢ = (Cᵢ - Kᵢ + 26) mod 26
```

Ketentuan khusus tugas:

-   hanya karakter alfabet yang dienkripsi;
-   angka, spasi, dan tanda baca diabaikan/dibuang ketika ciphertext
    ditampilkan/disimpan;
-   key dapat memiliki panjang bebas;
-   key diulang sepanjang plaintext alfabet.

Contoh:

``` text
Plaintext : ATTACKATDAWN
Key       : LEMON
Ciphertext: LXFOPVEFRNHR
```

Pastikan implementasi mengikuti spesifikasi tugas, bukan sekadar contoh
umum Vigenere.

------------------------------------------------------------------------

### 6.5 Hill Cipher

Gunakan alfabet 26 karakter dan operasi matriks modulo 26.

UI harus memungkinkan pengguna memasukkan matrix key.

Contoh minimal:

``` text
[ 3  3 ]
[ 2  5 ]
```

Implementasi harus mencakup:

-   perkalian matriks;
-   modulo 26;
-   determinant;
-   inverse matrix modulo 26;
-   validasi bahwa matrix memiliki inverse modulo 26;
-   padding jika panjang plaintext tidak sesuai ukuran blok.

Jika padding digunakan, dokumentasikan aturan padding dengan jelas.

------------------------------------------------------------------------

### 6.6 Permutation Cipher

Implementasikan permutation/transposition berdasarkan permutasi
alfabet/posisi sesuai konsep tugas.

UI harus menyediakan key permutation.

Validasi: - key merupakan permutasi valid; - tidak ada posisi yang
duplikat; - jumlah elemen sesuai kebutuhan algoritma.

Dokumentasikan format key yang digunakan pada README.

------------------------------------------------------------------------

### 6.7 One-Time Pad

Gunakan alfabet 26 huruf.

Untuk input teks:

``` text
Cᵢ = (Pᵢ + Kᵢ) mod 26
Pᵢ = (Cᵢ - Kᵢ) mod 26
```

Ketentuan tugas:

-   key dibaca dari file teks;
-   key berisi huruf yang dibangkitkan secara acak;
-   panjang key sebaiknya sangat panjang;
-   key yang digunakan hanya sepanjang karakter pesan;
-   sisa key tidak digunakan.

UI OTP harus menyediakan:

``` text
[ Choose Key File ]
```

dan menampilkan informasi:

``` text
Key file
Key length
Characters used
Characters remaining
```

Jangan menyimpan seluruh key ke output jika tidak diperlukan.

------------------------------------------------------------------------

## 7. Text Mode

Jika `Input Type = Text`:

Tampilkan textarea:

``` text
Input Message
```

dan input key sesuai cipher.

Setelah proses:

``` text
Plaintext
Ciphertext
```

Ciphertext memiliki pilihan:

``` text
Continuous:
LXFOPVEFRNHR

Groups of 5:
LXFOP VEFRN HR
```

Gunakan fungsi formatter terpisah agar algoritma cipher tidak bercampur
dengan presentation logic.

------------------------------------------------------------------------

## 8. File Mode

Jika `Input Type = File`:

Tampilkan:

``` text
[ Choose File ]

Selected file:
example.jpg
Size:
Type:
```

Gunakan JavaScript File API.

Untuk file binary: - baca sebagai `ArrayBuffer`; - ubah menjadi
`Uint8Array`; - proses byte secara langsung; - jangan menganggap file
binary sebagai UTF-8 text.

Hasil enkripsi dapat di-download sebagai file ciphertext.

Gunakan ekstensi default yang aman, misalnya:

``` text
original-name.ext.enc
```

atau `.dat`.

Jika metadata nama file asli disimpan, gunakan format internal yang
terdokumentasi dan pastikan proses decrypt dapat mengembalikan byte
asli.

------------------------------------------------------------------------

## 9. File Decryption

Saat decrypt file:

``` text
Cipher file
    ↓
Read bytes
    ↓
Decrypt
    ↓
Restore original bytes
    ↓
Download
```

Pengguna harus dapat memilih nama/ekstensi output jika metadata asli
tidak tersedia.

Contoh:

``` text
Output filename:
[ restored-image.jpg ]
```

Setelah decrypt, byte hasil harus sama dengan byte plaintext sebelum
encrypt.

------------------------------------------------------------------------

## 10. Binary File Integrity

Sediakan pengujian otomatis/manual:

``` text
Original file
     ↓
Encrypt
     ↓
Decrypt
     ↓
Compare bytes
```

Target:

``` text
Original bytes === Decrypted bytes
```

Gunakan checksum/hash hanya sebagai alat verifikasi jika diperlukan.

Tidak perlu menggunakan library kriptografi eksternal untuk algoritma
tugas.

------------------------------------------------------------------------

## 11. UI Behavior

Dropdown cipher mengubah parameter secara dinamis.

Contoh:

### Shift

``` text
Key / Shift
[ 3 ]
```

### Affine

``` text
a [ 5 ]
b [ 8 ]
```

### Hill

``` text
Matrix size
[ 2 x 2 ]

[ 3 ] [ 3 ]
[ 2 ] [ 5 ]
```

### Substitution

``` text
Alphabet key
[ QWERTYUIOPASDFGHJKLZXCVBNM ]
```

### Vigenere

``` text
Key
[ LEMON ]
```

### OTP

``` text
Key file
[ Choose File ]
```

### Permutation

``` text
Permutation key
[ 3 1 4 2 ]
```

------------------------------------------------------------------------

## 12. Validation & Error Handling

Jangan membiarkan aplikasi crash.

Gunakan error message yang mudah dipahami.

Contoh:

``` text
Key tidak boleh kosong.
```

``` text
Substitution key harus terdiri dari 26 huruf unik.
```

``` text
Nilai a tidak valid. gcd(a, 26) harus sama dengan 1.
```

``` text
Hill key matrix tidak memiliki inverse modulo 26.
```

``` text
OTP key lebih pendek daripada pesan.
```

``` text
File belum dipilih.
```

Error ditampilkan dekat dengan field terkait.

------------------------------------------------------------------------

## 13. Security/Privacy

Karena aplikasi berjalan client-side:

-   jangan upload file pengguna ke server;
-   semua proses dilakukan di browser;
-   jangan menyimpan plaintext/key ke localStorage kecuali memang
    dibutuhkan;
-   jangan menggunakan API eksternal untuk encryption.

Tambahkan informasi kecil di UI:

``` text
All encryption and decryption are processed locally in your browser.
```

------------------------------------------------------------------------

## 14. Testing

Buat test cases untuk setiap cipher.

Minimal setiap cipher memiliki:

1.  encrypt sederhana;
2.  decrypt kembali;
3.  hasil decrypt harus sama dengan plaintext yang diproses;
4.  input kosong;
5.  key invalid;
6.  karakter non-alfabet;
7.  edge cases.

Contoh Vigenere:

``` text
Plaintext:
ATTACKATDAWN

Key:
LEMON

Expected:
LXFOPVEFRNHR
```

Round trip:

``` text
plaintext
 → encrypt
 → ciphertext
 → decrypt
 → plaintext
```

Harus menghasilkan plaintext yang sama setelah normalisasi sesuai aturan
cipher.

------------------------------------------------------------------------

## 15. README.md

README wajib menjelaskan:

### Project

Nama aplikasi dan tujuan.

### Features

Daftar 7 cipher.

### Requirements

Browser modern.

### Run

Karena Vanilla JS, cukup:

``` text
Buka index.html
```

atau gunakan local server:

``` bash
python -m http.server 8000
```

kemudian buka:

``` text
http://localhost:8000
```

### Cipher Explanation

Berikan penjelasan singkat rumus setiap cipher.

### Input/Output

Jelaskan text mode dan file mode.

### File Encryption

Jelaskan bagaimana binary file diproses.

### Team

Sediakan placeholder:

``` text
- Nama — NIM
- Nama — NIM
- Nama — NIM
- Nama — NIM
```

------------------------------------------------------------------------

## 16. Development Rules untuk AI Agent

AI agent harus mengikuti aturan:

1.  Jangan menyalin source code dari repository/website lain.
2.  Jangan menggunakan library encryption yang langsung menyediakan
    algoritma tugas.
3.  Implementasikan algoritma sendiri.
4.  Gunakan struktur kode modular.
5.  Jangan mengubah spesifikasi algoritma hanya demi kemudahan
    implementasi.
6.  Jangan menghapus fitur hanya karena implementasinya sulit.
7.  Jika ada bagian spesifikasi yang ambigu, dokumentasikan asumsi
    implementasinya.
8.  Prioritaskan correctness sebelum visual polish.
9.  Setelah setiap cipher selesai, lakukan round-trip test.
10. Pastikan UI tidak rusak ketika cipher diganti.
11. Jangan menggunakan backend untuk fitur yang dapat dilakukan
    client-side.
12. Jangan menambahkan dependency yang tidak diperlukan.

------------------------------------------------------------------------

## 17. Urutan Implementasi

Jangan membuat seluruh aplikasi sekaligus.

Kerjakan bertahap:

### Phase 1 --- Foundation

-   Buat HTML.
-   Buat CSS.
-   Buat layout utama.
-   Buat cipher selector.
-   Buat input type selector.
-   Buat dynamic parameter panel.
-   Buat result panel.

### Phase 2 --- Basic Ciphers

Implementasikan:

``` text
Shift
Substitution
Affine
```

Kemudian testing.

### Phase 3 --- Vigenere

Implementasikan Vigenere sesuai aturan 26 alfabet.

Testing dengan:

``` text
ATTACKATDAWN
LEMON
LXFOPVEFRNHR
```

### Phase 4 --- Advanced Ciphers

Implementasikan:

``` text
Hill
Permutation
One-Time Pad
```

### Phase 5 --- File Handling

Implementasikan:

-   file picker;
-   text file;
-   binary file;
-   ArrayBuffer;
-   Uint8Array;
-   encrypt file;
-   decrypt file;
-   download result.

### Phase 6 --- Output Formatting

Implementasikan:

-   continuous;
-   groups of 5;
-   copy;
-   download.

### Phase 7 --- Testing

Test seluruh cipher dan file round-trip.

### Phase 8 --- Polish

-   responsive;
-   error handling;
-   loading/progress state jika diperlukan;
-   accessibility;
-   README;
-   cleanup code.

------------------------------------------------------------------------

## 18. Definition of Done

Project dianggap selesai jika:

-   [ ] Semua 7 cipher tersedia.
-   [ ] Encrypt tersedia.
-   [ ] Decrypt tersedia.
-   [ ] Text input tersedia.
-   [ ] File input tersedia.
-   [ ] Binary file diproses sebagai byte.
-   [ ] Ciphertext dapat ditampilkan continuous.
-   [ ] Ciphertext dapat ditampilkan groups of 5.
-   [ ] Ciphertext dapat di-download.
-   [ ] Key dapat dimasukkan sesuai cipher.
-   [ ] OTP dapat membaca key dari file.
-   [ ] Error validation tersedia.
-   [ ] Encrypt → decrypt menghasilkan plaintext/byte asli.
-   [ ] UI menyerupai konsep contoh pada soal tetapi bukan salinan.
-   [ ] README tersedia.
-   [ ] Kode modular.
-   [ ] Tidak menggunakan source code hasil copy dari sumber lain.
-   [ ] Project dapat dijalankan secara lokal tanpa konfigurasi backend.

------------------------------------------------------------------------

## 19. Prioritas

Prioritas pengerjaan:

``` text
1. Correctness algoritma
2. Encrypt/decrypt round-trip
3. File handling
4. Validation
5. UI/UX
6. Responsive design
7. Documentation
```

Jangan mengejar UI cantik jika algoritmanya belum benar.

------------------------------------------------------------------------

## 20. Instruksi Akhir untuk AI Agent

Mulai dengan membaca seluruh repository yang tersedia.

Sebelum coding:

1.  buat struktur project;
2.  jelaskan secara singkat rencana implementasi;
3.  implementasikan foundation UI;
4.  implementasikan cipher satu per satu;
5.  test setiap cipher sebelum lanjut;
6.  implementasikan file processing;
7.  lakukan end-to-end testing;
8.  perbaiki bug;
9.  buat README.

Jangan hanya membuat mockup UI. Hasil akhir harus berupa **aplikasi web
yang benar-benar berfungsi**.

Jangan menunggu semua fitur sempurna untuk mulai testing. Setelah setiap
modul selesai, langsung validasi dengan test case yang relevan.
