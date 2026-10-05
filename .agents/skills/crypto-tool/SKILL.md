---
name: crypto-tool
description: Instructions and guidelines for maintaining, testing, and extending the Web Cryptography Tool.
---

# Web Cryptography Tool

This workspace contains a pure client-side Vanilla JavaScript web application implementing 7 classical cryptosystems and binary file processing for the UNS Cryptography course assignment.

## Directory Structure

```text
.
├── index.html              # Main HTML markup
├── README.md               # User & technical documentation
├── package.json            # Node.js configuration for ESM testing
├── css/
│   └── style.css           # Custom CSS styling (dark slate theme)
├── js/
│   ├── app.js              # Application controller & UI event binder
│   ├── ciphers/            # Modular cryptographic algorithm implementations
│   │   ├── shift.js        # Shift Cipher (Caesar)
│   │   ├── substitution.js # Monoalphabetic Substitution Cipher
│   │   ├── affine.js       # Affine Cipher
│   │   ├── vigenere.js     # Vigenere Cipher (26 letters)
│   │   ├── hill.js         # Hill Cipher (2x2 and 3x3 matrices)
│   │   ├── permutation.js  # Permutation (Transposition) Cipher
│   │   └── otp.js          # One-Time Pad Cipher
│   └── utils/
│       ├── text.js         # Modular arithmetic & text utilities
│       ├── file.js         # Binary container & browser File API
│       └── validation.js   # Input and matrix/permutation validation
└── tests/                  # Automated unit and round-trip tests
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

## Running Automated Tests

Run tests using the native Node.js test runner:
```bash
npm test
```

## Running the Web Application Locally

Run the built-in HTTP server:
```bash
npm run serve
# or
python3 -m http.server 8000
```
Open `http://localhost:8000` in any modern web browser.
