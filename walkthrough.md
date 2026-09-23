# 🎓 Complete Codebase Walkthrough & PQC Execution Guide

This document explains **what every part of the code is doing**, **why it is designed this way**, and **which exact functions/lines** are responsible at each stage of the application lifecycle.

---

## 📑 Table of Contents
1. [What is PQC & Why Do We Need It?](#1-what-is-pqc--why-do-we-need-it)
2. [Core Concepts & PQC Architecture (KEM + DEM)](#2-core-concepts--pqc-architecture-kem--dem)
3. [PQC Function Reference (Inputs, Outputs & Internal Operations)](#3-pqc-function-reference-inputs-outputs--internal-operations)
4. [Module Overview (Which file does what)](#4-module-overview-which-file-does-what)
5. [Step 1: User Login & Session Flow](#step-1-user-login--session-flow)
6. [Step 2: Quantum-Safe Key Generation Flow](#step-2-quantum-safe-key-generation-flow)
7. [Step 3: Deep Dive — Hybrid Encryption Flow (`encryptFile`)](#step-3-deep-dive--hybrid-encryption-flow-encryptfile)
8. [Step 4: Server-Side Storage Flow](#step-4-server-side-storage-flow)
9. [Step 5: Deep Dive — Decapsulation & File Decryption (`decryptFile`)](#step-5-deep-dive--decapsulation--file-decryption-decryptfile)
10. [Step 6: Fallback Liboqs Backend (`app.py`)](#step-6-fallback-liboqs-backend-apppy)
11. [Viva Quick Reference (Exact Numbers & Facts)](#viva-quick-reference-exact-numbers--facts)

---

## 1. What is PQC & Why Do We Need It?

### ⚛️ The Quantum Threat (Shor's Algorithm)
* Traditional asymmetric cryptography (RSA, ECC, Diffie-Hellman) relies on mathematical problems:
  * **Integer Factorization** (RSA)
  * **Discrete Logarithms & Elliptic Curves** (ECDH, ECDSA)
* In 1994, Peter Shor published a quantum algorithm that solves both in **polynomial time $O((\log N)^3)$**. When sufficiently large Cryptographically Relevant Quantum Computers (CRQCs) are built, all standard RSA/ECC keys can be broken instantly.
* **"Harvest Now, Decrypt Later" Threat:** Adversaries are intercepting and storing encrypted traffic today to decrypt it later once quantum computers arrive.

### 🛡️ What is Post-Quantum Cryptography (PQC)?
* PQC refers to classical cryptographic algorithms running on standard computers that are mathematically secure against **both quantum and classical computers**.
* The mathematical foundation used here is **Lattice-Based Cryptography**, specifically the **Module Learning with Errors (MLWE)** problem. Solving MLWE requires finding the shortest vector in high-dimensional lattices (SVP/CVP), which is believed to be exponentially hard for both quantum and classical machines.

### 📜 NIST Standardization: ML-KEM-768 (FIPS 203)
* In August 2024, NIST released **FIPS 203**, standardizing **ML-KEM** (Module-Lattice Key Encapsulation Mechanism, originally designed as *CRYSTALS-Kyber*).
* **Security Level 3 (ML-KEM-768):** Offers quantum security equivalent to AES-192 brute force. It is the recommended default standard for general data protection.

---

## 2. Core Concepts & PQC Architecture (KEM + DEM)

### Why KEM (ML-KEM-768) instead of RSA?
* Traditional PKE (like RSA) encrypts the symmetric key directly with the public key. However, Shor's quantum algorithm can factorize RSA moduli in polynomial time.
* **ML-KEM-768** (NIST FIPS 203, formerly *Kyber768*) is a **Key Encapsulation Mechanism** based on lattice mathematics (**Module Learning with Errors / MLWE**).
* **Key Encapsulation (KEM)** does **not** encrypt an external message directly. Instead:
  1. `Encap(pk)` generates a fresh, random 32-byte shared secret **AND** wraps it into a 1088-byte KEM ciphertext (`kem_ct`).
  2. `Decap(sk, kem_ct)` recovers that exact same 32-byte shared secret using the private key.

### The Hybrid Flow (KEM + DEM):
```
[User File (Plaintext)]           [Recipient Public Key (1184 B)]
       │                                       │
       │                                       ▼
       │                          ML-KEM-768 Encap (KEM)
       │                         ┌─────────────┴─────────────┐
       │                         ▼                           ▼
       │                [kem_ciphertext]              [shared_secret]
       │                    (1088 B)                      (32 B)
       │                         │                           │
       │                         │                           ▼
       │                         │                      HKDF-SHA256
       │                         │                           │
       │                         │                           ▼
       │                         │                     [AES-256 Key]
       │                         │                           │
       │    [Random IV (12 B)]   │                           │
       │            │            │                           │
       └────────────┼────────────┼───────────────────────────┘
                    ▼            │
               AES-256-GCM       │
              (Data Encrypt)     │
                    │            │
                    ▼            ▼
             [Ciphertext + Tag] [encrypted_key]
                    │            │
                    └──────┬─────┘
                           ▼
                  Stored in SQLite DB
```

---

## 3. PQC Function Reference (Inputs, Outputs & Internal Operations)

Here is every single PQC-related function used in the codebase:

### 1. `kem.generateKeyPair()`
* **Where:** In [`public/ml-kem.js`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/ml-kem.js) / [`crypto.js:243`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L243) & [`app.py:148`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L148)
* **Inputs:** None.
* **What it does:** Generates a lattice vector polynomial matrix using cryptographically secure random seeds according to NIST FIPS 203 ML-KEM-768 specification.
* **Outputs:** 
  * `publicKey` (Uint8Array, **1184 bytes**) — safe to share publicly.
  * `secretKey` (Uint8Array, **2400 bytes**) — private; stays strictly in browser RAM / local file.

---

### 2. `kem.encap(publicKeyBytes)`
* **Where:** In [`public/ml-kem.js`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/ml-kem.js) / [`crypto.js:295`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L295) & [`app.py:370`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L370)
* **Inputs:** `publicKeyBytes` (Uint8Array, **1184 bytes**).
* **What it does:** Samples a fresh random 32-byte shared secret, performs polynomial matrix multiplication with the public key, and encapsulates the secret.
* **Outputs:** An object `{ ciphertext, sharedSecret }`:
  * `ciphertext` (Uint8Array, **1088 bytes**) — The KEM ciphertext (`kem_ct`) sent to the recipient.
  * `sharedSecret` (Uint8Array, **32 bytes**) — The agreed raw secret entropy.

---

### 3. `kem.decap(ciphertextBytes, secretKeyBytes)`
* **Where:** In [`public/ml-kem.js`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/ml-kem.js) / [`crypto.js:342`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L342) & [`app.py:421`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L421)
* **Inputs:**
  * `ciphertextBytes` (Uint8Array, **1088 bytes**).
  * `secretKeyBytes` (Uint8Array, **2400 bytes**).
* **What it does:** Uses the secret key to compute the inner product of lattice polynomials, reversing the encapsulation and performing implicit rejection verification (Fujisaki-Okamoto transform) to protect against chosen-ciphertext attacks (IND-CCA2).
* **Outputs:** `sharedSecret` (Uint8Array, **32 bytes**) — Identical to the sender's 32-byte secret.

---

### 4. `deriveAesKey(sharedSecret)` / `hkdf_sha256(...)`
* **Where:** In [`public/crypto.js:228`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L228) & [`app.py:111`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L111)
* **Inputs:** `sharedSecret` (32 bytes).
* **What it does:** Runs HKDF-SHA256 (RFC 5869):
  1. `Extract`: $PRK = \text{HMAC-SHA256}(salt=32 \text{ zeros}, IKM=sharedSecret)$
  2. `Expand`: $OKM = \text{HMAC-SHA256}(PRK, \text{info} \parallel 0x01)$ using context info: `"ClassmateHub-ML-KEM-768-AES-256-GCM-v1"`.
* **Outputs:** `aesKeyBytes` (Uint8Array, **32 bytes / 256-bit key**) for AES-256-GCM.
* **Why:** Adds application domain separation so the same KEM secret in a different app cannot produce the same AES key.

---

### 5. `window.ClassmateCrypto.encryptFile(fileArrayBuffer, publicKeyPem)`
* **Where:** In [`public/crypto.js:292-330`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L292-L330)
* **Inputs:**
  * `fileArrayBuffer` (ArrayBuffer of raw file bytes).
  * `publicKeyPem` (String with PEM public key).
* **What it does:** Orchestrates:
  1. `parsePublicKeyPem()` → `kem.encap()`
  2. `deriveAesKey()` → HKDF
  3. `crypto.subtle.encrypt({ name: "AES-GCM", iv: 12-byte-random })`
* **Outputs:**
  ```javascript
  {
    ciphertext: "<Base64 string of file ciphertext + 16B tag>",
    iv: "<Base64 string of 12-byte IV>",
    encryptedKey: "<Base64 string of 1088-byte KEM ciphertext>"
  }
  ```

---

### 6. `window.ClassmateCrypto.decryptFile(ciphertextBase64, ivBase64, encryptedKeyBase64, privateKeyPem)`
* **Where:** In [`public/crypto.js:332-361`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L332-L361)
* **Inputs:** 4 Base64/PEM strings matching the stored database record and user's private key.
* **What it does:** Orchestrates:
  1. `parsePrivateKeyPem()` → `kem.decap(encryptedKey, privateKey)` → `sharedSecret`
  2. `deriveAesKey(sharedSecret)` → `aesKey`
  3. `crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext)`
* **Outputs:** `ArrayBuffer` containing the original decrypted file plaintext.


---

## 2. Module Overview (Which file does what)

| File | Primary Role & Responsibility |
| :--- | :--- |
| [`public/ml-kem.js`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/ml-kem.js) | Bundled browser engine for NIST FIPS 203 ML-KEM-768 (pure JS / WebAssembly). |
| [`public/crypto.js`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js) | Client-side cryptographic orchestrator: Keygen, HKDF, AES-256-GCM encrypt/decrypt, PEM parser. |
| [`app.py`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py) | Flask web server, HTML template renderer, SQLite storage for ciphertext blobs, and `liboqs` fallback routes. |
| [`db.py`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/db.py) / [`db.js`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/db.js) | Database initialization & migration scripts (adds `message_ciphertext`, `message_iv`, `message_encrypted_key`, `message_filename`). |

---

## Step 1: User Login & Session Flow

### What happens in UI:
User visits `/`, enters username/password, and clicks **"Log In 🚀"**.

### Code Segments Responsible:
1. **Frontend Form:** Rendered by `login_form()` in [`app.py:125-137`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L125-L137).
2. **Backend Authentication:** Handled in [`app.py:199-221`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L199-L221).
   ```python
   # Raw string concatenation intentionally kept for SQL-injection academic demo:
   check_query = "SELECT * FROM accounts WHERE username = '" + username + "' AND password = '" + password + "'"
   cursor.execute(check_query)
   ```
3. **Session Setting:** If user exists, Flask writes a plain cookie `res.set_cookie("username", match["username"])` and redirects to `/account`.

---

## Step 2: Quantum-Safe Key Generation Flow

### What happens in UI:
On `/set-message`, user clicks **"Generate ML-KEM-768 Key Pair"**.

### Code Segments Responsible:
1. **UI Button Handler:** [`app.py:506-520`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L506-L520)
   ```javascript
   const keys = await window.ClassmateCrypto.generateKeyPair();
   ```
2. **Backend KEM Execution:** Inside [`public/crypto.js:243-290`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L243-L290)
   * Calls `kem.generateKeyPair()` from `ml-kem.js`:
     * **Public Key:** 1184 bytes (Uint8Array)
     * **Secret Key:** 2400 bytes (Uint8Array)
   * Wraps bytes in standard PEM headers via `encodePublicKeyToPem()` and `encodePrivateKeyToPem()`.
3. **Why this design?**
   * **The Private Key never leaves the browser's RAM.** It is never POSTed to Flask in normal operation.
4. **Download Handler:** [`app.py:521-531`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L521-L531) calls `downloadFile()` to save `public_key.pqc` and `private_key.pqc`.

---

## Step 3: Deep Dive — Hybrid Encryption Flow (`encryptFile`)

You asked specifically about:
```javascript
const fileBuffer = await file.arrayBuffer();
const encrypted = await window.ClassmateCrypto.encryptFile(fileBuffer, publicKeyPem);
```

Here is the exact breakdown of what this line does, why it exists, and which functions execute:

### 1. `const fileBuffer = await file.arrayBuffer();`
* **Where:** Form submit listener in [`app.py:548`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L548).
* **What it does:** Reads the raw binary bytes of the selected file into browser memory as an `ArrayBuffer` so the crypto engine can process arbitrary files (images, PDFs, text, zip, etc.).

### 2. `ClassmateCrypto.encryptFile(fileBuffer, publicKeyPem)`
* **Where:** Defined in [`public/crypto.js:292-330`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L292-L330).
* **Step-by-Step Internal Execution:**

  #### A. Parse & Validate Public Key ([`crypto.js:106-115`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L106-L115)):
  ```javascript
  var publicKeyBytes = parsePublicKeyPem(publicKeyPem);
  ```
  Strips the `-----BEGIN ML-KEM-768 PUBLIC KEY-----` wrapper, base64-decodes it to raw bytes, and asserts that `publicKeyBytes.length === 1184`.

  #### B. KEM Encapsulation ([`crypto.js:295-299`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L295-L299)):
  ```javascript
  var encapOut = await kem.encap(publicKeyBytes);
  var kemCiphertext = encapOut.ciphertext;   // Exactly 1088 bytes
  var sharedSecret = encapOut.sharedSecret; // Exactly 32 uniform random bytes
  ```
  * **Work done:** Uses ML-KEM-768 lattice math to generate a random 32-byte secret and encapsulate it into a 1088-byte ciphertext that only the corresponding private key can decapsulate.

  #### C. Key Derivation via HKDF-SHA256 ([`crypto.js:228-237`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L228-L237) & [`crypto.js:205-226`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L205-L226)):
  ```javascript
  var aesKeyBytes = await deriveAesKey(sharedSecret);
  sharedSecret.fill(0); // Zeroized immediately for memory hygiene
  ```
  * **Work done:** Runs RFC 5869 HKDF:
    * `Extract`: PRK = HMAC-SHA256(salt=32 zeros, IKM=sharedSecret)
    * `Expand`: Expands PRK with domain string `"ClassmateHub-ML-KEM-768-AES-256-GCM-v1"` to generate a 32-byte (256-bit) AES key.

  #### D. Symmetric Encryption via AES-256-GCM ([`crypto.js:308-320`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L308-L320)):
  ```javascript
  var iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit random nonce
  var ciphertextBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      fileBytes
  );
  ```
  * **Work done:** Encrypts file payload using authenticated AES-GCM mode. Output is `[Ciphertext bytes] + [16-byte GHASH Authentication Tag]`.

  #### E. Return Base64 Object ([`crypto.js:324-328`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L324-L328)):
  ```javascript
  return {
      ciphertext: arrayBufferToBase64(ciphertextBuffer),
      iv: arrayBufferToBase64(iv),
      encryptedKey: arrayBufferToBase64(kemCiphertext)
  };
  ```

---

## Step 4: Server-Side Storage Flow

### What happens:
The hidden inputs on the form are filled with Base64 values and POSTed to `/set-message`.

### Code Segment Responsible:
* **Server Route:** [`@app.route("/set-message", methods=["POST"])` in app.py:579-608](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L579-L608).
* **What it does:**
  ```python
  cursor.execute("""
      UPDATE accounts 
      SET message_ciphertext = ?, message_iv = ?, message_encrypted_key = ?, message_filename = ?
      WHERE username = ?
  """, (ciphertext, iv, encrypted_key, filename, username))
  ```
* **Viva Note:** Flask does **not** interpret or decrypt this data. It acts as an opaque binary blob storage.

---

## Step 5: Deep Dive — Decapsulation & File Decryption (`decryptFile`)

### What happens in UI:
On `/account`, the user uploads or pastes their **Private Key (`.pqc`)** and clicks **"Decrypt File 🔓"**.

### Code Segments Responsible:

1. **Injecting Saved Blobs:** [`app.py:227-248`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L227-L248) embeds data attributes:
   ```html
   <div class="message-box" id="locked-message"
        data-ciphertext="{{ me['message_ciphertext'] }}"
        data-iv="{{ me['message_iv'] }}"
        data-encrypted-key="{{ me['message_encrypted_key'] }}"
        data-filename="{{ filename }}">
   ```
2. **Unlock Click Handler:** [`app.py:302-337`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L302-L337) reads the private key and calls:
   ```javascript
   decryptedBuffer = await window.ClassmateCrypto.decryptFile(ciphertext, iv, encryptedKey, privateKeyPem);
   ```
3. **Internal Decryption Execution in [`public/crypto.js:332-361`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L332-L361):**
   * **Step A:** `parsePrivateKeyPem(privateKeyPem)` asserts secret key is **2400 bytes**.
   * **Step B:** `kem.decap(kemCiphertext, secretKeyBytes)`:
     * Takes the 1088-byte KEM ciphertext + 2400-byte private key.
     * Decapsulates and recovers the identical **32-byte shared secret**.
   * **Step C:** `deriveAesKey(sharedSecret)` derives the exact same 32-byte AES key using the matching HKDF info string.
   * **Step D:** `crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, aesKey, ciphertextBuffer)`:
     * Decrypts the file and verifies the 16-byte GCM authentication tag.
     * *If private key is wrong or ciphertext is modified, it fails immediately with an integrity error.*
4. **Rendering & Download:**
   * Text files are decoded via `new TextDecoder("utf-8").decode(decryptedBuffer)` and displayed.
   * Binary files are downloaded using `ClassmateCrypto.downloadFile()`.

---

## Step 6: Fallback Liboqs Backend (`app.py`)

### Why does this exist?
If the app is opened on non-localhost HTTP (e.g. `http://192.168.1.50:3000`), modern web browsers disable `crypto.subtle` due to insecure context rules.

### How it works:
[`crypto.js:68-75`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/public/crypto.js#L68-L75) checks `hasSubtleCrypto()`. If false, calls:
1. **`/generate-keys`** ([`app.py:148-181`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L148-L181)): Uses Python `oqs.KeyEncapsulation("ML-KEM-768").generate_keypair()`.
2. **`/encrypt-file`** ([`app.py:355-398`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L355-L398)): Uses `kem.encap_secret()`, `derive_aes_key()`, and `_aes_gcm_encrypt()`.
3. **`/decrypt-file`** ([`app.py:400-449`](file:///home/kunal/cyber-sec/Assignment-1/assignment-1-group-3/app.py#L400-L449)): Uses `kem.decap_secret()`, `derive_aes_key()`, and `_aes_gcm_decrypt()`.

---

## 📊 Viva Quick Reference (Exact Numbers & Facts)

| Parameter | Exact Size | Purpose |
| :--- | :--- | :--- |
| **ML-KEM-768 Public Key** | **1184 Bytes** | Shared publicly; used to encapsulate shared secrets. |
| **ML-KEM-768 Secret Key** | **2400 Bytes** | Kept in browser/local file; used to decapsulate shared secrets. |
| **KEM Ciphertext (`kem_ct`)** | **1088 Bytes** | Transmitted alongside file ciphertext; encapsulates the 32B secret. |
| **KEM Shared Secret** | **32 Bytes** | Quantum-agreed entropy fed into HKDF. |
| **AES Key Size** | **32 Bytes (256-bit)** | Symmetric key for AES-GCM data encryption. |
| **AES-GCM IV (Nonce)** | **12 Bytes (96-bit)** | Fresh random IV generated per file to ensure semantic security. |
| **GCM Auth Tag** | **16 Bytes (128-bit)** | Appended to ciphertext; guarantees file integrity against tampering. |
| **HKDF Info String** | `"ClassmateHub-ML-KEM-768-AES-256-GCM-v1"` | Provides application-level domain separation. |
