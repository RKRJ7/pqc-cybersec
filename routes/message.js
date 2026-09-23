const express = require("express");
const router = express.Router();
const db = require("../db");
const { page } = require("../views");

router.get("/set-message", (req, res) => {
  if (!req.cookies.username) {
    return res.redirect("/");
  }

  res.send(page("Encrypt File", `
    <h1>📁 Encrypt File</h1>
    <p class="subtitle">Encrypt a file using a Post-Quantum ML-KEM-768 Public Key (KEM + AES-256-GCM).</p>

    <div class="message-box" style="margin-bottom: 20px;">
      <h3>🔑 PQC Key Generator (ML-KEM-768 via liboqs)</h3>
      <p class="subtitle">Need a key pair? Generate a quantum-safe ML-KEM-768 keypair below. Keys never leave your browser.</p>
      <button type="button" id="generate-keys-btn" class="btn btn-blue">Generate ML-KEM-768 Key Pair</button>
      <div id="key-gen-status" class="subtitle" style="margin-top: 8px;"></div>
      <div id="key-download-row" class="button-row" style="display:none; margin-top: 10px;">
        <button type="button" id="download-public-key-btn" class="btn btn-green">💾 Save public_key.pqc</button>
        <button type="button" id="download-private-key-btn" class="btn btn-pink">💾 Save private_key.pqc</button>
      </div>
    </div>

    <form id="message-form" method="POST" action="/set-message">
      <label for="input-file">Select File to Encrypt</label>
      <input type="file" id="input-file" required>

      <label for="public-key-file">Select ML-KEM-768 Public Key File (.pqc / .pem)</label>
      <input type="file" id="public-key-file" accept=".pqc,.pem,.pub,.txt">
      
      <label for="public-key-text">or Paste ML-KEM-768 Public Key</label>
      <textarea id="public-key-text" rows="5" placeholder="-----BEGIN ML-KEM-768 PUBLIC KEY-----&#10;...&#10;-----END ML-KEM-768 PUBLIC KEY-----"></textarea>

      <input type="hidden" name="ciphertext" id="message-ciphertext">
      <input type="hidden" name="iv" id="message-iv">
      <input type="hidden" name="encrypted_key" id="message-encrypted-key">
      <input type="hidden" name="filename" id="message-filename">

      <button type="submit" class="btn btn-yellow" style="margin-top: 15px;">Encrypt & Save File 💾</button>
    </form>
    <p id="message-status" class="subtitle"></p>
    <a href="/account" class="btn btn-pink" style="margin-top: 14px; display:inline-block;">Back</a>

    <script src="/public/ml-kem.js"></script>
    <script src="/public/crypto.js"></script>
    <script>
      (function () {
        let generatedPublicPem = "";
        let generatedPrivatePem = "";

        const genBtn = document.getElementById("generate-keys-btn");
        const keyStatus = document.getElementById("key-gen-status");
        const downloadRow = document.getElementById("key-download-row");
        const pubDownloadBtn = document.getElementById("download-public-key-btn");
        const privDownloadBtn = document.getElementById("download-private-key-btn");

        genBtn.addEventListener("click", async () => {
          keyStatus.textContent = "Generating ML-KEM-768 keypair via liboqs (browser KEM)...";
          try {
            const keys = await window.ClassmateCrypto.generateKeyPair();
            generatedPublicPem = keys.publicKeyPem;
            generatedPrivatePem = keys.privateKeyPem;

            document.getElementById("public-key-text").value = generatedPublicPem;
            keyStatus.textContent = "✅ ML-KEM-768 keypair generated (KEM: " + (keys.kemAlgorithm || "ML-KEM-768") + ")! Save your keys below. Private key never left your browser.";
            downloadRow.style.display = "flex";
          } catch (err) {
            keyStatus.textContent = "Error generating key pair: " + err.message;
          }
        });

        pubDownloadBtn.addEventListener("click", () => {
          if (generatedPublicPem) {
            window.ClassmateCrypto.downloadFile("public_key.pqc", generatedPublicPem, "application/x-pem-file");
          }
        });

        privDownloadBtn.addEventListener("click", () => {
          if (generatedPrivatePem) {
            window.ClassmateCrypto.downloadFile("private_key.pqc", generatedPrivatePem, "application/x-pem-file");
          }
        });

        const form = document.getElementById("message-form");
        const inputFile = document.getElementById("input-file");
        const publicKeyFileInput = document.getElementById("public-key-file");
        const publicKeyTextArea = document.getElementById("public-key-text");
        const status = document.getElementById("message-status");

        form.addEventListener("submit", async (event) => {
          event.preventDefault();

          if (!inputFile.files || inputFile.files.length === 0) {
            status.textContent = "Please select a file to encrypt.";
            return;
          }

          let publicKeyPem = publicKeyTextArea.value.trim();
          if (!publicKeyPem && publicKeyFileInput.files && publicKeyFileInput.files.length > 0) {
            publicKeyPem = await publicKeyFileInput.files[0].text();
          }

          if (!publicKeyPem) {
            status.textContent = "Please upload or paste a valid ML-KEM-768 Public Key.";
            return;
          }

          status.textContent = "Encapsulating KEM shared secret + encrypting file (ML-KEM-768 + AES-256-GCM)...";

          try {
            const file = inputFile.files[0];
            const fileBuffer = await file.arrayBuffer();
            const encrypted = await window.ClassmateCrypto.encryptFile(fileBuffer, publicKeyPem);

            document.getElementById("message-ciphertext").value = encrypted.ciphertext;
            document.getElementById("message-iv").value = encrypted.iv;
            document.getElementById("message-encrypted-key").value = encrypted.encryptedKey;
            document.getElementById("message-filename").value = file.name;

            form.submit();
          } catch (error) {
            console.error(error);
            status.textContent = "Error encrypting file. Ensure the ML-KEM-768 Public Key is valid.";
          }
        });
      })();
    </script>
  `));
});

router.post("/set-message", (req, res) => {
  if (!req.cookies.username) {
    return res.redirect("/");
  }

  const { ciphertext, iv, encrypted_key, filename } = req.body;

  if (!ciphertext || !iv || !encrypted_key) {
    return res.redirect("/set-message");
  }

  db.prepare(`
    UPDATE accounts 
    SET message_ciphertext = ?, message_iv = ?, message_encrypted_key = ?, message_filename = ?
    WHERE username = ?
  `).run(ciphertext, iv, encrypted_key, filename || "encrypted_file.bin", req.cookies.username);

  res.redirect("/account");
});

module.exports = router;
