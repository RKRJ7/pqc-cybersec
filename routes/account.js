const express = require("express");
const router = express.Router();
const db = require("../db");
const { page } = require("../views");

router.get("/account", (req, res) => {
  if (!req.cookies.username) {
    return res.redirect("/");
  }

  const me = db.prepare("SELECT * FROM accounts WHERE username = ?").get(req.cookies.username);
  if (!me) {
    res.clearCookie("username");
    return res.redirect("/");
  }

  const messageBlock = (me.message_ciphertext && me.message_iv && me.message_encrypted_key)
    ? `
      <div class="message-box" id="locked-message" 
           data-ciphertext="${me.message_ciphertext}" 
           data-iv="${me.message_iv}" 
           data-encrypted-key="${me.message_encrypted_key}" 
           data-filename="${me.message_filename || 'encrypted_file.bin'}">
        <div id="lock-state">🔒 Encrypted File (PQC ML-KEM-768 + AES-256-GCM): <strong>${me.message_filename || 'encrypted_file.bin'}</strong></div>
        
        <label for="private-key-file">Select Private Key File (.pqc / .pem)</label>
        <input type="file" id="private-key-file" accept=".pqc,.pem,.key,.txt">
        
        <label for="private-key-text">or Paste Private Key (ML-KEM-768)</label>
        <textarea id="private-key-text" rows="4" placeholder="-----BEGIN ML-KEM-768 PRIVATE KEY-----&#10;...&#10;-----END ML-KEM-768 PRIVATE KEY-----"></textarea>

        <button type="button" id="unlock-button" class="btn btn-yellow" style="margin-top: 10px;">Decrypt File 🔓</button>
        <div id="unlock-status" class="subtitle"></div>
        <div id="unlocked-message" class="message-box empty" style="display:none; white-space: pre-wrap; margin-top: 10px;"></div>
        <button type="button" id="download-unlocked-btn" class="btn btn-green" style="display:none; margin-top: 10px;">Download Decrypted File 💾</button>
      </div>
    `
    : `<div class="message-box empty">💬 No encrypted file saved yet.</div>`;

  res.send(page("My Page", `
    <h1>👋 Hi, ${me.display_name}!</h1>
    ${messageBlock}
    <div class="button-row">
      <a href="/set-message" class="btn btn-yellow">📁 Encrypt New File</a>
      <a href="/change-password" class="btn btn-green">🔑 Change Password</a>
    </div>
    <a href="/logout" class="btn btn-pink" style="margin-top: 14px; display:inline-block;">Log Out</a>
    <script src="/public/ml-kem.js"></script>
    <script src="/public/crypto.js"></script>
    <script>
      (function () {
        const lockedMessage = document.getElementById("locked-message");
        if (!lockedMessage) {
          return;
        }

        const unlockButton = document.getElementById("unlock-button");
        const privKeyFile = document.getElementById("private-key-file");
        const privKeyText = document.getElementById("private-key-text");
        const unlockStatus = document.getElementById("unlock-status");
        const unlockedMessage = document.getElementById("unlocked-message");
        const downloadBtn = document.getElementById("download-unlocked-btn");

        const ciphertext = lockedMessage.dataset.ciphertext;
        const iv = lockedMessage.dataset.iv;
        const encryptedKey = lockedMessage.dataset.encryptedKey;
        const filename = lockedMessage.dataset.filename || "decrypted_file.bin";

        let decryptedBuffer = null;

        unlockButton.addEventListener("click", async () => {
          let privateKeyPem = privKeyText.value.trim();
          if (!privateKeyPem && privKeyFile.files && privKeyFile.files.length > 0) {
            privateKeyPem = await privKeyFile.files[0].text();
          }

          if (!privateKeyPem) {
            unlockStatus.textContent = "Please select or paste your ML-KEM-768 Private Key file (.pqc).";
            return;
          }

          unlockStatus.textContent = "Decapsulating KEM shared secret + decrypting file with Private Key...";

          try {
            decryptedBuffer = await window.ClassmateCrypto.decryptFile(ciphertext, iv, encryptedKey, privateKeyPem);
            
            // Try displaying as text if valid UTF-8
            const textDecoder = new TextDecoder("utf-8", { fatal: true });
            try {
              const textContent = textDecoder.decode(decryptedBuffer);
              unlockedMessage.textContent = textContent;
              unlockedMessage.style.display = "block";
            } catch (e) {
              unlockedMessage.textContent = "Binary file decrypted successfully. Click download to save.";
              unlockedMessage.style.display = "block";
            }

            downloadBtn.style.display = "inline-block";
            unlockStatus.textContent = "✅ File decrypted successfully!";
            lockedMessage.querySelector("#lock-state").textContent = "🔓 File Unlocked: " + filename;
          } catch (error) {
            console.error(error);
            unlockStatus.textContent = "❌ Decryption failed. Invalid Private Key or corrupted file.";
            unlockedMessage.style.display = "none";
            downloadBtn.style.display = "none";
          }
        });

        downloadBtn.addEventListener("click", () => {
          if (decryptedBuffer) {
            window.ClassmateCrypto.downloadFile(filename, decryptedBuffer);
          }
        });
      })();
    </script>
  `));
});

router.get("/logout", (req, res) => {
  res.clearCookie("username");
  res.redirect("/");
});

module.exports = router;
