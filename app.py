import base64
import hashlib
import hmac
import os
import secrets
from flask import Flask, request, redirect, make_response, jsonify
from db import get_db, init_db
from views import page

# ---------------------------------------------------------------------------
# Classmate Hub — Flask backend with Post-Quantum hybrid encryption.
# Crypto scheme: ML-KEM-768 (NIST FIPS 203, formerly Kyber768) KEM +
#   HKDF-SHA256 key derivation + AES-256-GCM file encryption (KEM + DEM).
# Normally ALL crypto runs in the browser (crypto.js + ml-kem.js).
# /generate-keys, /encrypt-file, /decrypt-file are FALLBACKS only
#   (used when crypto.subtle is blocked on plain-HTTP).
# Server NEVER decrypts user files — stores opaque base64 blobs in SQLite.
# ---------------------------------------------------------------------------

# ML-KEM-768 preferred name (FIPS 203); Kyber768 = pre-standard alias for
# older liboqs builds. Both give identical sizes and interoperate.
PQC_KEM_ALGORITHMS = ("ML-KEM-768", "Kyber768")  # preferred first
PQC_KEM_ALGORITHM = "ML-KEM-768"

# HKDF info string for domain separation (must match crypto.js HKDF_INFO_STRING).
# Ensures same shared secret derives distinct keys across different applications.
HKDF_INFO = b"ClassmateHub-ML-KEM-768-AES-256-GCM-v1"

# FIPS 203 ML-KEM-768 sizes (bytes).
ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_KEM_768_SECRET_KEY_BYTES = 2400
ML_KEM_768_CIPHERTEXT_BYTES = 1088
ML_KEM_768_SHARED_SECRET_BYTES = 32
AES_GCM_IV_BYTES = 12  # 96-bit nonce (standard GCM size).

PUBLIC_PEM_LABEL = "ML-KEM-768 PUBLIC KEY"
PRIVATE_PEM_LABEL = "ML-KEM-768 PRIVATE KEY"


def _resolve_kem_algorithm():
    """Return the first available ML-KEM-768 name in this liboqs build.
    Prefers final FIPS 203 name; falls back to legacy 'Kyber768' alias.
    """
    import oqs
    enabled = set(oqs.get_enabled_kem_mechanisms())
    for name in PQC_KEM_ALGORITHMS:
        if name in enabled:
            return name
    raise RuntimeError("No ML-KEM-768 / Kyber768 KEM available in liboqs")


def _pem_encode(label, raw: bytes) -> str:
    # PEM = base64 of raw key bytes with BEGIN/END headers (allows raw binary keys to be saved as text files).
    b64 = base64.b64encode(raw).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----"


def _pem_decode(pem_text: str) -> bytes:
    # Strip any PEM header/footer and whitespace, then base64-decode.
    # Accepts ML-KEM, Kyber, or generic headers; length check in callers validates type.
    import re
    b64 = re.sub(r"-----BEGIN [A-Z0-9 ._-]+-----", "", pem_text)
    b64 = re.sub(r"-----END [A-Z0-9 ._-]+-----", "", b64)
    b64 = re.sub(r"\s+", "", b64)
    if not b64:
        raise ValueError("Empty key: expected a PEM-encoded ML-KEM-768 key")
    return base64.b64decode(b64)


def _parse_pqc_public_key(pem_text: str) -> bytes:
    # Decode PEM and assert exactly 1184 bytes (ML-KEM-768 public key size).
    raw = _pem_decode(pem_text)
    if len(raw) != ML_KEM_768_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"Invalid ML-KEM-768 public key length: expected "
            f"{ML_KEM_768_PUBLIC_KEY_BYTES}, got {len(raw)}"
        )
    return raw


def _parse_pqc_private_key(pem_text: str) -> bytes:
    # Decode PEM and assert exactly 2400 bytes (ML-KEM-768 secret key size).
    raw = _pem_decode(pem_text)
    if len(raw) != ML_KEM_768_SECRET_KEY_BYTES:
        raise ValueError(
            f"Invalid ML-KEM-768 private key length: expected "
            f"{ML_KEM_768_SECRET_KEY_BYTES}, got {len(raw)}"
        )
    return raw


def hkdf_sha256(ikm: bytes, salt: bytes = b"", info: bytes = HKDF_INFO, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869) key derivation.
    Extracts & stretches the raw KEM shared secret into a clean, uniform AES key.
    Extract: PRK = HMAC-SHA256(salt or 32 zero bytes, IKM)
    Expand:  T(i) = HMAC(PRK, T(i-1) || info || byte(i)); output = T(1)|T(2)|...[:length]
    Matches crypto.js hkdfSha256() exactly (same salt/info/length).
    """
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]


def derive_aes_key(shared_secret: bytes) -> bytes:
    """Derive 32-byte AES-256-GCM key from 32-byte KEM shared secret via HKDF-SHA256.
    Wraps HKDF with fixed domain info (same secret → different key in another app context).
    Matches crypto.js deriveAesKey().
    """
    if len(shared_secret) != ML_KEM_768_SHARED_SECRET_BYTES:
        raise ValueError("Invalid ML-KEM-768 shared secret length")
    return hkdf_sha256(shared_secret, salt=b"", info=HKDF_INFO, length=32)


def _aes_gcm_encrypt(aes_key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns ciphertext || 16-byte tag.
    GCM = CTR encryption + GHASH auth tag. IV reuse with the same key is catastrophic,
    so we always generate a fresh random 12-byte IV per file.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(aes_key) != 32 or len(iv) != AES_GCM_IV_BYTES:
        raise ValueError("AES-256-GCM requires a 32-byte key and 12-byte IV")
    return AESGCM(aes_key).encrypt(iv, plaintext, None)


def _aes_gcm_decrypt(aes_key: bytes, iv: bytes, ciphertext_and_tag: bytes) -> bytes:
    # AES-GCM decrypt. Raises on wrong key, wrong IV, or tampered ciphertext/tag
    # (GCM auth tag check provides integrity guarantee).
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(aes_key) != 32 or len(iv) != AES_GCM_IV_BYTES:
        raise ValueError("AES-256-GCM requires a 32-byte key and 12-byte IV")
    return AESGCM(aes_key).decrypt(iv, ciphertext_and_tag, None)

app = Flask(__name__, static_url_path="/public", static_folder="public")

# Initialize database on startup
init_db()

def login_form(message=None):
    notice = f'<p class="subtitle sad">{message}</p>' if message else '<p class="subtitle">Log in to see your page!</p>'
    return page("Log In", f"""
        <h1>🎓 Classmate Hub</h1>
        {notice}
        <form method="POST" action="/login">
          <label>Username</label>
          <input type="text" name="username" placeholder="e.g. arjun" required autofocus>
          <label>Password</label>
          <input type="password" name="password" placeholder="Your password" required>
          <button type="submit" class="btn btn-blue">Log In 🚀</button>
        </form>
    """)

@app.route("/", methods=["GET"])
def index():
    if request.cookies.get("username"):
        return redirect("/account")
    return login_form()

@app.route("/generate-keys", methods=["POST"])
def generate_keys():
    """Server-side ML-KEM-768 key generation via liboqs (FALLBACK only).
    Called by crypto.js when crypto.subtle is unavailable (plain-HTTP).
    In normal use, keys are generated entirely in the browser.
    Note: on this path the server sees the secret key (unavoidable without WebCrypto).
    """
    try:
        import oqs
        kem_name = _resolve_kem_algorithm()
        with oqs.KeyEncapsulation(kem_name) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()

        if len(public_key) != ML_KEM_768_PUBLIC_KEY_BYTES:
            raise RuntimeError("liboqs returned an unexpected ML-KEM-768 public key size")
        if len(secret_key) != ML_KEM_768_SECRET_KEY_BYTES:
            raise RuntimeError("liboqs returned an unexpected ML-KEM-768 secret key size")

        return jsonify({
            "publicKeyPem": _pem_encode(PUBLIC_PEM_LABEL, public_key),
            "privateKeyPem": _pem_encode(PRIVATE_PEM_LABEL, secret_key),
            "kemAlgorithm": kem_name,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------------------------------------------------------
# Plain web routes — no crypto here. Crypto lives in crypto.js (browser) +
# /generate-keys, /encrypt-file, /decrypt-file (server fallbacks).
# /set-message stores opaque base64 blobs; /account embeds them for browser decrypt.
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    # Cookie-based auth (username cookie). Query is intentionally
    # string-concatenated (mirrors the Express code — SQL injection demo).
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()
    cursor = conn.cursor()
    check_query = "SELECT * FROM accounts WHERE username = '" + username + "' AND password = '" + password + "'"
    try:
        cursor.execute(check_query)
        match = cursor.fetchone()
    except Exception:
        match = None
    finally:
        conn.close()

    if not match:
        return login_form("😕 That username/password didn't match. Try again!")

    res = make_response(redirect("/account"))
    res.set_cookie("username", match["username"])
    return res

@app.route("/account", methods=["GET"])
def account():
    # Reads stored ciphertext/iv/kem_ct/filename and embeds as data-* attributes.
    # Inline JS calls ClassmateCrypto.decryptFile() entirely in browser —
    # private key pasted by user is never POSTed anywhere.
    username = request.cookies.get("username")
    if not username:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE username = ?", (username,))
    me = cursor.fetchone()
    conn.close()

    if not me:
        res = make_response(redirect("/"))
        res.delete_cookie("username")
        return res

    has_encrypted_file = (
        "message_encrypted_key" in me.keys()
        and me["message_ciphertext"]
        and me["message_iv"]
        and me["message_encrypted_key"]
    )

    if has_encrypted_file:
        filename = me["message_filename"] if ("message_filename" in me.keys() and me["message_filename"]) else "encrypted_file.bin"
        message_block = f"""
          <div class="message-box" id="locked-message" 
               data-ciphertext="{me['message_ciphertext']}" 
               data-iv="{me['message_iv']}" 
               data-encrypted-key="{me['message_encrypted_key']}" 
               data-filename="{filename}">
            <div id="lock-state">🔒 Encrypted File (PQC ML-KEM-768 + AES-256-GCM): <strong>{filename}</strong></div>
            
            <label for="private-key-file">Select Private Key File (.pqc / .pem)</label>
            <input type="file" id="private-key-file" accept=".pqc,.pem,.key,.txt">
            
            <label for="private-key-text">or Paste Private Key (ML-KEM-768)</label>
            <textarea id="private-key-text" rows="4" placeholder="-----BEGIN ML-KEM-768 PRIVATE KEY-----&#10;...&#10;-----END ML-KEM-768 PRIVATE KEY-----"></textarea>

            <button type="button" id="unlock-button" class="btn btn-yellow" style="margin-top: 10px;">Decrypt File 🔓</button>
            <div id="unlock-status" class="subtitle"></div>
            <div id="unlocked-message" class="message-box empty" style="display:none; white-space: pre-wrap; margin-top: 10px;"></div>
            <button type="button" id="download-unlocked-btn" class="btn btn-green" style="display:none; margin-top: 10px;">Download Decrypted File 💾</button>
          </div>
        """
    else:
        message_block = '<div class="message-box empty">💬 No encrypted file saved yet.</div>'

    return page("My Page", f"""
        <h1>👋 Hi, {me['display_name']}!</h1>
        {message_block}
        <div class="button-row">
          <a href="/set-message" class="btn btn-yellow">📁 Encrypt New File</a>
          <a href="/change-password" class="btn btn-green">🔑 Change Password</a>
        </div>
        <a href="/logout" class="btn btn-pink" style="margin-top: 14px; display:inline-block;">Log Out</a>
        <script src="/public/ml-kem.js"></script>
        <script src="/public/crypto.js"></script>
        <script>
          (function () {{
            const lockedMessage = document.getElementById("locked-message");
            if (!lockedMessage) {{
              return;
            }}

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

            unlockButton.addEventListener("click", async () => {{
              let privateKeyPem = privKeyText.value.trim();
              if (!privateKeyPem && privKeyFile.files && privKeyFile.files.length > 0) {{
                privateKeyPem = await privKeyFile.files[0].text();
              }}

              if (!privateKeyPem) {{
                unlockStatus.textContent = "Please select or paste your ML-KEM-768 Private Key file (.pqc).";
                return;
              }}

              unlockStatus.textContent = "Decapsulating KEM shared secret + decrypting file with Private Key...";

              try {{
                decryptedBuffer = await window.ClassmateCrypto.decryptFile(ciphertext, iv, encryptedKey, privateKeyPem);
                
                const textDecoder = new TextDecoder("utf-8", {{ fatal: true }});
                try {{
                  const textContent = textDecoder.decode(decryptedBuffer);
                  unlockedMessage.textContent = textContent;
                  unlockedMessage.style.display = "block";
                }} catch (e) {{
                  unlockedMessage.textContent = "Binary file decrypted successfully. Click download to save.";
                  unlockedMessage.style.display = "block";
                }}

                downloadBtn.style.display = "inline-block";
                unlockStatus.textContent = "✅ File decrypted successfully!";
                lockedMessage.querySelector("#lock-state").textContent = "🔓 File Unlocked: " + filename;
              }} catch (error) {{
                console.error(error);
                unlockStatus.textContent = "❌ Decryption failed. Invalid Private Key or corrupted file.";
                unlockedMessage.style.display = "none";
                downloadBtn.style.display = "none";
              }}
            }});

            downloadBtn.addEventListener("click", () => {{
              if (decryptedBuffer) {{
                window.ClassmateCrypto.downloadFile(filename, decryptedBuffer);
              }}
            }});
          }})();
        </script>
    """)

@app.route("/logout", methods=["GET"])
def logout():
    res = make_response(redirect("/"))
    res.delete_cookie("username")
    return res

@app.route("/encrypt-file", methods=["POST"])
def encrypt_file_api():
    """Server-side PQC hybrid encryption (FALLBACK): ML-KEM-768 KEM + AES-256-GCM.
    Steps (mirrors crypto.js encryptFile):
      1. Parse recipient public key (1184 B).
      2. Encap(pk) → (kem_ct[1088 B], shared_secret[32 B]).
      3. aes_key = HKDF-SHA256(shared_secret).
      4. iv = random 12 B; ciphertext = AES-GCM(aes_key, iv, file).
    Returns JSON: { ciphertext, iv, encryptedKey, filename } — all base64.
    'encryptedKey' = KEM ciphertext (not an RSA-encrypted AES key).
    """
    try:
        public_key_pem = request.form.get("public_key_pem", "")
        file = request.files.get("file")
        if not public_key_pem or not file:
            return jsonify({"error": "Missing public_key_pem or file"}), 400

        import oqs

        file_bytes = file.read()
        filename = file.filename or "encrypted_file.bin"
        public_key = _parse_pqc_public_key(public_key_pem)

        kem_name = _resolve_kem_algorithm()
        with oqs.KeyEncapsulation(kem_name) as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(public_key)

        if len(kem_ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
            raise RuntimeError("Unexpected ML-KEM-768 ciphertext size from liboqs")

        aes_key = derive_aes_key(bytes(shared_secret))
        iv = secrets.token_bytes(AES_GCM_IV_BYTES)
        full_ct = _aes_gcm_encrypt(aes_key, iv, file_bytes)  # ciphertext || 16-byte tag

        return jsonify({
            "ciphertext": base64.b64encode(full_ct).decode(),
            "iv": base64.b64encode(iv).decode(),
            "encryptedKey": base64.b64encode(bytes(kem_ciphertext)).decode(),
            "filename": filename
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/decrypt-file", methods=["POST"])
def decrypt_file_api():
    """Server-side PQC hybrid decryption (FALLBACK): ML-KEM-768 decap + AES-256-GCM.
    Steps (mirrors crypto.js decryptFile):
      1. Validate kem_ct (1088 B) and IV (12 B) lengths.
      2. Decap(kem_ct, secret_key) → shared_secret.
      3. aes_key = HKDF-SHA256(shared_secret); plaintext = AES-GCM-decrypt.
    Wrong key or tampered bytes raise here (GCM auth tag failure) → HTTP 500.
    """
    try:
        private_key_pem = request.form.get("private_key_pem", "")
        ciphertext_b64 = request.form.get("ciphertext", "")
        iv_b64 = request.form.get("iv", "")
        encrypted_key_b64 = request.form.get("encrypted_key", "")

        if not all([private_key_pem, ciphertext_b64, iv_b64, encrypted_key_b64]):
            return jsonify({"error": "Missing required fields"}), 400

        import oqs

        full_ct = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        kem_ciphertext = base64.b64decode(encrypted_key_b64)
        if len(kem_ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
            return jsonify({"error": "Invalid ML-KEM-768 ciphertext length"}), 400
        if len(iv) != AES_GCM_IV_BYTES:
            return jsonify({"error": "Invalid AES-GCM IV length"}), 400

        secret_key = _parse_pqc_private_key(private_key_pem)

        kem_name = _resolve_kem_algorithm()
        with oqs.KeyEncapsulation(kem_name, secret_key=bytes(secret_key)) as kem:
            shared_secret = bytes(kem.decap_secret(bytes(kem_ciphertext)))

        aes_key = derive_aes_key(shared_secret)
        plaintext = _aes_gcm_decrypt(aes_key, iv, full_ct)

        return jsonify({
            "data": base64.b64encode(plaintext).decode(),
            "encoding": "base64"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/set-message", methods=["GET"])
def get_set_message():
    if not request.cookies.get("username"):
        return redirect("/")

    return page("Encrypt File", """
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
                const encrypted = await window.ClassmateCrypto.encryptFile(fileBuffer, publicKeyPem, file.name);

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
    """)

@app.route("/set-message", methods=["POST"])
def post_set_message():
    # Store encrypted blob — UPDATEs ciphertext/iv/kem_ct/filename for logged-in user.
    # No crypto here; server only stores opaque base64 strings from the browser.
    username = request.cookies.get("username")
    if not username:
        return redirect("/")

    ciphertext = request.form.get("ciphertext")
    iv = request.form.get("iv")
    encrypted_key = request.form.get("encrypted_key")
    filename = request.form.get("filename", "encrypted_file.bin")

    if not ciphertext or not iv or not encrypted_key:
        return redirect("/set-message")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE accounts 
        SET message_ciphertext = ?, message_iv = ?, message_encrypted_key = ?, message_filename = ?
        WHERE username = ?
        """,
        (ciphertext, iv, encrypted_key, filename, username)
    )
    conn.commit()
    conn.close()

    return redirect("/account")

@app.route("/change-password", methods=["GET"])
def get_change_password():
    if not request.cookies.get("username"):
        return redirect("/")

    return page("Change Password", """
        <h1>🔑 Change Password</h1>
        <p class="subtitle">Pick something only you know!</p>
        <form method="POST" action="/change-password">
          <label>New password</label>
          <input type="password" name="password" placeholder="New password" required autofocus>
          <button type="submit" class="btn btn-green">Save Password ✅</button>
        </form>
        <a href="/account" class="btn btn-pink" style="margin-top: 14px; display:inline-block;">Back</a>
    """)

@app.route("/change-password", methods=["POST"])
def post_change_password():
    username = request.cookies.get("username")
    if not username:
        return redirect("/")

    password = request.form.get("password")
    if password:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE accounts SET password = ? WHERE username = ?", (password, username))
        conn.commit()
        conn.close()

    return redirect("/account")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=True)
