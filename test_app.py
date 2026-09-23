# ===========================================================================
# test_app.py — unit tests (run: venv/bin/python test_app.py). VIVA MAP:
#   * Framework: stdlib unittest, Flask test_client (no live server needed).
#   * setUp(): fresh app in TESTING mode + init_db() reseeds demo accounts.
#   * test_login_and_account_flow: covers the whole NON-crypto web journey —
#     homepage -> bad login -> good login (arjun/Football123) -> POST an
#     encrypted-file payload to /set-message (dummy base64 here; REAL PQC
#     roundtrips are verified manually via /generate-keys + /encrypt-file +
#     /decrypt-file) -> account page shows data-* blobs + filename ->
#     change-password writes through to SQLite -> logout returns to login.
#   * test_static_files: proves the browser can fetch /public/style.css and
#     /public/crypto.js (the PQC bundle /public/ml-kem.js is loaded the same
#     way via static_folder="public"). If these 404, encryption UI breaks.
# ===========================================================================
import unittest
from app import app
from db import init_db, get_db


class TestClassmateHub(unittest.TestCase):
    def setUp(self):
        # VIVA: TESTING=True gives better error propagation; test_client()
        # simulates HTTP without binding a port; init_db() guarantees the
        # 'arjun' demo account exists with a known password.
        app.config['TESTING'] = True
        self.client = app.test_client()
        init_db()

    def test_login_and_account_flow(self):
        # 1. Logged-out homepage must show the login form (no redirect).
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Log In", response.data)

        # 2. Wrong password re-renders the form with the mismatch message.
        response = self.client.post("/login", data={"username": "arjun", "password": "wrongpassword"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"didn't match", response.data)

        # 3. Correct demo credentials redirect to /account greeting Arjun.
        # VIVA: auth is a plain "username" cookie (demo-grade, not sessions).
        response = self.client.post("/login", data={"username": "arjun", "password": "Football123"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Hi, Arjun!", response.data)

        # 4. Store an encrypted-file payload. VIVA: these are OPAQUE base64
        # blobs to the server — here dummy values prove the plumbing
        # (ciphertext + iv + encrypted_key=KEM ct + filename); the account
        # page must then embed them as data-ciphertext / data-encrypted-key
        # attributes for crypto.js to decrypt client-side.
        response = self.client.post("/set-message", data={
            "ciphertext": "dGVzdF9jaXBoZXI=",
            "iv": "dGVzdF9pdg==",
            "encrypted_key": "dGVzdF9rZXk=",
            "filename": "test_file.txt"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"data-ciphertext=\"dGVzdF9jaXBoZXI=\"", response.data)
        self.assertIn(b"data-encrypted-key=\"dGVzdF9rZXk=\"", response.data)
        self.assertIn(b"test_file.txt", response.data)

        # 5. Change password persists to SQLite (verified with a direct query).
        response = self.client.post("/change-password", data={"password": "NewFootballPass123"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        # Verify password in DB
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM accounts WHERE username = 'arjun'")
        row = cursor.fetchone()
        conn.close()
        self.assertEqual(row["password"], "NewFootballPass123")

        # 6. Logout clears the cookie, homepage shows login again.
        response = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Log In", response.data)

    def test_static_files(self):
        # VIVA: the encryption UI depends on these static files; a 404 here
        # means <script src="/public/crypto.js"> (or the stylesheet) is
        # misconfigured via static_url_path/static_folder in app.py.
        response = self.client.get("/public/style.css")
        self.assertEqual(response.status_code, 200)
        response_crypto = self.client.get("/public/crypto.js")
        self.assertEqual(response_crypto.status_code, 200)


if __name__ == "__main__":
    unittest.main()
