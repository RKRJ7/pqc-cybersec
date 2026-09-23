# ===========================================================================
# db.py — SQLite storage layer. VIVA MAP:
#   * DB file: classmates.db (auto-created next to this file, gitignored).
#   * Table `accounts`: id, username (UNIQUE), password, display_name, plus
#     4 nullable TEXT columns holding the PQC payload: message_ciphertext
#     (base64 AES-GCM ct||tag), message_iv (base64 12 B), message_encrypted_key
#     (base64 KEM ciphertext, 1088 B -> ~1452 chars), message_filename.
#   * VIVA: the DB stores ONLY ciphertexts — no keys, no plaintext. Without
#     the user's ML-KEM-768 private key the rows are useless to an attacker.
#   * init_db() is idempotent: creates the table on first run, ALTERs missing
#     columns on later runs, then upserts the 5 demo accounts WITHOUT wiping
#     any saved encrypted file (COALESCE keeps existing blobs).
# ===========================================================================
import sqlite3
import os

# Absolute path so the app works regardless of the current working directory.
DB_PATH = os.path.join(os.path.dirname(__file__), "classmates.db")


def get_db():
    # VIVA: Row factory lets routes use me["message_ciphertext"] instead of
    # numeric indexes. Each caller must conn.close() (see app.py finally:).
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    # VIVA: called once at app startup (app.py) and before each unit test.
    is_new = not os.path.exists(DB_PATH)
    conn = get_db()
    cursor = conn.cursor()

    if is_new:
        # Fresh install: create the full schema in one statement.
        cursor.execute("""
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                display_name TEXT NOT NULL,
                message_ciphertext TEXT,
                message_iv TEXT
            );
        """)
    else:
        # Upgrade path: older DBs may lack the KEM/filename columns, so add
        # each one only if PRAGMA table_info says it is missing.
        cursor.execute("PRAGMA table_info(accounts)")
        columns = [row["name"] for row in cursor.fetchall()]

        if "message_ciphertext" not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN message_ciphertext TEXT")

        if "message_iv" not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN message_iv TEXT")

        if "message_encrypted_key" not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN message_encrypted_key TEXT")

        if "message_filename" not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN message_filename TEXT")

    # Demo logins the examiner can use (see README sample-accounts table).
    seed_accounts = [
        ("arjun", "Football123", "Arjun"),
        ("meera", "SummerFun2024", "Meera"),
        ("kabir", "ChessMaster9", "Kabir"),
        ("zara", "RainbowUnicorn", "Zara"),
        ("vedant", "12345678", "Vedant")
    ]

    # VIVA: ON CONFLICT upsert resets demo passwords/names every run but the
    # COALESCE(...) guards preserve any saved encrypted file blobs, so
    # restarting the server never deletes a user's ciphertext.
    upsert_sql = """
        INSERT INTO accounts (username, password, display_name, message_ciphertext, message_iv)
        VALUES (?, ?, ?, NULL, NULL)
        ON CONFLICT(username) DO UPDATE SET
            password = excluded.password,
            display_name = excluded.display_name,
            message_ciphertext = COALESCE(accounts.message_ciphertext, excluded.message_ciphertext),
            message_iv = COALESCE(accounts.message_iv, excluded.message_iv)
    """

    for username, password, display_name in seed_accounts:
        cursor.execute(upsert_sql, (username, password, display_name))

    conn.commit()
    conn.close()
    print("Set up classmates.db with the expected sample accounts.")


if __name__ == "__main__":
    init_db()
