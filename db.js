// db.js — SQLite setup using better-sqlite3.
// Creates/migrates the accounts table (adds ciphertext/iv/kem_ct/filename columns if missing).
// Seeds 5 demo accounts; COALESCE upsert preserves existing encrypted blobs across restarts.
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const dbFile = path.join(__dirname, "classmates.db");
const isNewDatabase = !fs.existsSync(dbFile);
const db = new Database(dbFile);

if (isNewDatabase) {
  db.exec(`
    CREATE TABLE accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      display_name TEXT NOT NULL,
      message_ciphertext TEXT,
      message_iv TEXT
    );
  `);
} else {
  const columns = db.prepare("PRAGMA table_info(accounts)").all().map((column) => column.name);

  if (!columns.includes("message_ciphertext")) {
    db.exec("ALTER TABLE accounts ADD COLUMN message_ciphertext TEXT");
  }

  if (!columns.includes("message_iv")) {
    db.exec("ALTER TABLE accounts ADD COLUMN message_iv TEXT");
  }

  if (!columns.includes("message_encrypted_key")) {
    db.exec("ALTER TABLE accounts ADD COLUMN message_encrypted_key TEXT");
  }

  if (!columns.includes("message_filename")) {
    db.exec("ALTER TABLE accounts ADD COLUMN message_filename TEXT");
  }
}

const seedAccounts = [
  ["arjun", "Football123", "Arjun"],
  ["meera", "SummerFun2024", "Meera"],
  ["kabir", "ChessMaster9", "Kabir"],
  ["zara", "RainbowUnicorn", "Zara"],
  ["vedant", "12345678", "Vedant"]
];

const upsertAccount = db.prepare(`
  INSERT INTO accounts (username, password, display_name, message_ciphertext, message_iv)
  VALUES (?, ?, ?, ?, ?)
  ON CONFLICT(username) DO UPDATE SET
    password = excluded.password,
    display_name = excluded.display_name,
    message_ciphertext = COALESCE(accounts.message_ciphertext, excluded.message_ciphertext),
    message_iv = COALESCE(accounts.message_iv, excluded.message_iv)
`);

for (const [username, password, displayName] of seedAccounts) {
  upsertAccount.run(username, password, displayName, null, null);
}

console.log("Set up classmates.db with the expected sample accounts.");

module.exports = db;
