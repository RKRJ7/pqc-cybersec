// ===========================================================================
// server.js — ORIGINAL Node/Express entry point (kept for reference).
// VIVA: the graded runnable app is the Flask backend (python app.py); this
// file boots the equivalent Express app (npm start) sharing the SAME SQLite
// schema and the SAME browser PQC bundle (public/crypto.js + ml-kem.js).
// Middleware: urlencoded forms, cookie parser (demo "username" cookie),
// /public static files. Routes mounted from routes/*.js. No crypto runs
// here — encryption/decryption happen in the browser; Node only stores blobs.
// ===========================================================================
const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");

require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use("/public", express.static(path.join(__dirname, "public")));

app.use(require("./routes/login"));
app.use(require("./routes/account"));
app.use(require("./routes/message"));
app.use(require("./routes/password"));

app.listen(PORT, () => {
  console.log(`Classmate Hub is running on http://localhost:${PORT}`);
});
