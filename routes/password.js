const express = require("express");
const router = express.Router();
const db = require("../db");
const { page } = require("../views");

router.get("/change-password", (req, res) => {
  if (!req.cookies.username) {
    return res.redirect("/");
  }

  res.send(page("Change Password", `
    <h1>🔑 Change Password</h1>
    <p class="subtitle">Pick something only you know!</p>
    <form method="POST" action="/change-password">
      <label>New password</label>
      <input type="password" name="password" placeholder="New password" required autofocus>
      <button type="submit" class="btn btn-green">Save Password ✅</button>
    </form>
    <a href="/account" class="btn btn-pink" style="margin-top: 14px; display:inline-block;">Back</a>
  `));
});

router.post("/change-password", (req, res) => {
  if (!req.cookies.username) {
    return res.redirect("/");
  }

  db.prepare("UPDATE accounts SET password = ? WHERE username = ?").run(
    req.body.password,
    req.cookies.username
  );

  res.redirect("/account");
});

module.exports = router;
