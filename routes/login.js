const express = require("express");
const router = express.Router();
const db = require("../db");
const { page } = require("../views");

function loginForm(message) {
  const notice = message ? `<p class="subtitle sad">${message}</p>` : `<p class="subtitle">Log in to see your page!</p>`;
  return page("Log In", `
    <h1>🎓 Classmate Hub</h1>
    ${notice}
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="username" placeholder="e.g. arjun" required autofocus>
      <label>Password</label>
      <input type="password" name="password" placeholder="Your password" required>
      <button type="submit" class="btn btn-blue">Log In 🚀</button>
    </form>
  `);
}

router.get("/", (req, res) => {
  if (req.cookies.username) {
    return res.redirect("/account");
  }
  res.send(loginForm());
});

router.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const checkQuery = "SELECT * FROM accounts WHERE username = '" + username + "' AND password = '" + password + "'";
  const match = db.prepare(checkQuery).get();

  if (!match) {
    return res.send(loginForm("😕 That username/password didn't match. Try again!"));
  }

  res.cookie("username", match.username);
  res.redirect("/account");
});

module.exports = router;
