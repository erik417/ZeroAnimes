const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'otp.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY,
  password TEXT NOT NULL,
  code TEXT NOT NULL,
  is_verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
`);

const page = (body) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Register</title>
</head>
<body style="font-family:Arial,sans-serif;max-width:720px;margin:40px auto;padding:0 16px">
${body}
</body>
</html>`;

app.get('/', (req, res) => {
  res.send(
    page(`
      <h1>Register</h1>
      <form method="post" action="/register">
        <label>Email</label><br/>
        <input name="email" type="email" required /><br/><br/>
        <label>Password</label><br/>
        <input name="password" type="password" required /><br/><br/>
        <button type="submit">Register</button>
      </form>
      <p><a href="/">Back to home</a></p>
    `)
  );
});

app.post('/register', async (req, res) => {
  const email = String(req.body.email || '').trim();
  const password = String(req.body.password || '').trim();
  if (!email || !password) return res.status(400).send('Email and password are required.');
  db.prepare(
    `INSERT INTO users (email, password, code, is_verified, created_at)
     VALUES (?, ?, '000000', 1, datetime('now'))
     ON CONFLICT(email) DO UPDATE SET password=excluded.password, code='000000', is_verified=1`
  ).run(email, password);

  res.send('Registered successfully.');
});

app.listen(PORT, () => {
  console.log(`OTP server running on http://localhost:${PORT}`);
});
