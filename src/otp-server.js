const express = require('express');
const nodemailer = require('nodemailer');
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

const hasGmail = process.env.GMAIL_USER && process.env.GMAIL_PASS;
const mailTransport = hasGmail
  ? nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
    })
  : null;

const page = (body) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OTP Register</title>
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
        <button type="submit">Send code</button>
      </form>
      <p>Already have a code? <a href="/verify">Verify here</a></p>
    `)
  );
});

app.get('/verify', (req, res) => {
  res.send(
    page(`
      <h1>Verify</h1>
      <form method="post" action="/verify">
        <label>Email</label><br/>
        <input name="email" type="email" required /><br/><br/>
        <label>Code</label><br/>
        <input name="code" required /><br/><br/>
        <button type="submit">Verify</button>
      </form>
      <p><a href="/">Back to register</a></p>
    `)
  );
});

app.post('/register', async (req, res) => {
  const email = String(req.body.email || '').trim();
  const password = String(req.body.password || '').trim();
  if (!email || !password) return res.status(400).send('Email and password are required.');
  if (!mailTransport) return res.status(500).send('Email service not configured.');

  const code = String(Math.floor(100000 + Math.random() * 900000));
  db.prepare(
    `INSERT INTO users (email, password, code, is_verified, created_at)
     VALUES (?, ?, ?, 0, datetime('now'))
     ON CONFLICT(email) DO UPDATE SET password=excluded.password, code=excluded.code, is_verified=0`
  ).run(email, password, code);

  await mailTransport.sendMail({
    from: process.env.GMAIL_USER,
    to: email,
    subject: 'Verification code',
    text: `Your verification code is: ${code}`,
  });

  res.send('Verification code sent. Check your email.');
});

app.post('/verify', (req, res) => {
  const email = String(req.body.email || '').trim();
  const code = String(req.body.code || '').trim();
  if (!email || !code) return res.status(400).send('Email and code are required.');

  const row = db.prepare('SELECT code FROM users WHERE email=?').get(email);
  if (!row || row.code !== code) return res.status(400).send('Invalid code.');

  db.prepare('UPDATE users SET is_verified=1 WHERE email=?').run(email);
  res.send('Account verified.');
});

app.listen(PORT, () => {
  console.log(`OTP server running on http://localhost:${PORT}`);
});
