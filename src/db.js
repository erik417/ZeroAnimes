const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const dayjs = require('dayjs');

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const dbPath = path.join(dataDir, 'zeroanime.db');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  is_verified INTEGER NOT NULL DEFAULT 0,
  avatar_path TEXT DEFAULT '',
  bio TEXT DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anime (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT DEFAULT '',
  cover_path TEXT DEFAULT '',
  genres TEXT DEFAULT '',
  rating REAL DEFAULT 0,
  rating_count INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_anime_title ON anime(title);

CREATE TABLE IF NOT EXISTS episodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  anime_id INTEGER NOT NULL,
  number INTEGER NOT NULL,
  title TEXT DEFAULT '',
  video_360 TEXT DEFAULT '',
  video_720 TEXT DEFAULT '',
  video_1080 TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE,
  UNIQUE(anime_id, number)
);

CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  anime_id INTEGER,
  episode_id INTEGER,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE,
  FOREIGN KEY (episode_id) REFERENCES episodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS favorites (
  user_id INTEGER NOT NULL,
  anime_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, anime_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS likes (
  user_id INTEGER NOT NULL,
  anime_id INTEGER,
  episode_id INTEGER,
  value INTEGER NOT NULL CHECK (value IN (-1, 1)),
  created_at TEXT NOT NULL,
  UNIQUE(user_id, anime_id, episode_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS views (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  anime_id INTEGER NOT NULL,
  episode_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (anime_id) REFERENCES anime(id) ON DELETE CASCADE,
  FOREIGN KEY (episode_id) REFERENCES episodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS watch_history (
  user_id INTEGER NOT NULL,
  episode_id INTEGER NOT NULL,
  last_time REAL NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, episode_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (episode_id) REFERENCES episodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS email_verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_email_verifications_email ON email_verifications(email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_verifications_username ON email_verifications(username);

CREATE TABLE IF NOT EXISTS verification_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  decided_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS forum_posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  video_url TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS followers (
  follower_id INTEGER NOT NULL,
  following_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (follower_id, following_id),
  FOREIGN KEY (follower_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (following_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS forum_post_reactions (
  user_id INTEGER NOT NULL,
  post_id INTEGER NOT NULL,
  value INTEGER NOT NULL CHECK (value IN (-1, 1)),
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, post_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (post_id) REFERENCES forum_posts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS forum_post_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  reply_to_comment_id INTEGER,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (post_id) REFERENCES forum_posts(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user1_id INTEGER NOT NULL,
  user2_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(user1_id, user2_id),
  FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL,
  sender_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
  FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

try {
  db.exec("ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0");
} catch (e) {}
try {
  db.exec("ALTER TABLE users ADD COLUMN avatar_path TEXT DEFAULT ''");
} catch (e) {}
try {
  db.exec("ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''");
} catch (e) {}
try {
  db.exec('ALTER TABLE forum_post_comments ADD COLUMN reply_to_comment_id INTEGER');
} catch (e) {}

// Seed admin if not exists (password: admin123)
const adminExists = db.prepare('SELECT id FROM users WHERE is_admin=1 LIMIT 1').get();
if (!adminExists) {
  const bcrypt = require('bcryptjs');
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare(
    'INSERT INTO users (username, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run('admin', 'admin@example.com', hash, 1, dayjs().toISOString());
}

module.exports = db;
