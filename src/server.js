const express = require('express');
const path = require('path');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const slugify = require('slugify');
const dayjs = require('dayjs');
const fs = require('fs');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Security & basic middleware
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const uploadsDir = path.join(__dirname, '..', 'uploads');
const coverDir = path.join(uploadsDir, 'covers');
const videoDir = path.join(uploadsDir, 'videos');
const avatarDir = path.join(uploadsDir, 'avatars');
if (!fs.existsSync(coverDir)) fs.mkdirSync(coverDir, { recursive: true });
if (!fs.existsSync(videoDir)) fs.mkdirSync(videoDir, { recursive: true });
if (!fs.existsSync(avatarDir)) fs.mkdirSync(avatarDir, { recursive: true });

// Sessions
app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: path.join(__dirname, '..', 'data') }),
    secret: process.env.SESSION_SECRET || 'zeroanime-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 30 },
  })
);

// Rate limiting for auth and comments
const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
const commentLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });

// Views & static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use('/public', express.static(path.join(__dirname, '..', 'public')));
app.use('/uploads', express.static(uploadsDir));

// Multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'cover') return cb(null, coverDir);
    if (file.fieldname === 'avatar') return cb(null, avatarDir);
    return cb(null, videoDir);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + '-' + file.originalname.replace(/\\s+/g, '_'));
  },
});
const upload = multer({ storage });

// Helpers
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) return res.redirect('/admin/login');
  next();
}
function setCaptcha(req) {
  const a = Math.floor(Math.random() * 9) + 1;
  const b = Math.floor(Math.random() * 9) + 1;
  req.session.captchaAnswer = String(a + b);
  return `${a} + ${b} = ?`;
}
function genresArrayToString(genres) {
  if (Array.isArray(genres)) return genres.join(',');
  return String(genres || '');
}
function genresStringToArray(s) {
  return s ? s.split(',').map((g) => g.trim()).filter(Boolean) : [];
}

app.use((req, res, next) => {
  if (req.session.user) {
    const fresh = db
      .prepare('SELECT id, username, is_admin, is_verified, avatar_path, bio FROM users WHERE id=?')
      .get(req.session.user.id);
    if (fresh) {
      req.session.user = {
        id: fresh.id,
        username: fresh.username,
        is_admin: !!fresh.is_admin,
        is_verified: !!fresh.is_verified,
        avatar_path: fresh.avatar_path || '',
        bio: fresh.bio || '',
      };
      res.locals.user = req.session.user;
    } else {
      req.session.user = null;
      res.locals.user = null;
    }
  } else {
    res.locals.user = null;
  }
  res.locals.nowYear = new Date().getFullYear();
  res.locals.path = req.path;
  next();
});

// Home page
app.get('/', (req, res) => {
  const q = (req.query.q || '').trim();
  const words = q ? q.split(/\s+/).map((w) => w.trim()).filter(Boolean) : [];
  const tokens = Array.from(new Set(words)).slice(0, 8);
  const where = tokens.length ? `WHERE (${tokens.map(() => 'title LIKE ?').join(' OR ')})` : '';
  const params = tokens.map((t) => `%${t}%`);
  const anime = db.prepare(`SELECT * FROM anime ${where} ORDER BY created_at DESC LIMIT 24`).all(...params);
  const popular = db
    .prepare(
      `SELECT a.*, COUNT(v.id) AS views7
       FROM anime a
       LEFT JOIN views v ON v.anime_id=a.id AND v.created_at>=?
       GROUP BY a.id
       ORDER BY views7 DESC
       LIMIT 10`
    )
    .all(dayjs().subtract(7, 'day').toISOString());
  const latestEpisodes = db
    .prepare(
      `SELECT e.*, a.title as anime_title, a.slug as anime_slug, a.cover_path
       FROM episodes e JOIN anime a ON a.id=e.anime_id
       ORDER BY e.created_at DESC LIMIT 12`
    )
    .all();
  res.render('index', { anime, popular, latestEpisodes, q });
});

// Genre
app.get('/genre/:name', (req, res) => {
  const name = req.params.name;
  const anime = db
    .prepare(`SELECT * FROM anime WHERE (',' || genres || ',') LIKE ? ORDER BY created_at DESC LIMIT 48`)
    .all(`%,${name},%`);
  res.render('genre', { anime, genre: name });
});

// Anime details
app.get('/anime/:slug', (req, res) => {
  const slug = req.params.slug;
  const anime = db.prepare('SELECT * FROM anime WHERE slug=?').get(slug);
  if (!anime) return res.status(404).send('Not found');
  const episodes = db.prepare('SELECT * FROM episodes WHERE anime_id=? ORDER BY number ASC').all(anime.id);
  const comments = db
    .prepare(
      `SELECT c.*, u.username, u.is_verified, u.avatar_path
       FROM comments c JOIN users u ON u.id=c.user_id
       WHERE c.anime_id=? AND c.is_deleted=0 ORDER BY c.created_at DESC LIMIT 50`
    )
    .all(anime.id);
  const isFav =
    req.session.user &&
    db.prepare('SELECT 1 FROM favorites WHERE user_id=? AND anime_id=?').get(req.session.user.id, anime.id);
  const likeCount = db.prepare('SELECT COUNT(*) AS c FROM likes WHERE anime_id=? AND value=1').get(anime.id).c;
  const userLike =
    req.session.user &&
    db.prepare('SELECT value FROM likes WHERE user_id=? AND anime_id=? AND episode_id IS NULL')
      .get(req.session.user.id, anime.id)?.value;
  res.render('anime', {
    anime,
    episodes,
    comments,
    isFav: !!isFav,
    genres: genresStringToArray(anime.genres),
    likeCount,
    userLike: Number(userLike) === 1 ? 1 : 0,
  });
});

// Watch episode
app.get('/watch/:episodeId', (req, res) => {
  const episodeId = Number(req.params.episodeId);
  const episode = db.prepare('SELECT * FROM episodes WHERE id=?').get(episodeId);
  if (!episode) return res.status(404).send('Not found');
  const anime = db.prepare('SELECT * FROM anime WHERE id=?').get(episode.anime_id);
  const nextEpisode = db
    .prepare('SELECT * FROM episodes WHERE anime_id=? AND number>? ORDER BY number ASC LIMIT 1')
    .get(episode.anime_id, episode.number);
  const viewerId = req.session.user ? req.session.user.id : null;
  db.prepare('INSERT INTO views (user_id, anime_id, episode_id, created_at) VALUES (?, ?, ?, ?)').run(
    viewerId,
    anime.id,
    episode.id,
    dayjs().toISOString()
  );
  res.render('watch', { anime, episode, nextEpisode });
});

// Auth
app.get('/register', (req, res) =>
  res.render('auth/register', {
    errors: [],
    values: {},
    captchaQuestion: setCaptcha(req),
  })
);
app.post(
  '/register',
  authLimiter,
  upload.single('avatar'),
  body('username').isLength({ min: 3, max: 20 }),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    const captchaOk =
      req.body.captcha && req.session.captchaAnswer && req.body.captcha.trim() === req.session.captchaAnswer;
    if (!errors.isEmpty() || !captchaOk) {
      if (req.file) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (e) {}
      }
      const list = errors.array();
      if (!captchaOk) list.push({ msg: 'Invalid captcha' });
      return res
        .status(400)
        .render('auth/register', {
          errors: list,
          values: req.body,
          captchaQuestion: setCaptcha(req),
          pendingEmail: null,
          notice: null,
        });
    }
    const { username, email, password } = req.body;
    const existingUser = db.prepare('SELECT 1 FROM users WHERE username=? OR email=?').get(username, email);
    if (existingUser) {
      if (req.file) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (e) {}
      }
      return res
        .status(400)
        .render('auth/register', {
          errors: [{ msg: 'Username or email exists' }],
          values: req.body,
          captchaQuestion: setCaptcha(req),
        });
    }
    try {
      const hash = bcrypt.hashSync(password, 10);
      const avatarPath = req.file ? '/uploads/avatars/' + path.basename(req.file.path) : '';
      db.prepare(
        'INSERT INTO users (username, email, password_hash, is_admin, avatar_path, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(username, email, hash, 0, avatarPath, dayjs().toISOString());
      res.redirect('/login');
    } catch (e) {
      if (req.file) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (e) {}
      }
      res
        .status(400)
        .render('auth/register', {
          errors: [{ msg: 'Username or email exists' }],
          values: req.body,
          captchaQuestion: setCaptcha(req),
        });
    }
  }
);
app.get('/login', (req, res) => res.render('auth/login', { error: null, captchaQuestion: setCaptcha(req) }));
app.post('/login', authLimiter, (req, res) => {
  const { username, password } = req.body;
  const captchaOk =
    req.body.captcha && req.session.captchaAnswer && req.body.captcha.trim() === req.session.captchaAnswer;
  if (!captchaOk) {
    return res.status(401).render('auth/login', { error: 'Invalid captcha', captchaQuestion: setCaptcha(req) });
  }
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res
      .status(401)
      .render('auth/login', { error: 'Invalid credentials', captchaQuestion: setCaptcha(req) });
  }
  req.session.user = {
    id: user.id,
    username: user.username,
    is_admin: !!user.is_admin,
    is_verified: !!user.is_verified,
    avatar_path: user.avatar_path || '',
    bio: user.bio || '',
  };
  res.redirect('/');
});
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// User features
app.get('/profile', requireAuth, (req, res) => {
  const user = req.session.user;
  const favorites = db
    .prepare('SELECT a.* FROM favorites f JOIN anime a ON a.id=f.anime_id WHERE f.user_id=?')
    .all(user.id);
  const history = db
    .prepare(
      `SELECT wh.*, e.title AS episode_title, e.number, a.title AS anime_title, a.slug
       FROM watch_history wh 
       JOIN episodes e ON e.id=wh.episode_id 
       JOIN anime a ON a.id=e.anime_id
       WHERE wh.user_id=? ORDER BY wh.updated_at DESC LIMIT 50`
    )
    .all(user.id);
  const verifyRequest = db
    .prepare('SELECT status FROM verification_requests WHERE user_id=?')
    .get(user.id);
  res.render('profile', { favorites, history, verifyRequest });
});

app.get('/profile/edit', requireAuth, (req, res) => {
  const user = db.prepare('SELECT username, bio, avatar_path FROM users WHERE id=?').get(req.session.user.id);
  res.render('profile_edit', { errors: [], values: { username: user.username, bio: user.bio || '' }, avatar: user.avatar_path || '' });
});

app.post(
  '/profile/edit',
  requireAuth,
  upload.single('avatar'),
  body('username').isLength({ min: 3, max: 20 }),
  body('bio').isLength({ max: 300 }),
  (req, res) => {
    const errors = validationResult(req);
    const username = String(req.body.username || '').trim();
    const bio = String(req.body.bio || '').trim();
    const current = db.prepare('SELECT username, avatar_path FROM users WHERE id=?').get(req.session.user.id);
    if (!errors.isEmpty()) {
      if (req.file) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (e) {}
      }
      return res.status(400).render('profile_edit', {
        errors: errors.array(),
        values: { username, bio },
        avatar: current.avatar_path || '',
      });
    }
    const existing = db.prepare('SELECT id FROM users WHERE username=? AND id<>?').get(username, req.session.user.id);
    if (existing) {
      if (req.file) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (e) {}
      }
      return res.status(400).render('profile_edit', {
        errors: [{ msg: 'Username already taken' }],
        values: { username, bio },
        avatar: current.avatar_path || '',
      });
    }
    const avatarPath = req.file ? '/uploads/avatars/' + path.basename(req.file.path) : current.avatar_path || '';
    if (req.file && current.avatar_path) {
      const oldPath = path.join(avatarDir, path.basename(current.avatar_path));
      if (fs.existsSync(oldPath)) {
        try {
          fs.unlinkSync(oldPath);
        } catch (e) {}
      }
    }
    db.prepare('UPDATE users SET username=?, bio=?, avatar_path=? WHERE id=?').run(
      username,
      bio,
      avatarPath,
      req.session.user.id
    );
    res.redirect(`/user/${username}`);
  }
);

app.get('/user/:username', (req, res) => {
  const username = String(req.params.username || '').trim();
  const profileUser = db
    .prepare('SELECT id, username, is_verified, avatar_path, bio, created_at FROM users WHERE username=?')
    .get(username);
  if (!profileUser) return res.status(404).send('User not found');
  const favorites = db
    .prepare(
      `SELECT a.* FROM favorites f
       JOIN anime a ON a.id=f.anime_id
       WHERE f.user_id=?
       ORDER BY f.created_at DESC
       LIMIT 12`
    )
    .all(profileUser.id);
  const stats = {
    favoritesCount: db.prepare('SELECT COUNT(*) AS c FROM favorites WHERE user_id=?').get(profileUser.id).c,
    followersCount: db.prepare('SELECT COUNT(*) AS c FROM followers WHERE following_id=?').get(profileUser.id).c,
    followingCount: db.prepare('SELECT COUNT(*) AS c FROM followers WHERE follower_id=?').get(profileUser.id).c,
    likesCount: db.prepare('SELECT COUNT(*) AS c FROM likes WHERE user_id=? AND value=1').get(profileUser.id).c,
    postsCount: db
      .prepare('SELECT COUNT(*) AS c FROM forum_posts WHERE user_id=? AND is_deleted=0')
      .get(profileUser.id).c,
  };
  const viewerId = req.session.user ? req.session.user.id : null;
  const posts = db
    .prepare(
      `SELECT f.*, 
       COALESCE(SUM(CASE WHEN r.value=1 THEN 1 ELSE 0 END), 0) AS like_count,
       COALESCE(SUM(CASE WHEN r.value=-1 THEN 1 ELSE 0 END), 0) AS dislike_count,
       (SELECT value FROM forum_post_reactions WHERE user_id=? AND post_id=f.id) AS my_reaction,
       (SELECT COUNT(*) FROM forum_post_comments c WHERE c.post_id=f.id AND c.is_deleted=0) AS comment_count
       FROM forum_posts f
       LEFT JOIN forum_post_reactions r ON r.post_id=f.id
       WHERE f.user_id=? AND f.is_deleted=0
       GROUP BY f.id
       ORDER BY f.created_at DESC
       LIMIT 10`
    )
    .all(viewerId || null, profileUser.id);
  const followers = db
    .prepare(
      `SELECT u.username, u.is_verified, u.avatar_path
       FROM followers f JOIN users u ON u.id=f.follower_id
       WHERE f.following_id=?
       ORDER BY f.created_at DESC
       LIMIT 10`
    )
    .all(profileUser.id);
  const following = db
    .prepare(
      `SELECT u.username, u.is_verified, u.avatar_path
       FROM followers f JOIN users u ON u.id=f.following_id
       WHERE f.follower_id=?
       ORDER BY f.created_at DESC
       LIMIT 10`
    )
    .all(profileUser.id);
  const isSelf = viewerId && viewerId === profileUser.id;
  const isFollowing = viewerId
    ? !!db
        .prepare('SELECT 1 FROM followers WHERE follower_id=? AND following_id=?')
        .get(viewerId, profileUser.id)
    : false;
  const commentsMap = getForumPostComments(posts.map((p) => p.id));
  res.render('user_profile', {
    profileUser,
    favorites,
    stats,
    followers,
    following,
    posts,
    commentsMap,
    isFollowing,
    isSelf,
  });
});

app.post('/user/:username/follow', requireAuth, (req, res) => {
  const username = String(req.params.username || '').trim();
  const target = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if (!target) return res.status(404).send('User not found');
  if (target.id === req.session.user.id) return res.redirect(`/user/${username}`);
  db.prepare(
    'INSERT OR IGNORE INTO followers (follower_id, following_id, created_at) VALUES (?, ?, ?)'
  ).run(req.session.user.id, target.id, dayjs().toISOString());
  res.redirect(`/user/${username}`);
});

app.post('/user/:username/unfollow', requireAuth, (req, res) => {
  const username = String(req.params.username || '').trim();
  const target = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if (!target) return res.status(404).send('User not found');
  db.prepare('DELETE FROM followers WHERE follower_id=? AND following_id=?').run(
    req.session.user.id,
    target.id
  );
  res.redirect(`/user/${username}`);
});

app.get('/chats', requireAuth, (req, res) => {
  const chats = db
    .prepare(
      `SELECT c.id, c.user1_id, c.user2_id,
       u1.username AS user1_name, u1.avatar_path AS user1_avatar, u1.is_verified AS user1_verified,
       u2.username AS user2_name, u2.avatar_path AS user2_avatar, u2.is_verified AS user2_verified,
       (SELECT content FROM chat_messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1) AS last_message,
       (SELECT created_at FROM chat_messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1) AS last_at
       FROM chats c
       JOIN users u1 ON u1.id=c.user1_id
       JOIN users u2 ON u2.id=c.user2_id
       WHERE c.user1_id=? OR c.user2_id=?
       ORDER BY COALESCE(last_at, c.created_at) DESC`
    )
    .all(req.session.user.id, req.session.user.id)
    .map((c) => {
      const isUser1 = c.user1_id === req.session.user.id;
      return {
        id: c.id,
        username: isUser1 ? c.user2_name : c.user1_name,
        avatar: isUser1 ? c.user2_avatar : c.user1_avatar,
        is_verified: isUser1 ? c.user2_verified : c.user1_verified,
        last_message: c.last_message || '',
        last_at: c.last_at || c.created_at,
      };
    });
  res.render('chats', { chats });
});

app.get('/chat/:username', requireAuth, (req, res) => {
  const other = db
    .prepare('SELECT id, username, avatar_path, is_verified FROM users WHERE username=?')
    .get(req.params.username);
  if (!other) return res.status(404).send('User not found');
  if (other.id === req.session.user.id) return res.redirect('/chats');
  const pair = [req.session.user.id, other.id].sort((a, b) => a - b);
  let chat = db.prepare('SELECT * FROM chats WHERE user1_id=? AND user2_id=?').get(pair[0], pair[1]);
  if (!chat) {
    db.prepare('INSERT INTO chats (user1_id, user2_id, created_at) VALUES (?, ?, ?)').run(
      pair[0],
      pair[1],
      dayjs().toISOString()
    );
    chat = db.prepare('SELECT * FROM chats WHERE user1_id=? AND user2_id=?').get(pair[0], pair[1]);
  }
  const messages = db
    .prepare(
      `SELECT m.*, u.username, u.avatar_path
       FROM chat_messages m JOIN users u ON u.id=m.sender_id
       WHERE m.chat_id=?
       ORDER BY m.created_at ASC`
    )
    .all(chat.id);
  res.render('chat', { other, messages, chatId: chat.id });
});

app.post(
  '/chat/:username',
  requireAuth,
  body('content').isLength({ min: 1, max: 1000 }),
  (req, res) => {
    const errors = validationResult(req);
    const other = db.prepare('SELECT id FROM users WHERE username=?').get(req.params.username);
    if (!other) return res.status(404).send('User not found');
    if (!errors.isEmpty()) return res.redirect(`/chat/${req.params.username}`);
    const pair = [req.session.user.id, other.id].sort((a, b) => a - b);
    let chat = db.prepare('SELECT * FROM chats WHERE user1_id=? AND user2_id=?').get(pair[0], pair[1]);
    if (!chat) {
      db.prepare('INSERT INTO chats (user1_id, user2_id, created_at) VALUES (?, ?, ?)').run(
        pair[0],
        pair[1],
        dayjs().toISOString()
      );
      chat = db.prepare('SELECT * FROM chats WHERE user1_id=? AND user2_id=?').get(pair[0], pair[1]);
    }
    db.prepare('INSERT INTO chat_messages (chat_id, sender_id, content, created_at) VALUES (?, ?, ?, ?)').run(
      chat.id,
      req.session.user.id,
      String(req.body.content || '').trim(),
      dayjs().toISOString()
    );
    res.redirect(`/chat/${req.params.username}`);
  }
);

app.get('/verify-request', requireAuth, (req, res) => {
  const user = req.session.user;
  const request = db
    .prepare('SELECT status FROM verification_requests WHERE user_id=?')
    .get(user.id);
  res.render('verify_request', { request });
});

app.post('/verify-request', requireAuth, (req, res) => {
  const user = req.session.user;
  const existing = db
    .prepare('SELECT status FROM verification_requests WHERE user_id=?')
    .get(user.id);
  if (!existing) {
    db.prepare(
      'INSERT INTO verification_requests (user_id, status, created_at) VALUES (?, ?, ?)'
    ).run(user.id, 'pending', dayjs().toISOString());
  }
  res.redirect('/verify-request');
});

app.post('/anime/:id/favorite', requireAuth, (req, res) => {
  const animeId = Number(req.params.id);
  try {
    db.prepare('INSERT OR IGNORE INTO favorites (user_id, anime_id, created_at) VALUES (?, ?, ?)').run(
      req.session.user.id,
      animeId,
      dayjs().toISOString()
    );
    res.json({ ok: true });
  } catch {
    res.status(400).json({ ok: false });
  }
});
app.delete('/anime/:id/favorite', requireAuth, (req, res) => {
  const animeId = Number(req.params.id);
  db.prepare('DELETE FROM favorites WHERE user_id=? AND anime_id=?').run(req.session.user.id, animeId);
  res.json({ ok: true });
});

app.post('/like', requireAuth, (req, res) => {
  const { anime_id, episode_id, value } = req.body;
  const v = Number(value) === -1 ? -1 : 1;
  db.prepare(
    'INSERT INTO likes (user_id, anime_id, episode_id, value, created_at) VALUES (?, ?, ?, ?, ?) ' +
      'ON CONFLICT(user_id, anime_id, episode_id) DO UPDATE SET value=excluded.value'
  ).run(req.session.user.id, anime_id || null, episode_id || null, v, dayjs().toISOString());
  res.json({ ok: true });
});

app.post('/comments', requireAuth, commentLimiter, body('content').isLength({ min: 1, max: 1000 }), (req, res) => {
  const { anime_id, episode_id, content } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ ok: false, errors: errors.array() });
  db.prepare(
    'INSERT INTO comments (user_id, anime_id, episode_id, content, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(req.session.user.id, anime_id || null, episode_id || null, content, dayjs().toISOString());
  res.json({ ok: true });
});

app.post('/progress', requireAuth, (req, res) => {
  const { episode_id, last_time } = req.body;
  db.prepare(
    'INSERT INTO watch_history (user_id, episode_id, last_time, updated_at) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT(user_id, episode_id) DO UPDATE SET last_time=excluded.last_time, updated_at=excluded.updated_at'
  ).run(req.session.user.id, Number(episode_id), Number(last_time), dayjs().toISOString());
  res.json({ ok: true });
});

function getForumPosts(viewerId) {
  return db
    .prepare(
      `SELECT f.*, u.username, u.is_verified,
       COALESCE(SUM(CASE WHEN r.value=1 THEN 1 ELSE 0 END), 0) AS like_count,
       COALESCE(SUM(CASE WHEN r.value=-1 THEN 1 ELSE 0 END), 0) AS dislike_count,
       (SELECT value FROM forum_post_reactions WHERE user_id=? AND post_id=f.id) AS my_reaction,
       (SELECT COUNT(*) FROM forum_post_comments c WHERE c.post_id=f.id AND c.is_deleted=0) AS comment_count
       FROM forum_posts f
       JOIN users u ON u.id=f.user_id
       LEFT JOIN forum_post_reactions r ON r.post_id=f.id
       WHERE f.is_deleted=0
       GROUP BY f.id
       ORDER BY f.created_at DESC`
    )
    .all(viewerId || null);
}

function getForumPostComments(postIds) {
  if (!postIds.length) return {};
  const placeholders = postIds.map(() => '?').join(',');
  const rows = db
    .prepare(
      `SELECT c.*, u.username, u.is_verified, u.avatar_path,
       ru.username AS reply_to_username
       FROM forum_post_comments c
       JOIN users u ON u.id=c.user_id
       LEFT JOIN forum_post_comments rc ON rc.id=c.reply_to_comment_id AND rc.is_deleted=0
       LEFT JOIN users ru ON ru.id=rc.user_id
       WHERE c.is_deleted=0 AND c.post_id IN (${placeholders})
       ORDER BY c.created_at ASC`
    )
    .all(...postIds);
  const map = {};
  rows.forEach((row) => {
    if (!map[row.post_id]) map[row.post_id] = [];
    map[row.post_id].push(row);
  });
  return map;
}

app.get('/forum', (req, res) => {
  const viewerId = req.session.user ? req.session.user.id : null;
  const posts = getForumPosts(viewerId);
  const commentsMap = getForumPostComments(posts.map((p) => p.id));
  res.render('forum', { posts, commentsMap, error: null });
});

app.post(
  '/forum',
  requireAuth,
  upload.single('video'),
  body('title').isLength({ min: 3, max: 120 }),
  body('content').isLength({ min: 1, max: 4000 }),
  (req, res) => {
    const errors = validationResult(req);
    const user = req.session.user;
    if (!user.is_verified) {
      if (req.file) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (e) {}
      }
      const posts = getForumPosts(user.id);
      const commentsMap = getForumPostComments(posts.map((p) => p.id));
      return res.status(403).render('forum', { posts, commentsMap, error: 'Only verified users can create posts.' });
    }
    const videoUrl = String(req.body.video_url || '').trim();
    const fileUrl = req.file ? '/uploads/videos/' + path.basename(req.file.path) : '';
    const finalVideo = fileUrl || videoUrl;
    if (!errors.isEmpty()) {
      const posts = getForumPosts(user.id);
      const commentsMap = getForumPostComments(posts.map((p) => p.id));
      return res.status(400).render('forum', { posts, commentsMap, error: 'Please fill out all fields correctly.' });
    }
    db.prepare(
      'INSERT INTO forum_posts (user_id, title, content, video_url, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(user.id, req.body.title.trim(), req.body.content.trim(), finalVideo, dayjs().toISOString());
    res.redirect('/forum');
  }
);

app.post(
  '/forum/:id/react',
  requireAuth,
  body('value').isIn(['1', '-1', '0']),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).send('Invalid input');
    const postId = Number(req.params.id);
    const post = db.prepare('SELECT id FROM forum_posts WHERE id=? AND is_deleted=0').get(postId);
    if (!post) return res.status(404).send('Post not found');
    const value = Number(req.body.value);
    const existing = db
      .prepare('SELECT value FROM forum_post_reactions WHERE user_id=? AND post_id=?')
      .get(req.session.user.id, postId);
    if (value === 0 || (existing && existing.value === value)) {
      db.prepare('DELETE FROM forum_post_reactions WHERE user_id=? AND post_id=?').run(
        req.session.user.id,
        postId
      );
      return res.redirect('/forum');
    }
    db.prepare(
      'INSERT INTO forum_post_reactions (user_id, post_id, value, created_at) VALUES (?, ?, ?, ?) ' +
        'ON CONFLICT(user_id, post_id) DO UPDATE SET value=excluded.value'
    ).run(req.session.user.id, postId, value, dayjs().toISOString());
    res.redirect('/forum');
  }
);

app.post(
  '/forum/:id/comment',
  requireAuth,
  body('content').isLength({ min: 1, max: 1000 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.redirect(req.get('Referer') || '/forum');
    const postId = Number(req.params.id);
    const post = db.prepare('SELECT id FROM forum_posts WHERE id=? AND is_deleted=0').get(postId);
    if (!post) return res.status(404).send('Post not found');
    const content = String(req.body.content || '').trim();
    if (!content) return res.redirect(req.get('Referer') || '/forum');
    const replyToRaw = req.body.reply_to ? Number(req.body.reply_to) : null;
    let replyTo = null;
    if (replyToRaw) {
      const parent = db
        .prepare('SELECT id FROM forum_post_comments WHERE id=? AND post_id=? AND is_deleted=0')
        .get(replyToRaw, postId);
      if (parent) replyTo = parent.id;
    }
    db.prepare(
      'INSERT INTO forum_post_comments (post_id, user_id, reply_to_comment_id, content, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(postId, req.session.user.id, replyTo, content, dayjs().toISOString());
    res.redirect(req.get('Referer') || '/forum');
  }
);

app.post('/forum/comments/:id/delete', requireAuth, (req, res) => {
  const commentId = Number(req.params.id);
  const comment = db
    .prepare('SELECT id, post_id, user_id FROM forum_post_comments WHERE id=? AND is_deleted=0')
    .get(commentId);
  if (!comment) return res.status(404).send('Comment not found');
  const post = db.prepare('SELECT user_id FROM forum_posts WHERE id=? AND is_deleted=0').get(comment.post_id);
  const canDelete =
    comment.user_id === req.session.user.id ||
    (post && post.user_id === req.session.user.id) ||
    req.session.user.is_admin;
  if (!canDelete) return res.status(403).send('Forbidden');
  db.prepare('UPDATE forum_post_comments SET is_deleted=1 WHERE id=?').run(commentId);
  res.redirect(req.get('Referer') || '/forum');
});

app.post(
  '/forum/comments/:id/edit',
  requireAuth,
  body('content').isLength({ min: 1, max: 1000 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.redirect(req.get('Referer') || '/forum');
    const commentId = Number(req.params.id);
    const comment = db
      .prepare('SELECT id, user_id FROM forum_post_comments WHERE id=? AND is_deleted=0')
      .get(commentId);
    if (!comment) return res.status(404).send('Comment not found');
    if (comment.user_id !== req.session.user.id && !req.session.user.is_admin) {
      return res.status(403).send('Forbidden');
    }
    const content = String(req.body.content || '').trim();
    if (!content) return res.redirect(req.get('Referer') || '/forum');
    db.prepare('UPDATE forum_post_comments SET content=? WHERE id=?').run(content, commentId);
    res.redirect(req.get('Referer') || '/forum');
  }
);

// Admin
app.get('/admin/login', (req, res) =>
  res.render('admin/login', { error: null, captchaQuestion: setCaptcha(req) })
);
app.post('/admin/login', authLimiter, (req, res) => {
  const { username, password } = req.body;
  const captchaOk =
    req.body.captcha && req.session.captchaAnswer && req.body.captcha.trim() === req.session.captchaAnswer;
  if (!captchaOk) {
    return res.status(401).render('admin/login', { error: 'Invalid captcha', captchaQuestion: setCaptcha(req) });
  }
  const user = db.prepare('SELECT * FROM users WHERE username=? AND is_admin=1').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res
      .status(401)
      .render('admin/login', { error: 'Invalid credentials', captchaQuestion: setCaptcha(req) });
  }
  req.session.user = { id: user.id, username: user.username, is_admin: true };
  res.redirect('/admin');
});

app.get('/admin', requireAdmin, (req, res) => {
  const usersCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  const viewsCount = db.prepare('SELECT COUNT(*) AS c FROM views').get().c;
  const animeCount = db.prepare('SELECT COUNT(*) AS c FROM anime').get().c;
  const commentsCount = db.prepare('SELECT COUNT(*) AS c FROM comments WHERE is_deleted=0').get().c;
  const animeList = db
    .prepare(
      `SELECT a.*, COUNT(e.id) AS episode_count
       FROM anime a LEFT JOIN episodes e ON e.anime_id=a.id
       GROUP BY a.id
       ORDER BY a.created_at DESC`
    )
    .all();
  const recentComments = db
    .prepare(
      `SELECT c.id, c.content, u.username
       FROM comments c JOIN users u ON u.id=c.user_id
       WHERE c.is_deleted=0
       ORDER BY c.created_at DESC LIMIT 10`
    )
    .all();
  const pendingVerifications = db
    .prepare("SELECT COUNT(*) AS c FROM verification_requests WHERE status='pending'")
    .get().c;
  res.render('admin/index', {
    usersCount,
    viewsCount,
    animeCount,
    commentsCount,
    animeList,
    recentComments,
    pendingVerifications,
  });
});

app.get('/admin/anime/new', requireAdmin, (req, res) => {
  res.render('admin/anime_form', { anime: null, errors: [], values: {} });
});

app.get('/admin/videos', requireAdmin, (req, res) => {
  const files = fs
    .readdirSync(videoDir)
    .filter((f) => !f.startsWith('.'))
    .map((f) => ({ name: f, url: '/uploads/videos/' + f }));
  res.render('admin/videos', { files });
});

app.post('/admin/videos', requireAdmin, upload.single('video'), (req, res) => {
  res.redirect('/admin/videos');
});

app.get('/admin/verify-requests', requireAdmin, (req, res) => {
  const requests = db
    .prepare(
      `SELECT r.*, u.username, u.email, u.is_verified
       FROM verification_requests r JOIN users u ON u.id=r.user_id
       ORDER BY r.created_at DESC`
    )
    .all();
  res.render('admin/verify_requests', { requests });
});

app.post('/admin/verify-requests/:id/approve', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT user_id FROM verification_requests WHERE id=?').get(id);
  if (row) {
    db.prepare("UPDATE verification_requests SET status='approved', decided_at=? WHERE id=?").run(
      dayjs().toISOString(),
      id
    );
    db.prepare('UPDATE users SET is_verified=1 WHERE id=?').run(row.user_id);
  }
  res.redirect('/admin/verify-requests');
});

app.post('/admin/verify-requests/:id/reject', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT user_id FROM verification_requests WHERE id=?').get(id);
  if (row) {
    db.prepare("UPDATE verification_requests SET status='rejected', decided_at=? WHERE id=?").run(
      dayjs().toISOString(),
      id
    );
    db.prepare('UPDATE users SET is_verified=0 WHERE id=?').run(row.user_id);
  }
  res.redirect('/admin/verify-requests');
});

app.get('/admin/forum', requireAdmin, (req, res) => {
  const posts = db
    .prepare(
      `SELECT f.*, u.username, u.is_verified
       FROM forum_posts f JOIN users u ON u.id=f.user_id
       ORDER BY f.created_at DESC`
    )
    .all();
  res.render('admin/forum', { posts });
});

app.post('/admin/forum/:id/delete', requireAdmin, (req, res) => {
  db.prepare('UPDATE forum_posts SET is_deleted=1 WHERE id=?').run(Number(req.params.id));
  res.redirect('/admin/forum');
});

app.post(
  '/admin/anime',
  requireAdmin,
  upload.single('cover'),
  body('title').isLength({ min: 1 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).render('admin/anime_form', { anime: null, errors: errors.array(), values: req.body });
    const { title, description, genres } = req.body;
    const slug = slugify(title, { lower: true, strict: true });
    const cover_path = req.file ? '/uploads/covers/' + path.basename(req.file.path) : '';
    try {
      db.prepare(
        'INSERT INTO anime (title, slug, description, cover_path, genres, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(title, slug, description || '', cover_path, genresArrayToString(genres?.split(',') || []), dayjs().toISOString());
      res.redirect('/admin');
    } catch (e) {
      res.status(400).render('admin/anime_form', { anime: null, errors: [{ msg: 'Title/slug exists' }], values: req.body });
    }
  }
);

app.get('/admin/anime/:id', requireAdmin, (req, res) => {
  const anime = db.prepare('SELECT * FROM anime WHERE id=?').get(Number(req.params.id));
  if (!anime) return res.status(404).send('Not found');
  const episodes = db.prepare('SELECT * FROM episodes WHERE anime_id=? ORDER BY number ASC').all(anime.id);
  const comments = db
    .prepare(
      `SELECT c.id, c.content, u.username
       FROM comments c JOIN users u ON u.id=c.user_id
       WHERE c.anime_id=? AND c.is_deleted=0
       ORDER BY c.created_at DESC`
    )
    .all(anime.id);
  res.render('admin/anime_edit', { anime, episodes, comments, errors: [] });
});

app.post('/admin/anime/:id', requireAdmin, upload.single('cover'), (req, res) => {
  const anime = db.prepare('SELECT * FROM anime WHERE id=?').get(Number(req.params.id));
  if (!anime) return res.status(404).send('Not found');
  const { title, description, genres } = req.body;
  const slug = slugify(title, { lower: true, strict: true });
  let cover_path = anime.cover_path;
  if (req.file) {
    cover_path = '/uploads/covers/' + path.basename(req.file.path);
  }
  db.prepare('UPDATE anime SET title=?, slug=?, description=?, cover_path=?, genres=? WHERE id=?').run(
    title,
    slug,
    description || '',
    cover_path,
    genresArrayToString(genres?.split(',') || []),
    anime.id
  );
  res.redirect(`/admin/anime/${anime.id}`);
});

app.post('/admin/anime/:id/delete', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM anime WHERE id=?').run(Number(req.params.id));
  res.redirect('/admin');
});

// Episodes
app.post('/admin/anime/:id/episodes', requireAdmin, upload.fields([{ name: 'video_360' }, { name: 'video_720' }, { name: 'video_1080' }]), (req, res) => {
  const animeId = Number(req.params.id);
  const { number, title, video_360_url, video_720_url, video_1080_url } = req.body;
  const f = req.files || {};
  const v360File = f.video_360?.[0] ? '/uploads/videos/' + path.basename(f.video_360[0].path) : '';
  const v720File = f.video_720?.[0] ? '/uploads/videos/' + path.basename(f.video_720[0].path) : '';
  const v1080File = f.video_1080?.[0] ? '/uploads/videos/' + path.basename(f.video_1080[0].path) : '';
  const normalizeUrl = (value) => {
    const v = (value || '').trim();
    if (!v) return '';
    if (v.startsWith('http://') || v.startsWith('https://') || v.startsWith('/uploads/')) return v;
    return '/uploads/videos/' + v.replace(/^\/+/, '');
  };
  const v360 = v360File || normalizeUrl(video_360_url);
  const v720 = v720File || normalizeUrl(video_720_url);
  const v1080 = v1080File || normalizeUrl(video_1080_url);
  try {
    db.prepare(
      'INSERT INTO episodes (anime_id, number, title, video_360, video_720, video_1080, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(animeId, Number(number), title || `Episode ${number}`, v360, v720, v1080, dayjs().toISOString());
  } catch (e) {
    // ignore uniqueness errors
  }
  res.redirect(`/admin/anime/${animeId}`);
});

app.post('/admin/episodes/:id/delete', requireAdmin, (req, res) => {
  const epId = Number(req.params.id);
  const ep = db.prepare('SELECT * FROM episodes WHERE id=?').get(epId);
  if (ep) {
    db.prepare('DELETE FROM episodes WHERE id=?').run(epId);
    res.redirect(`/admin/anime/${ep.anime_id}`);
  } else {
    res.redirect('/admin');
  }
});

// Comment moderation
app.post('/admin/comments/:id/delete', requireAdmin, (req, res) => {
  db.prepare('UPDATE comments SET is_deleted=1 WHERE id=?').run(Number(req.params.id));
  res.json({ ok: true });
});

// SEO friendly sitemeta
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send('User-agent: *\nAllow: /');
});

app.listen(PORT, () => {
  console.log(`ZeroAnime running on http://localhost:${PORT}`);
});
