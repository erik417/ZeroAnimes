const express = require('express');
const path = require('path');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const slugify = require('slugify');
const dayjs = require('dayjs');
const fs = require('fs');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Security & basic middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const uploadsDir = path.join(__dirname, '..', 'uploads');
const coverDir = path.join(uploadsDir, 'covers');
const videoDir = path.join(uploadsDir, 'videos');
if (!fs.existsSync(coverDir)) fs.mkdirSync(coverDir, { recursive: true });
if (!fs.existsSync(videoDir)) fs.mkdirSync(videoDir, { recursive: true });

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

const mailTransport =
  process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: String(process.env.SMTP_SECURE || '').toLowerCase() === 'true',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      })
    : null;
const mailFrom = process.env.SMTP_FROM || process.env.SMTP_USER || '';

// Views & static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use('/public', express.static(path.join(__dirname, '..', 'public')));
app.use('/uploads', express.static(uploadsDir));

// Multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'cover') return cb(null, coverDir);
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
function generateVerificationCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
function sendVerificationEmail(to, code) {
  if (!mailTransport || !mailFrom) return Promise.reject(new Error('Email service not configured'));
  return mailTransport.sendMail({
    from: mailFrom,
    to,
    subject: 'ZeroAnime verification code',
    text: `Your verification code: ${code}`,
  });
}
function genresArrayToString(genres) {
  if (Array.isArray(genres)) return genres.join(',');
  return String(genres || '');
}
function genresStringToArray(s) {
  return s ? s.split(',').map((g) => g.trim()).filter(Boolean) : [];
}

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
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
      `SELECT c.*, u.username FROM comments c JOIN users u ON u.id=c.user_id
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
    pendingEmail: null,
    notice: null,
  })
);
app.post(
  '/register',
  authLimiter,
  body('username').isLength({ min: 3, max: 20 }),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    const captchaOk =
      req.body.captcha && req.session.captchaAnswer && req.body.captcha.trim() === req.session.captchaAnswer;
    if (!errors.isEmpty() || !captchaOk) {
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
    db.prepare('DELETE FROM email_verifications WHERE expires_at < ?').run(dayjs().toISOString());
    const existingUser = db.prepare('SELECT 1 FROM users WHERE username=? OR email=?').get(username, email);
    if (existingUser) {
      return res
        .status(400)
        .render('auth/register', {
          errors: [{ msg: 'Username or email exists' }],
          values: req.body,
          captchaQuestion: setCaptcha(req),
          pendingEmail: null,
          notice: null,
        });
    }
    const pending = db.prepare('SELECT 1 FROM email_verifications WHERE username=? OR email=?').get(username, email);
    if (pending) {
      return res
        .status(400)
        .render('auth/register', {
          errors: [{ msg: 'Verification already sent. Check your email.' }],
          values: req.body,
          captchaQuestion: setCaptcha(req),
          pendingEmail: email,
          notice: null,
        });
    }
    try {
      const hash = bcrypt.hashSync(password, 10);
      const code = generateVerificationCode();
      const expiresAt = dayjs().add(15, 'minute').toISOString();
      db.prepare(
        'INSERT INTO email_verifications (username, email, password_hash, code, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(username, email, hash, code, expiresAt, dayjs().toISOString());
      try {
        await sendVerificationEmail(email, code);
        res.render('auth/register', {
          errors: [],
          values: {},
          captchaQuestion: setCaptcha(req),
          pendingEmail: email,
          notice: 'Verification code sent to your email.',
        });
      } catch (mailErr) {
        db.prepare('DELETE FROM email_verifications WHERE email=?').run(email);
        res
          .status(500)
          .render('auth/register', {
            errors: [{ msg: 'Email service not configured or unavailable' }],
            values: req.body,
            captchaQuestion: setCaptcha(req),
            pendingEmail: null,
            notice: null,
          });
      }
    } catch (e) {
      res
        .status(400)
        .render('auth/register', {
          errors: [{ msg: 'Username or email exists' }],
          values: req.body,
          captchaQuestion: setCaptcha(req),
          pendingEmail: null,
          notice: null,
        });
    }
  }
);
app.post('/register/verify', authLimiter, (req, res) => {
  const email = (req.body.email || '').trim();
  const code = (req.body.code || '').trim();
  if (!email || !code) {
    return res
      .status(400)
      .render('auth/register', {
        errors: [{ msg: 'Email and code are required' }],
        values: {},
        captchaQuestion: setCaptcha(req),
        pendingEmail: email || null,
        notice: null,
      });
  }
  db.prepare('DELETE FROM email_verifications WHERE expires_at < ?').run(dayjs().toISOString());
  const row = db.prepare('SELECT * FROM email_verifications WHERE email=? AND code=?').get(email, code);
  if (!row) {
    return res
      .status(400)
      .render('auth/register', {
        errors: [{ msg: 'Invalid or expired code' }],
        values: {},
        captchaQuestion: setCaptcha(req),
        pendingEmail: email,
        notice: null,
      });
  }
  try {
    db.prepare(
      'INSERT INTO users (username, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(row.username, row.email, row.password_hash, 0, dayjs().toISOString());
    db.prepare('DELETE FROM email_verifications WHERE id=?').run(row.id);
    res.redirect('/login');
  } catch (e) {
    db.prepare('DELETE FROM email_verifications WHERE id=?').run(row.id);
    res
      .status(400)
      .render('auth/register', {
        errors: [{ msg: 'Username or email exists' }],
        values: {},
        captchaQuestion: setCaptcha(req),
        pendingEmail: null,
        notice: null,
      });
  }
});
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
  req.session.user = { id: user.id, username: user.username, is_admin: !!user.is_admin };
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
  res.render('profile', { favorites, history });
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
  res.render('admin/index', { usersCount, viewsCount, animeCount, commentsCount, animeList, recentComments });
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
