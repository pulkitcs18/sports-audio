require('dotenv').config();
const express      = require('express');
const axios        = require('axios');
const cors         = require('cors');
const path         = require('path');
const crypto       = require('crypto');
const Database     = require('better-sqlite3');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const rateLimit    = require('express-rate-limit');

// ── Env validation ────────────────────────────────────────────────────────
const BASE_URL        = 'https://stevesrodeo.com';
const PORT            = process.env.PORT || 3000;
const DEVICE_ID       = process.env.STEVE_DEVICE_ID;
const STEVE_USERNAME  = process.env.STEVE_USERNAME;
const STEVE_PASSWORD  = process.env.STEVE_PASSWORD;
const JWT_SECRET      = process.env.JWT_SECRET;
const ADMIN_USERNAME  = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD  = process.env.ADMIN_PASSWORD;
// Comma-separated list of allowed origins, e.g. "https://sportsaudio.dev,http://localhost:3000"
const CORS_ORIGINS    = (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',').map(s => s.trim());

for (const [k, v] of Object.entries({
  STEVE_DEVICE_ID: DEVICE_ID, STEVE_USERNAME, STEVE_PASSWORD,
  JWT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
})) {
  if (!v) { console.error(`Missing required env var: ${k}`); process.exit(1); }
}

// ── SQLite ────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'users.db'));

db.exec(`CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_access   INTEGER NOT NULL DEFAULT 0
)`);

// Migrate: add full_access column if upgrading from older schema
const cols = db.prepare('PRAGMA table_info(users)').all();
if (!cols.find(c => c.name === 'full_access')) {
  db.exec('ALTER TABLE users ADD COLUMN full_access INTEGER NOT NULL DEFAULT 0');
}

db.exec(`CREATE TABLE IF NOT EXISTS user_channels (
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  channel_id TEXT    NOT NULL,
  PRIMARY KEY (user_id, channel_id)
)`);

// Sessions table: one active session per user; login kills all previous sessions
db.exec(`CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT    PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
)`);

// Seed family accounts — passwords come from env vars, NOT hardcoded here.
// Set SEED_HARSHIT_PW, SEED_PRIYA_PW, etc. in .env or skip seeding entirely.
const SEED_USERS = [
  { username: 'harshit', envKey: 'SEED_HARSHIT_PW'  },
  { username: 'priya',   envKey: 'SEED_PRIYA_PW'    },
  { username: 'rahul',   envKey: 'SEED_RAHUL_PW'    },
  { username: 'anita',   envKey: 'SEED_ANITA_PW'    },
  { username: 'vikram',  envKey: 'SEED_VIKRAM_PW'   },
];
const insertUser     = db.prepare('INSERT OR IGNORE INTO users (username, password_hash, full_access) VALUES (?, ?, 1)');
const grantFullAccess = db.prepare('UPDATE users SET full_access = 1 WHERE username = ?');
for (const u of SEED_USERS) {
  const pw = process.env[u.envKey];
  if (pw) {
    insertUser.run(u.username, bcrypt.hashSync(pw, 10));
    grantFullAccess.run(u.username);
  }
}
console.log('✅ SQLite users ready');

// ── Helpers ───────────────────────────────────────────────────────────────

function getAllowedChannels(userId) {
  const user = db.prepare('SELECT full_access FROM users WHERE id = ?').get(userId);
  if (!user || user.full_access) return null;
  return db.prepare('SELECT channel_id FROM user_channels WHERE user_id = ?')
    .all(userId).map(r => r.channel_id);
}

// ── Steve's Rodeo shared token ────────────────────────────────────────────
let steveToken = null;
let steveTokenExpiry = 0;
let steveTokenRefreshPromise = null;

async function getSteveToken() {
  if (steveToken && Date.now() < steveTokenExpiry) return steveToken;
  if (steveTokenRefreshPromise) return steveTokenRefreshPromise;

  steveTokenRefreshPromise = (async () => {
    console.log("🔐 Refreshing Steve's Rodeo token…");
    const { data } = await axios.post(
      `${BASE_URL}/pb/api/collections/users/auth-with-password`,
      { identity: STEVE_USERNAME, password: STEVE_PASSWORD },
      { headers: { 'Content-Type': 'application/json' } }
    );
    steveToken = data.token;
    steveTokenExpiry = Date.now() + 23 * 60 * 60 * 1000;
    try {
      await axios.post(`${BASE_URL}/api/login-lock`, {}, {
        headers: { 'Authorization': `Bearer ${steveToken}`, 'x-device-id': DEVICE_ID }
      });
    } catch (e) {
      console.warn('login-lock failed (non-fatal):', e.message);
    }
    console.log("✅ Steve's Rodeo token refreshed");
    return steveToken;
  })().finally(() => { steveTokenRefreshPromise = null; });

  return steveTokenRefreshPromise;
}

// ── Express ───────────────────────────────────────────────────────────────
const app = express();

// CORS: only allow our own domain(s)
app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (same-origin browser requests, curl, Postman)
    if (!origin || CORS_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));

app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Rate limiting ─────────────────────────────────────────────────────────

// Strict limit on login: 10 attempts per 15 minutes per IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
});

// General API limit: 200 req/min per IP (protects against scraping)
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests.' },
});

app.use('/api/', apiLimiter);
app.use('/auth/', apiLimiter);

// ── Auth middleware ───────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : header;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role === 'admin') return res.status(403).json({ error: 'Use user token' });
    if (!decoded.sessionId) return res.status(401).json({ error: 'Invalid token format' });

    // Validate session still exists in DB (killed if another device logged in)
    const sess = db.prepare('SELECT id FROM sessions WHERE id = ? AND user_id = ?')
      .get(decoded.sessionId, decoded.userId);
    if (!sess) return res.status(401).json({ error: 'Session expired — please log in again' });

    // Update last_seen
    db.prepare('UPDATE sessions SET last_seen = ? WHERE id = ?').run(Date.now(), decoded.sessionId);
    req.user = decoded;
    next();
  } catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

function requireAdmin(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : header;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    req.admin = decoded;
    next();
  } catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

// ── Auth routes ───────────────────────────────────────────────────────────

// POST /auth/login
app.post('/auth/login', loginLimiter, (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    // Always run bcrypt compare to prevent timing-based username enumeration
    const hash = user ? user.password_hash : '$2a$10$invalidhashfortimingnormalization';
    const valid = bcrypt.compareSync(password, hash);
    if (!user || !valid) return res.status(401).json({ error: 'Invalid credentials' });

    // One active session per user — kill all previous sessions (logs out other devices)
    const killed = db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id).changes;
    if (killed > 0) console.log(`⚠️  Killed ${killed} existing session(s) for ${user.username}`);

    // Create new session
    const sessionId = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (id, user_id, created_at, last_seen) VALUES (?, ?, ?, ?)')
      .run(sessionId, user.id, Date.now(), Date.now());

    const token = jwt.sign(
      { username: user.username, userId: user.id, sessionId },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    console.log(`✅ Login: ${username}`);
    res.json({ token, username: user.username });
  } catch (err) { console.error('Login error:', err); res.status(500).json({ error: 'Server error' }); }
});

// POST /auth/logout
app.post('/auth/logout', requireAuth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(req.user.sessionId);
  console.log(`✅ Logout: ${req.user.username}`);
  res.json({ ok: true });
});

// POST /auth/change-password
app.post('/auth/change-password', requireAuth, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    if (!user || !bcrypt.compareSync(currentPassword, user.password_hash))
      return res.status(401).json({ error: 'Current password is incorrect' });
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), user.id);
    // Invalidate ALL sessions — force re-login on every device
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
    console.log(`✅ Password changed: ${user.username}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// POST /admin/login
app.post('/admin/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD)
    return res.status(401).json({ error: 'Invalid admin credentials' });
  const token = jwt.sign({ role: 'admin', username }, JWT_SECRET, { expiresIn: '8h' });
  console.log(`✅ Admin login: ${username}`);
  res.json({ token });
});

// ── Admin routes ──────────────────────────────────────────────────────────

app.get('/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, username, full_access FROM users ORDER BY username').all();
  const result = users.map(u => {
    const channelCount   = db.prepare('SELECT COUNT(*) as n FROM user_channels WHERE user_id = ?').get(u.id).n;
    const activeSessions = db.prepare('SELECT COUNT(*) as n FROM sessions WHERE user_id = ?').get(u.id).n;
    return { id: u.id, username: u.username, full_access: !!u.full_access, channel_count: channelCount, active_sessions: activeSessions };
  });
  res.json(result);
});

app.post('/admin/users', requireAdmin, (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (username, password_hash, full_access) VALUES (?, ?, 0)').run(username, hash);
    console.log(`✅ Admin created user: ${username}`);
    res.json({ ok: true, id: result.lastInsertRowid, username });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/admin/users/:id', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  console.log(`✅ Admin deleted user: ${user.username}`);
  res.json({ ok: true });
});

app.post('/admin/users/:id/reset-password', requireAdmin, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), req.params.id);
  // Kill active sessions — force re-login
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id);
  console.log(`✅ Admin reset password for: ${user.username}`);
  res.json({ ok: true });
});

// Kick user: kill their session so they're logged out immediately
app.post('/admin/users/:id/kick', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id);
  console.log(`✅ Admin kicked: ${user.username}`);
  res.json({ ok: true });
});

app.get('/admin/users/:id/channels', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT id, username, full_access FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const channels = db.prepare('SELECT channel_id FROM user_channels WHERE user_id = ?').all(user.id).map(r => r.channel_id);
  res.json({ id: user.id, username: user.username, full_access: !!user.full_access, channels });
});

app.put('/admin/users/:id/channels', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { full_access, channel_ids } = req.body;
  db.transaction(() => {
    db.prepare('UPDATE users SET full_access = ? WHERE id = ?').run(full_access ? 1 : 0, user.id);
    db.prepare('DELETE FROM user_channels WHERE user_id = ?').run(user.id);
    if (!full_access && Array.isArray(channel_ids)) {
      const insert = db.prepare('INSERT OR IGNORE INTO user_channels (user_id, channel_id) VALUES (?, ?)');
      for (const cid of channel_ids) insert.run(user.id, cid);
    }
  })();
  console.log(`✅ Admin updated channels for ${user.username}: full_access=${full_access}, channels=${channel_ids?.length ?? 0}`);
  res.json({ ok: true });
});

app.get('/admin/channels', requireAdmin, async (req, res) => {
  try {
    const token = await getSteveToken();
    const { data } = await axios.get(`${BASE_URL}/api/listener/channels?all=1`, {
      headers: { 'Authorization': `Bearer ${token}`, 'x-device-id': DEVICE_ID }
    });
    res.json(data);
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

// ── API routes ────────────────────────────────────────────────────────────

app.get('/api/channels', requireAuth, async (req, res) => {
  try {
    const token = await getSteveToken();
    const { data } = await axios.get(`${BASE_URL}/api/listener/channels?all=1`, {
      headers: { 'Authorization': `Bearer ${token}`, 'x-device-id': DEVICE_ID }
    });
    const allowed = getAllowedChannels(req.user.userId);
    if (allowed === null) return res.json(data);
    const allowedSet = new Set(allowed);
    res.json(data.filter(ch => allowedSet.has(ch.id)));
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

// POST /api/session — returns LiveKit credentials for browser-side WebRTC connection
app.post('/api/session', requireAuth, async (req, res) => {
  try {
    const { channelId } = req.body;
    if (!channelId || typeof channelId !== 'string' || channelId.length > 200)
      return res.status(400).json({ error: 'channelId required' });

    const allowed = getAllowedChannels(req.user.userId);
    if (allowed !== null && !allowed.includes(channelId)) {
      console.warn(`⛔ ${req.user.username} denied access to channel ${channelId}`);
      return res.status(403).json({ error: 'Access denied for this channel' });
    }

    const token = await getSteveToken();
    const { data } = await axios.post(
      `${BASE_URL}/api/session/start`,
      { channel_id: channelId, device_id: DEVICE_ID },
      { headers: { 'Authorization': `Bearer ${token}`, 'x-device-id': DEVICE_ID, 'Content-Type': 'application/json' } }
    );

    console.log(`🎵 ${req.user.username} joined channel ${channelId}`);
    res.json({ token: data.token, url: data.url, sessionId: data.session_id });
  } catch (err) {
    console.error('Session error:', err.message);
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

// Catch-all: serve index.html for all non-API, non-admin routes
app.get('*', (req, res) => {
  if (req.path.startsWith('/admin')) {
    return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Graceful shutdown ─────────────────────────────────────────────────────
function shutdown(signal) {
  console.log(`\n${signal} received — shutting down…`);
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ── Start ─────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ Sports Audio server running at http://localhost:${PORT}`);
  console.log(`   CORS origins: ${CORS_ORIGINS.join(', ')}\n`);
  getSteveToken().catch(err => console.error("Initial Steve's token fetch failed:", err.message));
});
