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
// Comma-separated allowed origins, e.g. "https://sportsaudio.dev,http://localhost:3000"
const CORS_ORIGINS    = (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',').map(s => s.trim());

for (const [k, v] of Object.entries({
  STEVE_DEVICE_ID: DEVICE_ID, STEVE_USERNAME, STEVE_PASSWORD,
  JWT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD,
})) {
  if (!v) { console.error(`Missing required env var: ${k}`); process.exit(1); }
}

// Pre-compute a valid dummy hash used for constant-time login (prevents username enumeration).
// bcrypt.compareSync on an invalid hash format throws; using a real hash keeps timing uniform.
const DUMMY_HASH = bcrypt.hashSync('__dummy_timing_placeholder__', 10);

// ── SQLite ────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'users.db'));

db.exec(`CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_access   INTEGER NOT NULL DEFAULT 0
)`);

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
// Set SEED_HARSHIT_PW, SEED_PRIYA_PW, etc. in .env
const SEED_USERS = [
  { username: 'harshit', envKey: 'SEED_HARSHIT_PW' },
  { username: 'priya',   envKey: 'SEED_PRIYA_PW'   },
  { username: 'rahul',   envKey: 'SEED_RAHUL_PW'   },
  { username: 'anita',   envKey: 'SEED_ANITA_PW'   },
  { username: 'vikram',  envKey: 'SEED_VIKRAM_PW'  },
];
const insertUser      = db.prepare('INSERT OR IGNORE INTO users (username, password_hash, full_access) VALUES (?, ?, 1)');
const grantFullAccess = db.prepare('UPDATE users SET full_access = 1 WHERE username = ?');
for (const u of SEED_USERS) {
  const pw = process.env[u.envKey];
  if (pw) {
    insertUser.run(u.username, bcrypt.hashSync(pw, 10));
    grantFullAccess.run(u.username);
  }
}
console.log('✅ SQLite users ready');

// ── Per-account login failure tracking ───────────────────────────────────
// Prevents credential stuffing via IP rotation — each account locks after 5 failures.
// In-memory only (resets on restart), which is fine for a single-process deployment.
const loginFailures = new Map(); // username -> { count, lockedUntil }
const LOGIN_MAX_FAILURES  = 5;
const LOGIN_LOCKOUT_MS    = 15 * 60 * 1000; // 15 minutes

function checkLoginLock(username) {
  const rec = loginFailures.get(username);
  if (!rec) return null; // no failures
  if (rec.lockedUntil && Date.now() < rec.lockedUntil) {
    const mins = Math.ceil((rec.lockedUntil - Date.now()) / 60000);
    return `Account locked after too many failed attempts. Try again in ${mins} minute${mins !== 1 ? 's' : ''}.`;
  }
  return null;
}

function recordLoginFailure(username) {
  const rec = loginFailures.get(username) || { count: 0, lockedUntil: null };
  rec.count += 1;
  if (rec.count >= LOGIN_MAX_FAILURES) {
    rec.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
    console.warn(`🔒 Account locked: ${username} (${rec.count} failures)`);
  }
  loginFailures.set(username, rec);
}

function clearLoginFailures(username) {
  loginFailures.delete(username);
}

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

// Trust exactly one proxy hop (Nginx). Without this, req.ip is always 127.0.0.1
// and rate limiting either blocks everyone or can be trivially spoofed via X-Forwarded-For.
// If you add Cloudflare in front of Nginx later, change this to 2.
app.set('trust proxy', 1);

// CORS: only allow our own domain(s)
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || CORS_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));

app.use(express.json({ limit: '16kb' }));

// ── Security headers ──────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // connect-src wss: covers any LiveKit SFU domain (we don't know it at build time).
  // unsafe-inline for style-src is required because all CSS is inline in the HTML.
  // unsafe-inline is required for both script-src and style-src because all JS and CSS
  // live inline in the HTML. The main CSP value here is blocking external script hosts
  // (only 'self' and cdn.jsdelivr.net allowed) and preventing framing (frame-ancestors).
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' cdn.jsdelivr.net 'unsafe-inline'; " +
    "connect-src 'self' wss:; " +
    "media-src blob:; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; " +
    "frame-ancestors 'none'"
  );
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ── Rate limiting ─────────────────────────────────────────────────────────

// Login: 10 attempts per 15 min per IP (combined with per-account lock above)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
});

// General API: 200 req/min per IP
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests.' },
});

// Session creation: 5 per 60 sec per IP — prevents mass LiveKit token generation
const sessionLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many session requests. Wait a moment.' },
});

app.use('/api/', apiLimiter);
app.use('/auth/', apiLimiter);

// ── Auth middleware ───────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : header;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    // Pin algorithm to prevent alg:none and RS256-confusion attacks
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    if (decoded.role === 'admin') return res.status(403).json({ error: 'Use user token' });
    if (!decoded.sessionId) return res.status(401).json({ error: 'Invalid token format' });

    // Validate session still exists in DB (killed if another device logged in)
    const sess = db.prepare('SELECT id FROM sessions WHERE id = ? AND user_id = ?')
      .get(decoded.sessionId, decoded.userId);
    if (!sess) return res.status(401).json({ error: 'Session expired — please log in again' });

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
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
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

    // Reject excessively long passwords before hitting bcrypt (bcrypt truncates at 72 bytes,
    // and large inputs burn CPU — this caps it safely)
    if (typeof password !== 'string' || password.length > 128)
      return res.status(400).json({ error: 'Invalid credentials' });

    // Per-account lockout check
    const lockMsg = checkLoginLock(username);
    if (lockMsg) return res.status(429).json({ error: lockMsg });

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    // Always run bcrypt to prevent timing-based username enumeration
    const hash  = user ? user.password_hash : DUMMY_HASH;
    const valid = bcrypt.compareSync(password, hash);

    if (!user || !valid) {
      recordLoginFailure(username);
      // Log failed attempt for monitoring
      console.warn(`⛔ Failed login: ${username} | IP: ${req.ip} | UA: ${req.headers['user-agent']}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Success — clear any failure record
    clearLoginFailures(username);

    // One active session per user — kill all previous sessions (logs out other devices)
    const killed = db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id).changes;
    if (killed > 0) console.log(`⚠️  Killed ${killed} existing session(s) for ${user.username}`);

    const sessionId = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (id, user_id, created_at, last_seen) VALUES (?, ?, ?, ?)')
      .run(sessionId, user.id, Date.now(), Date.now());

    const token = jwt.sign(
      { username: user.username, userId: user.id, sessionId },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log(`✅ Login: ${username} | IP: ${req.ip} | UA: ${req.headers['user-agent']}`);
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
    if (typeof newPassword !== 'string' || newPassword.length > 128)
      return res.status(400).json({ error: 'Invalid password' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    if (!user || !bcrypt.compareSync(currentPassword, user.password_hash))
      return res.status(401).json({ error: 'Current password is incorrect' });
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), user.id);
    // Invalidate ALL sessions — force re-login on every device
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
    clearLoginFailures(user.username);
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
  console.log(`✅ Admin login: ${username} | IP: ${req.ip}`);
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
    if (typeof password !== 'string' || password.length > 128 || password.length < 8)
      return res.status(400).json({ error: 'Password must be 8–128 characters' });
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
  if (!password || typeof password !== 'string' || password.length < 8 || password.length > 128)
    return res.status(400).json({ error: 'Password must be 8–128 characters' });
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), req.params.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id);
  clearLoginFailures(user.username);
  console.log(`✅ Admin reset password for: ${user.username}`);
  res.json({ ok: true });
});

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

// POST /api/session — returns LiveKit credentials for browser WebRTC connection
app.post('/api/session', sessionLimiter, requireAuth, async (req, res) => {
  try {
    const { channelId } = req.body;
    if (!channelId || typeof channelId !== 'string' || channelId.length > 200)
      return res.status(400).json({ error: 'channelId required' });

    const allowed = getAllowedChannels(req.user.userId);
    if (allowed !== null && !allowed.includes(channelId)) {
      console.warn(`⛔ ${req.user.username} denied access to channel ${channelId} | IP: ${req.ip}`);
      return res.status(403).json({ error: 'Access denied for this channel' });
    }

    const token = await getSteveToken();
    const { data } = await axios.post(
      `${BASE_URL}/api/session/start`,
      { channel_id: channelId, device_id: DEVICE_ID },
      { headers: { 'Authorization': `Bearer ${token}`, 'x-device-id': DEVICE_ID, 'Content-Type': 'application/json' } }
    );

    console.log(`🎵 ${req.user.username} joined channel ${channelId} | IP: ${req.ip}`);
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
