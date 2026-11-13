require('dotenv').config();
const express      = require('express');
const axios        = require('axios');
const cors         = require('cors');
const path         = require('path');
const Database     = require('better-sqlite3');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');

// ── Env validation ────────────────────────────────────────────────────────
const BASE_URL        = 'https://stevesrodeo.com';
const PORT            = process.env.PORT || 3000;
const DEVICE_ID       = process.env.STEVE_DEVICE_ID;
const STEVE_USERNAME  = process.env.STEVE_USERNAME;
const STEVE_PASSWORD  = process.env.STEVE_PASSWORD;
const JWT_SECRET      = process.env.JWT_SECRET;
const ADMIN_USERNAME  = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD  = process.env.ADMIN_PASSWORD;

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

// Seed family accounts with full_access=1 (they existed before the access system)
const SEED_USERS = [
  { username: 'harshit', password: 'Audio@2026'  },
  { username: 'priya',   password: 'Listen@2026' },
  { username: 'rahul',   password: 'Sports@2026' },
  { username: 'anita',   password: 'Games@2026'  },
  { username: 'vikram',  password: 'Play@2026'   },
];
const insertUser = db.prepare(
  'INSERT OR IGNORE INTO users (username, password_hash, full_access) VALUES (?, ?, 1)'
);
const grantFullAccess = db.prepare('UPDATE users SET full_access = 1 WHERE username = ?');
for (const u of SEED_USERS) {
  insertUser.run(u.username, bcrypt.hashSync(u.password, 10));
  grantFullAccess.run(u.username); // idempotent — upgrades existing rows too
}
console.log('✅ SQLite users ready');

// ── Helpers ───────────────────────────────────────────────────────────────

// Returns the channel IDs a user is allowed to access.
// null means full access (no filtering needed).
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
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : header;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role === 'admin') return res.status(403).json({ error: 'Use user token' });
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

// POST /auth/login  (family users)
app.post('/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user || !bcrypt.compareSync(password, user.password_hash))
      return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ username: user.username, userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    console.log(`✅ Login: ${username}`);
    res.json({ token, username: user.username });
  } catch (err) { console.error('Login error:', err); res.status(500).json({ error: 'Server error' }); }
});

// POST /auth/change-password
app.post('/auth/change-password', requireAuth, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    if (!user || !bcrypt.compareSync(currentPassword, user.password_hash))
      return res.status(401).json({ error: 'Current password is incorrect' });
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), user.id);
    console.log(`✅ Password changed: ${user.username}`);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// POST /admin/login  (admin username + password → admin JWT)
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD)
    return res.status(401).json({ error: 'Invalid admin credentials' });
  const token = jwt.sign({ role: 'admin', username }, JWT_SECRET, { expiresIn: '8h' });
  console.log(`✅ Admin login: ${username}`);
  res.json({ token });
});

// ── Admin routes ──────────────────────────────────────────────────────────

// GET /admin/users  — list all users
app.get('/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, username, full_access FROM users ORDER BY username').all();
  const result = users.map(u => {
    const channelCount = db.prepare('SELECT COUNT(*) as n FROM user_channels WHERE user_id = ?').get(u.id).n;
    return { id: u.id, username: u.username, full_access: !!u.full_access, channel_count: channelCount };
  });
  res.json(result);
});

// POST /admin/users  — create user (no access by default)
app.post('/admin/users', requireAdmin, (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (username, password_hash, full_access) VALUES (?, ?, 0)').run(username, hash);
    console.log(`✅ Admin created user: ${username}`);
    res.json({ ok: true, id: result.lastInsertRowid, username });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /admin/users/:id  — delete user
app.delete('/admin/users/:id', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  console.log(`✅ Admin deleted user: ${user.username}`);
  res.json({ ok: true });
});

// POST /admin/users/:id/reset-password
app.post('/admin/users/:id/reset-password', requireAdmin, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), req.params.id);
  console.log(`✅ Admin reset password for: ${user.username}`);
  res.json({ ok: true });
});

// GET /admin/users/:id/channels  — get user's access config
app.get('/admin/users/:id/channels', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT id, username, full_access FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const channels = db.prepare('SELECT channel_id FROM user_channels WHERE user_id = ?').all(user.id).map(r => r.channel_id);
  res.json({ id: user.id, username: user.username, full_access: !!user.full_access, channels });
});

// PUT /admin/users/:id/channels  — set user's access config
// Body: { full_access: bool, channel_ids: string[] }
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

// GET /admin/channels  — full channel list for admin UI (unfiltered)
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

// GET /api/channels  — filtered by user's access
app.get('/api/channels', requireAuth, async (req, res) => {
  try {
    const token = await getSteveToken();
    const { data } = await axios.get(`${BASE_URL}/api/listener/channels?all=1`, {
      headers: { 'Authorization': `Bearer ${token}`, 'x-device-id': DEVICE_ID }
    });
    const allowed = getAllowedChannels(req.user.userId);
    if (allowed === null) return res.json(data); // full access
    const allowedSet = new Set(allowed);
    res.json(data.filter(ch => allowedSet.has(ch.id)));
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

// POST /api/session — proxy to Steve's Rodeo session/start, return LiveKit credentials
// Browser uses these to connect directly to LiveKit (sub-300ms latency)
app.post('/api/session', requireAuth, async (req, res) => {
  try {
    const { channelId } = req.body;
    if (!channelId) return res.status(400).json({ error: 'channelId required' });

    // Enforce channel access
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
    // data contains { session_id, token (LiveKit JWT), url (LiveKit WS URL) }
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
  console.log(`\n✅ Sports Audio server running at http://localhost:${PORT}\n`);
  getSteveToken().catch(err => console.error("Initial Steve's token fetch failed:", err.message));
});
