require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = 'https://stevesrodeo.com';
const DEVICE_ID   = process.env.STEVE_DEVICE_ID;
const STEVE_USERNAME = process.env.STEVE_USERNAME;
const STEVE_PASSWORD = process.env.STEVE_PASSWORD;
const JWT_SECRET  = process.env.JWT_SECRET;
const ADMIN_KEY   = process.env.ADMIN_KEY;

for (const [name, val] of Object.entries({ STEVE_DEVICE_ID: DEVICE_ID, STEVE_USERNAME, STEVE_PASSWORD, JWT_SECRET, ADMIN_KEY })) {
  if (!val) { console.error(`Missing required env var: ${name}`); process.exit(1); }
}

// --- SQLite setup ---
const db = new Database(path.join(__dirname, 'users.db'));
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
)`);

const SEED_USERS = [
  { username: 'harshit', password: 'Audio@2026' },
  { username: 'priya',   password: 'Listen@2026' },
  { username: 'rahul',   password: 'Sports@2026' },
  { username: 'anita',   password: 'Games@2026' },
  { username: 'vikram',  password: 'Play@2026' }
];

const insertUser = db.prepare('INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)');
for (const u of SEED_USERS) {
  insertUser.run(u.username, bcrypt.hashSync(u.password, 10));
}
console.log('✅ SQLite users ready');

// --- Steve's Rodeo shared token ---
let steveToken = null;
let steveTokenExpiry = 0;

async function getSteveToken() {
  if (steveToken && Date.now() < steveTokenExpiry) return steveToken;

  console.log("🔐 Refreshing Steve's Rodeo token...");
  const authRes = await axios.post(
    `${BASE_URL}/pb/api/collections/users/auth-with-password`,
    { identity: STEVE_USERNAME, password: STEVE_PASSWORD },
    { headers: { 'Content-Type': 'application/json' } }
  );
  steveToken = authRes.data.token;

  await axios.post(`${BASE_URL}/api/login-lock`, {}, {
    headers: { 'Authorization': `Bearer ${steveToken}`, 'x-device-id': DEVICE_ID }
  });

  steveTokenExpiry = Date.now() + 23 * 60 * 60 * 1000;
  console.log("✅ Steve's Rodeo token refreshed");
  return steveToken;
}

// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : header;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// --- Family auth routes ---

// POST /auth/login  { username, password }
app.post('/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ username: user.username, userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    console.log(`✅ Login: ${username}`);
    res.json({ token, username: user.username });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /auth/change-password  { currentPassword, newPassword }
app.post('/auth/change-password', requireAuth, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    if (!user || !bcrypt.compareSync(currentPassword, user.password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), user.id);
    console.log(`✅ Password changed: ${user.username}`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /auth/register  { adminKey, username, password }
app.post('/auth/register', (req, res) => {
  try {
    const { adminKey, username, password } = req.body;
    if (adminKey !== ADMIN_KEY) return res.status(403).json({ error: 'Invalid admin key' });
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, bcrypt.hashSync(password, 10));
    console.log(`✅ Registered: ${username}`);
    res.json({ ok: true, username });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Steve's Rodeo proxy routes (require family JWT) ---

// GET /api/channels
app.get('/api/channels', requireAuth, async (req, res) => {
  try {
    const token = await getSteveToken();
    const response = await axios.get(`${BASE_URL}/api/listener/channels?all=1`, {
      headers: { 'Authorization': `Bearer ${token}`, 'x-device-id': DEVICE_ID }
    });
    res.json(response.data);
  } catch (err) {
    console.error('Channels error:', err.response?.status, err.message);
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

// POST /api/session/start  { channel_id }
app.post('/api/session/start', requireAuth, async (req, res) => {
  try {
    const token = await getSteveToken();
    const { channel_id } = req.body;
    console.log(`🎤 ${req.user.username} starting session: ${channel_id}`);
    const response = await axios.post(`${BASE_URL}/api/session/start`,
      { channel_id, device_id: DEVICE_ID },
      { headers: { 'Authorization': `Bearer ${token}`, 'x-device-id': DEVICE_ID, 'Content-Type': 'application/json' } }
    );
    res.json(response.data);
  } catch (err) {
    console.error('Session start error:', err.response?.status, err.response?.data);
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

// POST /api/session/heartbeat  { session_id }
app.post('/api/session/heartbeat', requireAuth, async (req, res) => {
  try {
    const token = await getSteveToken();
    const { session_id } = req.body;
    await axios.post(`${BASE_URL}/api/session/heartbeat`,
      { session_id },
      { headers: { 'Authorization': `Bearer ${token}`, 'x-device-id': DEVICE_ID, 'Content-Type': 'application/json' } }
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

// POST /api/session/end  { session_id }
app.post('/api/session/end', requireAuth, async (req, res) => {
  try {
    const token = await getSteveToken();
    const { session_id } = req.body;
    await axios.post(`${BASE_URL}/api/session/end`,
      { session_id },
      { headers: { 'Authorization': `Bearer ${token}`, 'x-device-id': DEVICE_ID, 'Content-Type': 'application/json' } }
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n✅ Sports Audio server running at http://localhost:${PORT}\n`);
  getSteveToken().catch(err => console.error("Initial Steve's token fetch failed:", err.message));
});
