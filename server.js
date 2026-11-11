const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3002;
const BASE_URL = 'https://stevesrodeo.com';
const DEVICE_ID = '59e04898-b483-48c7-95e8-0eaabd9fe9ee';

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Step 1: Login
app.post('/api/login', async (req, res) => {
  try {
    const { identity, password } = req.body;
    console.log('🔐 Logging in:', identity);

    const authRes = await axios.post(`${BASE_URL}/pb/api/collections/users/auth-with-password`, {
      identity, password
    }, { headers: { 'Content-Type': 'application/json' } });

    const token = authRes.data.token;
    const userId = authRes.data.record.id;

    // Lock to device
    await axios.post(`${BASE_URL}/api/login-lock`, {}, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'x-device-id': DEVICE_ID
      }
    });

    console.log('✅ Login success, user:', userId);
    res.json({ token, userId, deviceId: DEVICE_ID });

  } catch (error) {
    console.error('❌ Login error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ error: error.message });
  }
});

// Step 2: Get all channels
app.get('/api/channels', async (req, res) => {
  try {
    const token = req.headers['authorization'];
    console.log('📺 Fetching all channels...');

    const response = await axios.get(`${BASE_URL}/api/listener/channels?all=1`, {
      headers: {
        'Authorization': token,
        'x-device-id': DEVICE_ID
      }
    });

    console.log(`✅ Got ${response.data.length} channels`);
    res.json(response.data);
  } catch (error) {
    console.error('❌ Channels error:', error.response?.status);
    res.status(error.response?.status || 500).json({ error: error.message });
  }
});

// Step 3: Start session and get LiveKit token
app.post('/api/session/start', async (req, res) => {
  try {
    const token = req.headers['authorization'];
    const { channel_id } = req.body;

    console.log(`🎤 Starting session for channel: ${channel_id}`);

    const response = await axios.post(`${BASE_URL}/api/session/start`, {
      channel_id,
      device_id: DEVICE_ID
    }, {
      headers: {
        'Authorization': token,
        'x-device-id': DEVICE_ID,
        'Content-Type': 'application/json'
      }
    });

    console.log(`✅ Session started: ${response.data.session_id}`);
    res.json(response.data);
  } catch (error) {
    console.error('❌ Session error:', error.response?.status, error.response?.data);
    res.status(error.response?.status || 500).json({ error: error.message });
  }
});

// Step 4: Heartbeat (keep session alive)
app.post('/api/session/heartbeat', async (req, res) => {
  try {
    const token = req.headers['authorization'];
    const { session_id } = req.body;

    await axios.post(`${BASE_URL}/api/session/heartbeat`, { session_id }, {
      headers: {
        'Authorization': token,
        'x-device-id': DEVICE_ID,
        'Content-Type': 'application/json'
      }
    });

    res.json({ ok: true });
  } catch (error) {
    res.status(error.response?.status || 500).json({ error: error.message });
  }
});

// Step 5: End session
app.post('/api/session/end', async (req, res) => {
  try {
    const token = req.headers['authorization'];
    const { session_id } = req.body;

    await axios.post(`${BASE_URL}/api/session/end`, { session_id }, {
      headers: {
        'Authorization': token,
        'x-device-id': DEVICE_ID,
        'Content-Type': 'application/json'
      }
    });

    res.json({ ok: true });
  } catch (error) {
    res.status(error.response?.status || 500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n✅ Steve's Rodeo proxy running at http://localhost:${PORT}\n`);
});
