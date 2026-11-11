'use strict';

const { Room, RoomEvent, AudioStream } = require('@livekit/rtc-node');
const axios = require('axios');

const GRACE_MS      = 60_000;   // leave empty room after 60s with no listeners
const WATCHDOG_MS   = 45_000;   // reconnect if no audio frames for 45s (covers halftime / timeouts)
const PING_MS       = 30_000;   // server→client ping to keep proxy connections alive
const MAX_BACKOFF   = 30_000;   // cap reconnect delay at 30s
const SAMPLE_RATE   = 48_000;
const WS_OPEN       = 1;        // WebSocket.OPEN

class RelayManager {
  /**
   * @param {object} opts
   * @param {function():Promise<string>} opts.getSteveToken  - returns current aidan Bearer token
   * @param {string}  opts.deviceId
   * @param {string}  opts.baseUrl   - 'https://stevesrodeo.com'
   */
  constructor({ getSteveToken, deviceId, baseUrl }) {
    this.getSteveToken = getSteveToken;
    this.deviceId      = deviceId;
    this.baseUrl       = baseUrl;
    this.channels      = new Map(); // channelId -> ChannelState
  }

  // ── Public API ─────────────────────────────────────────────────────────

  async addListener(channelId, ws) {
    if (!this.channels.has(channelId)) {
      this._init(channelId);
      this._connect(channelId); // fire-and-forget
    }
    const ch = this.channels.get(channelId);

    // Cancel grace-period if running (someone rejoined before the timeout)
    if (ch.gracePeriodTimer) {
      clearTimeout(ch.gracePeriodTimer);
      ch.gracePeriodTimer = null;
    }

    ch.listeners.add(ws);
    ws.on('close', () => this._onListenerClose(channelId, ws));
    ws.on('error', () => this._onListenerClose(channelId, ws));

    // Per-listener ping to keep nginx/proxy connections alive when no audio is flowing
    const ping = setInterval(() => {
      if (ws.readyState === WS_OPEN) {
        try { ws.ping(); } catch {}
      } else {
        clearInterval(ping);
      }
    }, PING_MS);
    ws._pingTimer = ping;
  }

  async shutdown() {
    const ids = [...this.channels.keys()];
    await Promise.allSettled(ids.map(id => this._leave(id)));
  }

  // ── Internal ───────────────────────────────────────────────────────────

  _init(channelId) {
    this.channels.set(channelId, {
      channelId,
      room:              null,
      sessionId:         null,
      listeners:         new Set(),
      gracePeriodTimer:  null,
      watchdogTimer:     null,
      heartbeatTimer:    null,
      pingTimer:         null,
      lastFrameAt:       null,   // null until first frame arrives; watchdog ignores null
      relayRunning:      false,  // guard against double-relay on resubscribe
      reconnectAttempts: 0,
      leaving:           false,
      connecting:        false,
    });
  }

  _onListenerClose(channelId, ws) {
    if (ws._pingTimer) { clearInterval(ws._pingTimer); ws._pingTimer = null; }
    const ch = this.channels.get(channelId);
    if (!ch) return;
    ch.listeners.delete(ws);
    if (ch.listeners.size === 0 && !ch.gracePeriodTimer && !ch.leaving) {
      ch.gracePeriodTimer = setTimeout(() => this._leave(channelId), GRACE_MS);
    }
  }

  async _connect(channelId) {
    const ch = this.channels.get(channelId);
    if (!ch || ch.leaving || ch.connecting) return;
    ch.connecting = true;

    try {
      const steveToken = await this.getSteveToken();

      const { data } = await axios.post(
        `${this.baseUrl}/api/session/start`,
        { channel_id: channelId, device_id: this.deviceId },
        { headers: { 'Authorization': `Bearer ${steveToken}`, 'x-device-id': this.deviceId, 'Content-Type': 'application/json' } }
      );

      if (ch.leaving) return;
      ch.sessionId = data.session_id;

      const room = new Room();
      ch.room = room;

      room.on(RoomEvent.TrackSubscribed, (track) => {
        // kind 1 = audio in rtc-node's numeric enum
        if (track.kind !== 1) return;
        console.log(`🎵 Audio subscribed: ${channelId}`);
        this._startRelay(ch, track);
      });

      room.on(RoomEvent.TrackUnsubscribed, () => {
        // Caller went offline — audio stream ends naturally, browsers get silence
        console.log(`🔇 Track unsubscribed: ${channelId}`);
        this._broadcast(ch, JSON.stringify({ type: 'offline' }), false);
      });

      room.on(RoomEvent.Reconnecting, () => {
        console.log(`🔄 LiveKit reconnecting: ${channelId}`);
        this._broadcast(ch, JSON.stringify({ type: 'reconnecting' }), false);
      });

      room.on(RoomEvent.Reconnected, () => {
        console.log(`✅ LiveKit reconnected: ${channelId}`);
        ch.reconnectAttempts = 0;
        this._broadcast(ch, JSON.stringify({ type: 'connected' }), false);
      });

      room.on(RoomEvent.Disconnected, () => {
        if (!ch.leaving) {
          console.log(`❌ LiveKit disconnected: ${channelId}`);
          this._scheduleReconnect(ch);
        }
      });

      await room.connect(data.url, data.token, { autoSubscribe: true, dynacast: false });

      ch.reconnectAttempts = 0;
      ch.connecting = false;
      this._broadcast(ch, JSON.stringify({ type: 'connected' }), false);
      console.log(`✅ Server joined channel ${channelId}`);

      // Heartbeat — keep Steve's Rodeo session alive
      ch.heartbeatTimer = setInterval(async () => {
        if (!ch.sessionId) return;
        try {
          const st = await this.getSteveToken();
          await axios.post(`${this.baseUrl}/api/session/heartbeat`,
            { session_id: ch.sessionId },
            { headers: { 'Authorization': `Bearer ${st}`, 'x-device-id': this.deviceId, 'Content-Type': 'application/json' } }
          );
        } catch {}
      }, 20_000);

      // Watchdog — detect zombie connection (connected but no audio frames)
      // Only fires after the first frame has arrived; ignores natural broadcast silences
      ch.watchdogTimer = setInterval(() => {
        if (ch.leaving || ch.listeners.size === 0 || ch.lastFrameAt === null) return;
        const age = Date.now() - ch.lastFrameAt;
        if (age > WATCHDOG_MS) {
          console.warn(`🐕 Watchdog: no frames for ${age}ms on ${channelId}`);
          try { ch.room?.disconnect(); } catch {}
        }
      }, WATCHDOG_MS);

    } catch (err) {
      console.error(`❌ Connect error for ${channelId}:`, err.message);
      const ch = this.channels.get(channelId);
      if (ch) ch.connecting = false;
      this._scheduleReconnect(this.channels.get(channelId));
    }
  }

  _startRelay(ch, track) {
    // Guard: if a relay loop is already running (e.g. track resubscribed during reconnect),
    // skip starting a second one to avoid double-broadcast
    if (ch.relayRunning) {
      console.log(`⚠️  Relay already running for ${ch.channelId}, skipping duplicate`);
      return;
    }
    ch.relayRunning = true;

    const stream = new AudioStream(track, { sampleRate: SAMPLE_RATE, numChannels: 1 });
    (async () => {
      try {
        for await (const frame of stream) {
          if (ch.leaving) break;
          ch.lastFrameAt = Date.now(); // clock starts on first real frame
          if (ch.listeners.size === 0) continue;

          // frame.data is Int16Array — send as binary to all browser WebSockets
          this._broadcast(ch, frame.data, true);
        }
      } catch (e) {
        if (!ch.leaving) console.error(`Audio stream error on ${ch.channelId}:`, e.message);
      } finally {
        ch.relayRunning = false;
      }
    })();
  }

  _broadcast(ch, data, binary) {
    ch.listeners.forEach(ws => {
      if (ws.readyState === WS_OPEN) {
        try { ws.send(data, { binary }); } catch {}
      }
    });
  }

  _scheduleReconnect(ch) {
    if (!ch || ch.leaving) return;
    this._teardownRoom(ch);

    const delay = Math.min(1000 * (2 ** ch.reconnectAttempts), MAX_BACKOFF);
    ch.reconnectAttempts++;
    this._broadcast(ch, JSON.stringify({ type: 'reconnecting', retryIn: delay }), false);
    console.log(`🔄 Reconnect ${ch.channelId} in ${delay}ms (attempt ${ch.reconnectAttempts})`);

    setTimeout(() => {
      if (!ch.leaving && this.channels.has(ch.channelId)) {
        this._connect(ch.channelId);
      }
    }, delay);
  }

  _teardownRoom(ch) {
    if (ch.heartbeatTimer) { clearInterval(ch.heartbeatTimer); ch.heartbeatTimer = null; }
    if (ch.watchdogTimer)  { clearInterval(ch.watchdogTimer);  ch.watchdogTimer  = null; }
    if (ch.room) {
      try { ch.room.disconnect(); } catch {}
      ch.room = null;
    }
    ch.connecting   = false;
    ch.relayRunning = false; // allow new relay loop on reconnect
    ch.lastFrameAt  = null;  // reset watchdog clock; starts again on first frame after reconnect
  }

  async _leave(channelId) {
    const ch = this.channels.get(channelId);
    if (!ch) return;
    ch.leaving = true;
    this.channels.delete(channelId);

    this._teardownRoom(ch);
    if (ch.gracePeriodTimer) { clearTimeout(ch.gracePeriodTimer); }

    // End session with Steve's Rodeo
    if (ch.sessionId) {
      try {
        const st = await this.getSteveToken();
        await axios.post(`${this.baseUrl}/api/session/end`,
          { session_id: ch.sessionId },
          { headers: { 'Authorization': `Bearer ${st}`, 'x-device-id': this.deviceId, 'Content-Type': 'application/json' } }
        );
      } catch {}
    }

    console.log(`🚪 Left channel ${channelId}`);
  }
}

module.exports = RelayManager;
