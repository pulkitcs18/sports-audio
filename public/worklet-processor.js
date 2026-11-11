/**
 * PCM audio player AudioWorklet processor.
 * Receives Int16 PCM frames from the main thread via port.postMessage,
 * writes them into a ring buffer, and outputs Float32 audio on demand.
 *
 * Sample rate: 48000 Hz, mono.
 * Ring buffer: 1 second (48000 samples).
 * Prebuffer: ~60ms (2880 samples) before starting playback to absorb jitter.
 */

const CAPACITY  = 48000;      // 1s ring buffer
const PREBUFFER = 2880;       // 60ms @ 48kHz — wait this long before playing

class PCMPlayerProcessor extends AudioWorkletProcessor {
  constructor() {
    super();

    this._buf    = new Float32Array(CAPACITY);
    this._rp     = 0;       // read pointer
    this._wp     = 0;       // write pointer
    this._fill   = 0;       // samples available to read
    this._active = false;   // true once prebuffer is satisfied

    this.port.onmessage = ({ data }) => {
      // data is an ArrayBuffer (transferred zero-copy from main thread)
      const s16 = new Int16Array(data);
      for (let i = 0; i < s16.length; i++) {
        if (this._fill >= CAPACITY) {
          // Ring full — drop oldest sample to make room (keeps latency bounded)
          this._rp = (this._rp + 1) % CAPACITY;
          this._fill--;
        }
        this._buf[this._wp] = s16[i] / 32768.0;
        this._wp = (this._wp + 1) % CAPACITY;
        this._fill++;
      }
      // Start playing once we have enough buffered
      if (!this._active && this._fill >= PREBUFFER) {
        this._active = true;
      }
    };
  }

  process(inputs, outputs) {
    const out = outputs[0][0]; // mono channel, 128 samples per quantum
    if (!this._active) {
      out.fill(0);
      return true;
    }
    for (let i = 0; i < out.length; i++) {
      if (this._fill > 0) {
        out[i]  = this._buf[this._rp];
        this._rp = (this._rp + 1) % CAPACITY;
        this._fill--;
      } else {
        // Underrun — output silence and reset prebuffer gate
        out[i]       = 0;
        this._active = false;
      }
    }
    return true;
  }
}

registerProcessor('pcm-player', PCMPlayerProcessor);
