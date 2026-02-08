const fs = require('fs');
const path = require('path');

/**
 * Suspicious Activity Service
 * Tracks failures, spikes, patterns (in-memory + FS persist)
 * Flags on detection (no handling impl)
 */
class SuspiciousActivityService {
  constructor() {
    this.failures = new Map(); // ip/user -> count (now persisted)
    this.requests = new Map(); // ip -> timestamp array for spikes
    this.suspiciousFlags = new Map(); // ip/user -> true
    this.blocked = new Map(); // ip/user -> block info
    this.thresholds = {
      maxFailures: 5, // repeated fails
      spikeThreshold: 20, // reqs in 10s
      spikeWindowMs: 10000,
      patternIntervalMs: 100 // rapid fire
    };
    this.dataFile = path.join(process.env.DATA_DIR || './data', 'suspicious.json');
    this.blockFile = path.join(process.env.DATA_DIR || './data', 'blocked.json');
    this.failuresFile = path.join(process.env.DATA_DIR || './data', 'failures.json');
    this.loadFlags();
    this.loadBlocks();
    this.loadFailures();
  }

  // Normalize localhost IPs (::1 -> 127.0.0.1)
  normalizeIP(ip) {
    return ip === '::1' || ip === '::ffff:127.0.0.1' ? '127.0.0.1' : ip;
  }

  loadFlags() {
    try {
      if (fs.existsSync(this.dataFile)) {
        const data = JSON.parse(fs.readFileSync(this.dataFile, 'utf8'));
        this.suspiciousFlags = new Map(Object.entries(data));
      }
    } catch (err) {
      // Ignore load errors, use empty
    }
  }

  saveFlags() {
    const data = Object.fromEntries(this.suspiciousFlags);
    fs.writeFileSync(this.dataFile, JSON.stringify(data, null, 2));
  }

  loadBlocks() {
    try {
      if (fs.existsSync(this.blockFile)) {
        const data = JSON.parse(fs.readFileSync(this.blockFile, 'utf8'));
        this.blocked = new Map(Object.entries(data));
      }
    } catch (err) {
      this.blocked = new Map();
    }
  }

  saveBlocks() {
    try {
      const data = Object.fromEntries(this.blocked);
      fs.writeFileSync(this.blockFile, JSON.stringify(data, null, 2));
    } catch (err) {
      console.error('saveBlocks failed:', err.message);
    }
  }

  loadFailures() {
    try {
      if (fs.existsSync(this.failuresFile)) {
        const data = JSON.parse(fs.readFileSync(this.failuresFile, 'utf8'));
        this.failures = new Map(Object.entries(data));
      }
    } catch (err) {
      this.failures = new Map();
    }
  }

  saveFailures() {
    try {
      const data = Object.fromEntries(this.failures);
      fs.writeFileSync(this.failuresFile, JSON.stringify(data, null, 2));
    } catch (err) {
      console.error('saveFailures failed:', err.message);
    }
  }

  // Track failed request (401/403/429 etc)
  trackFailure(ip, userId = null) {
    const normIp = this.normalizeIP(ip);
    const key = userId || normIp;
    const count = (this.failures.get(key) || 0) + 1;
    this.failures.set(key, count);
    this.saveFailures(); // Persist to survive restarts
    if (count >= this.thresholds.maxFailures) {
      this.flag(key, 'repeated_failures');
    }
  }

  // Track request for spikes/patterns
  trackRequest(ip) {
    const normIp = this.normalizeIP(ip);
    const now = Date.now();
    let times = this.requests.get(normIp) || [];
    times = times.filter(t => now - t < this.thresholds.spikeWindowMs);
    times.push(now);
    this.requests.set(normIp, times);
    if (times.length >= this.thresholds.spikeThreshold) {
      this.flag(normIp, 'traffic_spike');
    }
    // Check abnormal pattern (e.g. too rapid)
    if (times.length > 3 && (times[times.length-1] - times[times.length-3] < this.thresholds.patternIntervalMs * 3)) {
      this.flag(normIp, 'abnormal_pattern');
    }
  }

  flag(key, reason) {
    if (!this.suspiciousFlags.has(key)) {
      this.suspiciousFlags.set(key, { flagged: true, reason, timestamp: new Date().toISOString() });
      this.saveFlags();
      // Block on flag (abuse/suspicious)
      this.block(key, reason);
    }
  }

  // Block user/IP
  block(key, reason) {
    this.blocked.set(key, { blocked: true, reason, timestamp: new Date().toISOString() });
    this.saveBlocks();
  }

  // Unblock (admin only)
  unblock(key) {
    if (this.blocked.has(key)) {
      this.blocked.delete(key);
      this.saveBlocks();
      return true;
    }
    return false;
  }

  isBlocked(ip, userId = null) {
    const normIp = this.normalizeIP(ip);
    const key = userId || normIp;
    return this.blocked.has(key);
  }

  getBlockInfo(key) {
    return this.blocked.get(key) || null;
  }

  isFlagged(ip, userId = null) {
    const normIp = this.normalizeIP(ip);
    const key = userId || normIp;
    return this.suspiciousFlags.has(key);
  }

  getFlagInfo(key) {
    return this.suspiciousFlags.get(key) || null;
  }
}

module.exports = new SuspiciousActivityService();
