/**
 * In-memory Rate Limiter Service
 * Simulates Redis (fixed window) using JS Map; supports IP + endpoint keys
 * For production, replace with Redis incr/expire
 */
const fs = require('fs');
const path = require('path');

class RateLimiterService {
  constructor() {
    this.requests = new Map();
    // Dynamic rules: endpoint -> {maxRequests, windowMs}
    this.rules = new Map();
    this.maxRequests = parseInt(process.env.RATE_LIMIT_MAX) || 100;
    this.windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;
    this.loadRules();
  }

  // Generate Redis-like key for IP-based + optional endpoint
  getKey(ip, endpoint = 'global') {
    return `${ip}:${endpoint}`;
  }

  // Load dynamic rules from FS (persistent)
  loadRules() {
    const rulesFile = path.join(process.env.DATA_DIR || './data', 'rate-rules.json');
    try {
      if (fs.existsSync(rulesFile)) {
        const data = JSON.parse(fs.readFileSync(rulesFile, 'utf8'));
        this.rules = new Map(Object.entries(data));
      }
    } catch (err) {
      this.rules = new Map();
    }
  }

  saveRules() {
    const rulesFile = path.join(process.env.DATA_DIR || './data', 'rate-rules.json');
    const data = Object.fromEntries(this.rules);
    fs.writeFileSync(rulesFile, JSON.stringify(data, null, 2));
  }

  // Set/update rule for endpoint (admin use)
  setRule(endpoint, maxRequests, windowMs) {
    this.rules.set(endpoint, { maxRequests, windowMs });
    this.saveRules();
  }

  // Get rule for endpoint (fallback to defaults)
  getRule(endpoint) {
    return this.rules.get(endpoint) || { maxRequests: this.maxRequests, windowMs: this.windowMs };
  }

  isAllowed(ip, endpoint = 'global') {
    const now = Date.now();
    const key = this.getKey(ip, endpoint);
    const rule = this.getRule(endpoint);
    const record = this.requests.get(key);

    if (!record) {
      this.requests.set(key, { count: 1, resetTime: now + rule.windowMs });
      return true;
    }

    if (now > record.resetTime) {
      this.requests.set(key, { count: 1, resetTime: now + rule.windowMs });
      return true;
    }

    if (record.count < rule.maxRequests) {
      record.count++;
      return true;
    }

    return false;
  }

  getRemaining(ip, endpoint = 'global') {
    const key = this.getKey(ip, endpoint);
    const record = this.requests.get(key);
    const rule = this.getRule(endpoint);
    if (!record || Date.now() > record.resetTime) {
      return rule.maxRequests;
    }
    return Math.max(0, rule.maxRequests - record.count);
  }

  cleanup() {
    const now = Date.now();
    for (const [key, record] of this.requests.entries()) {
      if (now > record.resetTime) {
        this.requests.delete(key);
      }
    }
  }
}

module.exports = new RateLimiterService();
