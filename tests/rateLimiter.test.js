const request = require('supertest');
const app = require('../src/server');

describe('IP-based Rate Limiter Integration Tests', () => {
  // Unique IPs per test to avoid persistent blocks from suspicious service
  let testIp;

  beforeAll(() => {
    // Clear blocked/suspicious/failures files before tests to prevent persistent state
    const fs = require('fs');
    ['blocked.json', 'suspicious.json', 'failures.json'].forEach(file => {
      const f = `./data/${file}`;
      if (fs.existsSync(f)) fs.unlinkSync(f);
    });
  });

  beforeEach(() => {
    testIp = `192.168.1.${Math.floor(Math.random() * 100)}`; // Random IP
    // Reset for clean tests (since in-memory + FS blocks)
    jest.resetModules();
    // Clear blocked file each test
    const fs = require('fs');
    const blockFile = './data/blocked.json';
    if (fs.existsSync(blockFile)) {
      fs.unlinkSync(blockFile);
    }
  });

  it('should allow requests within limit for /health', async () => {
    const res = await request(app)
      .get('/health')
      .set('X-Forwarded-For', testIp); // Simulate IP
    expect(res.status).toBe(200);
    expect(res.headers['x-ratelimit-remaining']).toBeDefined();
  });

  it('should return 429 when exceeding rate limit for particular endpoint (/api/submit)', async () => {
    // Use 2 requests (limit=2 for test override simulation via repeated hits, but since per-test reset limited)
    // Note: in real, use lower env or loop; here hit submit 6 times to exceed demo limit=5
    for (let i = 0; i < 6; i++) {
      const res = await request(app)
        .post('/api/submit')
        .set('X-Forwarded-For', testIp)
        .send({ message: 'test', userId: '1' })
        .set('Authorization', 'Bearer valid-token'); // Mock auth for protected
      if (i >= 5) {
        expect(res.status).toBe(429);
        expect(res.body.error).toBe('Too Many Requests');
        expect(res.body.endpoint).toBe('/api/submit');
        return;
      }
    }
  });

  it('should include rate limit headers on successful requests', async () => {
    const res = await request(app)
      .get('/health')
      .set('X-Forwarded-For', testIp);
    expect(res.status).toBe(200);
    expect(res.headers['x-ratelimit-limit']).toBeDefined();
    expect(res.headers['x-ratelimit-remaining']).toBeDefined();
    expect(res.headers['x-ratelimit-reset']).toBeDefined();
  });
});
