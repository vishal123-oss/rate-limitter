const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');

// Load environment variables FIRST
dotenv.config();

// Create necessary directories for file system storage BEFORE requiring services
const logsDir = process.env.LOGS_DIR || './logs';
const dataDir = process.env.DATA_DIR || './data';

[logsDir, dataDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Now import other modules and services
const express = require('express');
const helmet = require('helmet');
const bodyParser = require('body-parser');

// Import services and middlewares (now dirs exist and env loaded)
const loggerService = require('./services/LoggerService');
const rateLimiter = require('./middleware/rateLimiter');
const abuseDetector = require('./middleware/abuseDetector');
const suspiciousActivity = require('./middleware/suspiciousActivity');
const blockCheck = require('./middleware/blockCheck');
const { authenticate, authorize } = require('./middleware/auth');
const authRoutes = require('./routes/auth');
const rateLimiterService = require('./services/RateLimiterService');
const suspiciousService = require('./services/SuspiciousActivityService');

const app = express();
const PORT = process.env.PORT || 3000;

// Init demo dynamic rule for /api/submit (5 req / 10s window)
rateLimiterService.setRule('/api/submit', 5, 10000);

// Security middleware - Helmet
app.use(helmet());

// Body parser middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Emergency unblock endpoint (before blockCheck, no auth, uses secret for localhost blocked cases)
app.post('/emergency-unblock', (req, res) => {
  const { secret, key } = req.body;
  const expectedSecret = process.env.UNBLOCK_SECRET || 'abbbbbbbbbbbbbb';
  if (secret !== expectedSecret || !key) {
    return res.status(403).json({ error: 'Invalid secret or key' });
  }
  const wasBlocked = suspiciousService.unblock(key);
  res.json({ message: `Emergency unblock for ${key} (was blocked: ${wasBlocked})` });
});

// Request logging middleware with response time (early)
app.use((req, res, next) => {
  const start = Date.now();
  const originalEnd = res.end;

  res.end = function(chunk, encoding) {
    const responseTime = Date.now() - start;
    loggerService.logRequest(req, res, responseTime);
    originalEnd.call(this, chunk, encoding);
  };

  next();
});

// Global rate limiting (IP-based, all routes)
app.use(rateLimiter);

// Abuse detection middleware (apply after body parse)
app.use(abuseDetector);

// Suspicious activity detection (tracks repeated failures, spikes, patterns; just marks/flags)
app.use(suspiciousActivity);

// Block check (blocks flagged/suspicious users/IPs from any service - including auth)
app.use(blockCheck);

// Public auth routes (after block check to enforce blocks on login too)
app.use('/auth', authRoutes);

// Public health check (inherits global rate limit)
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    rateLimit: {
      max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000
    }
  });
});

// Protected routes requiring auth (dynamic rate limit via detected path)
app.post('/api/submit', authenticate, (req, res) => {
  const { message, userId } = req.body;
  res.status(200).json({
    success: true,
    message: 'Data received and logged',
    data: { message, userId },
    user: req.user,
    timestamp: new Date().toISOString()
  });
});

app.get('/logs/:type', authenticate, authorize(['admin']), (req, res) => {
  const { type } = req.params;
  const logs = loggerService.getLogs(type);
  res.json({ logs, count: logs.length });
});

// Admin endpoint to dynamically set/update rate limit rules per endpoint (admin only)
app.post('/admin/rate-limits', authenticate, authorize(['admin']), (req, res) => {
  const { endpoint, maxRequests, windowMs } = req.body;
  if (!endpoint || !maxRequests || !windowMs) {
    return res.status(400).json({ error: 'endpoint, maxRequests, windowMs required' });
  }
  rateLimiterService.setRule(endpoint, parseInt(maxRequests), parseInt(windowMs));
  res.json({ message: `Rate limit rule set for ${endpoint}`, rule: { maxRequests, windowMs } });
});

// Admin endpoint to unblock user/IP (admin only)
app.delete('/admin/blocked/:key', authenticate, authorize(['admin']), (req, res) => {
  const { key } = req.params;
  const wasBlocked = suspiciousService.unblock(key);
  res.json({ message: `Unblocked ${key} (was blocked: ${wasBlocked})` });
});

// Error handling middleware
app.use((err, req, res, next) => {
  loggerService.logError(err, req);
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong!'
  });
});

// Export app for testing/integration (listen only if not test)
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
    console.log(`📁 Logs directory: ${logsDir}`);
    console.log(`📁 Data directory: ${dataDir}`);
    console.log(`🔒 Rate limiting enabled with in-memory Map (Redis simulation)`);
    console.log(`🛡️  Helmet, Body Parser, Abuse Detection configured`);
  });
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

module.exports = app;
