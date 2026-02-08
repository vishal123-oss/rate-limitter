const rateLimiterService = require('../services/RateLimiterService');

/**
 * Rate Limiting Middleware (IP-based, fixed window, Redis sim)
 * Dynamically detects endpoint (req.path) and applies rules from service
 * Returns 429 on exceed
 */
const rateLimiter = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  // Dynamic endpoint detection for rule application
  const endpoint = req.path || req.originalUrl || 'global';
  
  if (!rateLimiterService.isAllowed(ip, endpoint)) {
    return res.status(429).json({
      error: 'Too Many Requests',
      message: 'Rate limit exceeded for this endpoint. Please try again later.',
      endpoint,
      remaining: 0
    });
  }

  const remaining = rateLimiterService.getRemaining(ip, endpoint);
  const rule = rateLimiterService.getRule(endpoint);
  res.set('X-RateLimit-Limit', rule.maxRequests);
  res.set('X-RateLimit-Remaining', remaining);
  res.set('X-RateLimit-Reset', Math.ceil((Date.now() + rule.windowMs) / 1000));

  next();
};

module.exports = rateLimiter;
