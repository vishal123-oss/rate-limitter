const suspiciousService = require('../services/SuspiciousActivityService');

/**
 * Suspicious Activity Middleware
 * Detects failures/spikes/patterns, flags (marks) user/IP
 * Does not handle flagged (just marks)
 */
const suspiciousActivity = (req, res, next) => {
  let ip = req.ip || req.connection.remoteAddress;
  ip = suspiciousService.normalizeIP ? suspiciousService.normalizeIP(ip) : ip;
  const userId = req.user ? req.user.id : null;

  // Track every request for spikes/patterns
  suspiciousService.trackRequest(ip);

  // Track failures on error status
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    if (res.statusCode >= 400) { // 4xx/5xx as failure
      suspiciousService.trackFailure(ip, userId);
    }
    if (suspiciousService.isFlagged(ip, userId)) {
      // Just mark (e.g. in req for later use)
      req.isSuspicious = true;
      req.suspiciousReason = suspiciousService.getFlagInfo(ip || userId).reason;
    }
    originalEnd.call(this, chunk, encoding);
  };

  next();
};

module.exports = suspiciousActivity;
