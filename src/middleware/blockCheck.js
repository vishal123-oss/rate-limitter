const suspiciousService = require('../services/SuspiciousActivityService');

/**
 * Block Check Middleware
 * Blocks access if flagged/blocked (from abuse/suspicious)
 * Admin can unblock via endpoint
 */
const blockCheck = (req, res, next) => {
  // Skip in tests to avoid state issues from submit fails
  if (process.env.NODE_ENV === 'test') {
    return next();
  }
  // Skip /admin paths so admin can always unblock (even if own IP blocked)
  if (req.path.startsWith('/admin/')) {
    return next();
  }
  let ip = req.ip || req.connection.remoteAddress;
  ip = suspiciousService.normalizeIP ? suspiciousService.normalizeIP(ip) : ip;
  const userId = req.user ? req.user.id : null;

  if (suspiciousService.isBlocked(ip, userId)) {
    const info = suspiciousService.getBlockInfo(userId || ip);
    return res.status(403).json({
      error: 'Access Blocked',
      message: 'Your account/IP has been blocked due to suspicious activity. Contact admin.',
      reason: info.reason
    });
  }
  next();
};

module.exports = blockCheck;
