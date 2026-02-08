const abuseDetector = require('../services/AbuseDetectorService');
const loggerService = require('../services/LoggerService');

/**
 * Middleware to detect abusive content in requests
 */
const abuseDetectorMiddleware = (req, res, next) => {
  if (abuseDetector.detectAndFlag(req)) {
    loggerService.logError(new Error('Abusive content detected'), req);
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Abusive content detected. Request blocked.'
    });
  }
  next();
};

module.exports = abuseDetectorMiddleware;
