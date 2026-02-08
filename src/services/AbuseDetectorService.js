/**
 * Abuse Detection Service
 * Detects abusive words in request body, params, etc.
 * Can be extended with ML or more sophisticated checks
 */
class AbuseDetectorService {
  constructor() {
    // List of abusive words (expand as needed, load from file/DB in prod)
    this.abusiveWords = [
      'abuse', 'hate', 'spam', 'fuck', 'shit', 'asshole', // example, use real list
      // Add more or use external dictionary
    ];
    this.abusivePatterns = [
      /spam+/i,
      /hate/i,
      // regex for patterns
    ];
  }

  /**
   * Check if content contains abusive words
   * @param {string|object} content - text or request body
   * @returns {boolean} true if abusive
   */
  isAbusive(content) {
    if (!content) return false;

    let text = typeof content === 'string' ? content : JSON.stringify(content).toLowerCase();
    text = text.toLowerCase();

    // Check words
    for (const word of this.abusiveWords) {
      if (text.includes(word)) {
        return true;
      }
    }

    // Check patterns
    for (const pattern of this.abusivePatterns) {
      if (pattern.test(text)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Sanitize or flag abusive content
   */
  detectAndFlag(req) {
    const checks = [
      req.body,
      req.params,
      req.query,
      req.headers['x-custom-data'] // etc.
    ];

    for (const check of checks) {
      if (this.isAbusive(check)) {
        return true;
      }
    }
    return false;
  }
}

module.exports = new AbuseDetectorService();
