const fs = require('fs');
const path = require('path');

/**
 * Logger Service using File System for storage
 * Can be extended to use Redis or database later
 */
class LoggerService {
  constructor() {
    this.logsDir = process.env.LOGS_DIR || './logs';
    this.accessLogPath = path.join(this.logsDir, 'access.log');
    this.errorLogPath = path.join(this.logsDir, 'error.log');
    this.ensureLogFiles();
  }

  ensureLogFiles() {
    [this.accessLogPath, this.errorLogPath].forEach(file => {
      if (!fs.existsSync(file)) {
        fs.writeFileSync(file, '');
      }
    });
  }

  /**
   * Log request traffic
   */
  logRequest(req, res, responseTime = 0) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      method: req.method,
      url: req.url,
      ip: req.ip || req.connection.remoteAddress,
      status: res.statusCode,
      userAgent: req.get('user-agent') || 'N/A',
      responseTime,
      headers: req.headers // optional, can filter sensitive
    };

    const logLine = JSON.stringify(logEntry) + '\n';
    
    // Append to access log
    fs.appendFile(this.accessLogPath, logLine, (err) => {
      if (err) console.error('Failed to write access log:', err);
    });
    
    // Also console log for dev
    console.log(`[${timestamp}] ${req.method} ${req.url} ${res.statusCode} ${responseTime}ms`);
  }

  /**
   * Log errors
   */
  logError(error, req = null) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level: 'ERROR',
      message: error.message,
      stack: error.stack,
      ...(req && {
        method: req.method,
        url: req.url,
        ip: req.ip || req.connection.remoteAddress
      })
    };

    const logLine = JSON.stringify(logEntry) + '\n';
    
    fs.appendFile(this.errorLogPath, logLine, (err) => {
      if (err) console.error('Failed to write error log:', err);
    });
  }

  /**
   * Get logs (for admin or monitoring)
   */
  getLogs(type = 'access', limit = 100) {
    const filePath = type === 'error' ? this.errorLogPath : this.accessLogPath;
    try {
      const logs = fs.readFileSync(filePath, 'utf8')
        .split('\n')
        .filter(line => line.trim())
        .slice(-limit)
        .map(line => JSON.parse(line));
      return logs.reverse(); // newest first
    } catch (err) {
      return [];
    }
  }
}

module.exports = new LoggerService();
