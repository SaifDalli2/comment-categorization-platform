// gateway-service/utils/simpleLogger.js
const os = require('os');

class SimpleLogger {
  constructor() {
    this.serviceName = 'gateway';
    this.logLevel = process.env.LOG_LEVEL || 'info';
    this.enableColors = process.env.NODE_ENV !== 'production' && process.env.ENABLE_COLORS !== 'false';
    
    // Log levels with numeric values for filtering
    this.levels = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3
    };
    
    this.currentLevel = this.levels[this.logLevel] || 1;
    this.startTime = Date.now();
  }

  // Core logging method
  log(level, message, metadata = {}, error = null) {
    if (this.levels[level] < this.currentLevel) {
      return; // Skip logs below current level
    }

    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      service: this.serviceName,
      message,
      ...(Object.keys(metadata).length > 0 && { metadata }),
      ...(error && {
        error: {
          name: error.name,
          message: error.message,
          ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
        }
      })
    };

    this.output(level, logEntry);
  }

  // Output log entry
  output(level, logEntry) {
    const output = process.env.NODE_ENV === 'production' ? 
      JSON.stringify(logEntry) : 
      this.formatForDevelopment(level, logEntry);

    if (level === 'error') {
      console.error(output);
    } else {
      console.log(output);
    }
  }

  // Format log for development with colors
  formatForDevelopment(level, logEntry) {
    const colors = {
      debug: '\x1b[36m', // cyan
      info: '\x1b[32m',  // green
      warn: '\x1b[33m',  // yellow
      error: '\x1b[31m'  // red
    };
    
    const reset = '\x1b[0m';
    const timestamp = new Date(logEntry.timestamp).toLocaleTimeString();
    
    let output = this.enableColors ? 
      `${colors[level]}[${level.toUpperCase()}]${reset} ${timestamp} ${logEntry.message}` :
      `[${level.toUpperCase()}] ${timestamp} ${logEntry.message}`;

    // Add metadata if present
    if (logEntry.metadata && Object.keys(logEntry.metadata).length > 0) {
      output += `\n  ${JSON.stringify(logEntry.metadata, null, 2)}`;
    }

    // Add error if present
    if (logEntry.error) {
      output += `\n  Error: ${logEntry.error.message}`;
      if (logEntry.error.stack) {
        output += `\n  ${logEntry.error.stack}`;
      }
    }

    return output;
  }

  // Convenience methods
  debug(message, metadata = {}) {
    this.log('debug', message, metadata);
  }

  info(message, metadata = {}) {
    this.log('info', message, metadata);
  }

  warn(message, metadata = {}, error = null) {
    this.log('warn', message, metadata, error);
  }

  error(message, metadata = {}, error = null) {
    this.log('error', message, metadata, error);
  }

  // HTTP request logging helper
  request(req, res, responseTime) {
    const metadata = {
      method: req.method,
      url: req.originalUrl || req.url,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      userAgent: req.get('User-Agent'),
      ip: req.ip
    };

    const level = res.statusCode >= 500 ? 'error' : 
                  res.statusCode >= 400 ? 'warn' : 'info';

    this.log(level, `${req.method} ${req.path} ${res.statusCode}`, metadata);
  }

  // Authentication logging helper
  auth(event, success, user = null, error = null) {
    const metadata = {
      event,
      success,
      ...(user && { userId: user.id, email: user.email })
    };

    const level = success ? 'info' : 'warn';
    const message = `Authentication ${event}: ${success ? 'success' : 'failed'}`;

    this.log(level, message, metadata, error);
  }

  // Service health logging helper
  health(serviceName, status, responseTime = null, error = null) {
    const metadata = {
      serviceName,
      status,
      ...(responseTime && { responseTime: `${responseTime}ms` })
    };

    const level = status === 'healthy' ? 'debug' : 'warn';
    const message = `Health check ${serviceName}: ${status}`;

    this.log(level, message, metadata, error);
  }

  // Performance logging helper
  performance(operation, duration, metadata = {}) {
    const perfMetadata = {
      operation,
      duration: `${duration}ms`,
      ...metadata
    };

    const level = duration > 5000 ? 'warn' : 'debug'; // 5 second threshold
    const message = `Performance: ${operation} completed`;

    this.log(level, message, perfMetadata);
  }

  // Get logger configuration
  getConfig() {
    return {
      serviceName: this.serviceName,
      logLevel: this.logLevel,
      enableColors: this.enableColors,
      uptime: Math.floor((Date.now() - this.startTime) / 1000),
      environment: process.env.NODE_ENV || 'development'
    };
  }

  // Set log level at runtime
  setLogLevel(level) {
    if (this.levels.hasOwnProperty(level)) {
      this.logLevel = level;
      this.currentLevel = this.levels[level];
      this.info(`Log level changed to ${level}`);
      return true;
    }
    return false;
  }

  // Express middleware for request logging
  middleware() {
    return (req, res, next) => {
      const start = Date.now();
      
      res.on('finish', () => {
        const duration = Date.now() - start;
        this.request(req, res, duration);
      });
      
      next();
    };
  }

  // Structured logging for different contexts
  gateway(message, metadata = {}) {
    this.info(message, { context: 'gateway', ...metadata });
  }

  proxy(serviceName, message, metadata = {}) {
    this.info(message, { context: 'proxy', serviceName, ...metadata });
  }

  security(event, metadata = {}) {
    this.warn(`Security event: ${event}`, { context: 'security', ...metadata });
  }

  // System information logging
  systemInfo() {
    const info = {
      nodeVersion: process.version,
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname(),
      uptime: Math.floor(process.uptime()),
      memory: {
        rss: Math.round(process.memoryUsage().rss / 1024 / 1024),
        heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        heapTotal: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
      },
      loadAverage: os.loadavg()
    };

    this.info('System information', info);
    return info;
  }

  // Cleanup method
  cleanup() {
    this.info('Logger cleanup completed');
  }
}

// Create singleton instance
const logger = new SimpleLogger();

module.exports = logger;