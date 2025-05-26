// gateway-service/utils/logger.js
const os = require('os');

class Logger {
  constructor(options = {}) {
    this.serviceName = options.serviceName || 'gateway';
    this.version = options.version || process.env.npm_package_version || '1.0.0';
    this.environment = options.environment || process.env.NODE_ENV || 'development';
    this.logLevel = options.logLevel || process.env.LOG_LEVEL || 'info';
    this.enableConsole = options.enableConsole !== false;
    
    // Log levels with numeric values for filtering
    this.levels = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3,
      fatal: 4
    };
    
    this.currentLevel = this.levels[this.logLevel] || 1;
    
    // Performance tracking
    this.startTime = Date.now();
    this.requestTimers = new Map();
  }

  // Core logging method following shared knowledge format
  log(level, message, metadata = {}, error = null) {
    if (this.levels[level] < this.currentLevel) {
      return; // Skip logs below current level
    }

    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      service: this.serviceName,
      message,
      metadata: {
        environment: this.environment,
        version: this.version,
        hostname: os.hostname(),
        pid: process.pid,
        uptime: Math.floor((Date.now() - this.startTime) / 1000),
        ...metadata
      }
    };

    // Add error details if provided
    if (error) {
      logEntry.error = {
        name: error.name,
        message: error.message,
        stack: this.environment === 'development' ? error.stack : undefined,
        code: error.code,
        status: error.status
      };
    }

    // Add memory usage for performance monitoring
    if (level === 'debug' || level === 'error') {
      const memUsage = process.memoryUsage();
      logEntry.metadata.memory = {
        rss: Math.round(memUsage.rss / 1024 / 1024), // MB
        heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024), // MB
        heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024), // MB
        external: Math.round(memUsage.external / 1024 / 1024) // MB
      };
    }

    // Output log entry
    if (this.enableConsole) {
      if (level === 'error' || level === 'fatal') {
        console.error(JSON.stringify(logEntry));
      } else {
        console.log(JSON.stringify(logEntry));
      }
    }

    return logEntry;
  }

  // Convenience methods for different log levels
  debug(message, metadata = {}) {
    return this.log('debug', message, metadata);
  }

  info(message, metadata = {}) {
    return this.log('info', message, metadata);
  }

  warn(message, metadata = {}, error = null) {
    return this.log('warn', message, metadata, error);
  }

  error(message, metadata = {}, error = null) {
    return this.log('error', message, metadata, error);
  }

  fatal(message, metadata = {}, error = null) {
    return this.log('fatal', message, metadata, error);
  }

  // HTTP request logging
  httpRequest(req, res, responseTime) {
    const metadata = {
      request: {
        id: req.headers['x-request-id'],
        method: req.method,
        url: req.originalUrl || req.url,
        path: req.path,
        query: Object.keys(req.query).length > 0 ? req.query : undefined,
        headers: this.sanitizeHeaders(req.headers),
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        contentLength: req.get('Content-Length') || 0
      },
      response: {
        statusCode: res.statusCode,
        statusMessage: res.statusMessage,
        contentLength: res.get('Content-Length') || 0,
        responseTime: responseTime
      },
      user: req.userContext ? {
        userId: req.userContext.userId,
        email: req.userContext.email,
        roles: req.userContext.roles
      } : undefined
    };

    // Determine log level based on status code
    let level = 'info';
    if (res.statusCode >= 500) {
      level = 'error';
    } else if (res.statusCode >= 400) {
      level = 'warn';
    }

    return this.log(level, 'HTTP Request completed', metadata);
  }

  // Service proxy logging
  serviceProxy(serviceName, req, res, responseTime, targetUrl, success = true, error = null) {
    const metadata = {
      proxy: {
        serviceName,
        targetUrl,
        success,
        responseTime
      },
      request: {
        id: req.headers['x-request-id'],
        method: req.method,
        path: req.path,
        userId: req.userContext?.userId
      },
      response: {
        statusCode: res?.statusCode,
        responseTime
      }
    };

    if (success) {
      return this.log('info', 'Service proxy request completed', metadata);
    } else {
      return this.log('error', 'Service proxy request failed', metadata, error);
    }
  }

  // Health check logging
  healthCheck(serviceName, status, responseTime, error = null) {
    const metadata = {
      healthCheck: {
        serviceName,
        status,
        responseTime
      }
    };

    const level = status === 'healthy' ? 'debug' : 'warn';
    const message = `Health check: ${serviceName} is ${status}`;

    return this.log(level, message, metadata, error);
  }

  // Authentication logging
  authentication(event, req, success = true, error = null, metadata = {}) {
    const logMetadata = {
      auth: {
        event, // 'login', 'token_validation', 'logout', etc.
        success,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path
      },
      request: {
        id: req.headers['x-request-id'],
        method: req.method
      },
      user: req.userContext ? {
        userId: req.userContext.userId,
        email: req.userContext.email
      } : undefined,
      ...metadata
    };

    const level = success ? 'info' : 'warn';
    const message = `Authentication ${event}: ${success ? 'success' : 'failed'}`;

    return this.log(level, message, logMetadata, error);
  }

  // Security event logging
  security(event, req, details = {}, severity = 'medium') {
    const metadata = {
      security: {
        event,
        severity,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        details
      },
      request: {
        id: req.headers['x-request-id'],
        method: req.method
      },
      user: req.userContext ? {
        userId: req.userContext.userId,
        email: req.userContext.email
      } : undefined
    };

    const level = severity === 'high' || severity === 'critical' ? 'error' : 'warn';
    const message = `Security event: ${event}`;

    return this.log(level, message, metadata);
  }

  // Performance logging
  performance(operation, duration, metadata = {}) {
    const perfMetadata = {
      performance: {
        operation,
        duration,
        ...metadata
      }
    };

    // Log slow operations as warnings
    const level = duration > 5000 ? 'warn' : 'debug'; // 5 seconds threshold
    const message = `Performance: ${operation} completed in ${duration}ms`;

    return this.log(level, message, perfMetadata);
  }

  // Business metrics logging
  businessMetric(metric, value, tags = {}) {
    const metadata = {
      metric: {
        name: metric,
        value,
        tags,
        type: 'business'
      }
    };

    return this.log('info', `Business metric: ${metric}`, metadata);
  }

  // Request timing utilities
  startTimer(requestId) {
    this.requestTimers.set(requestId, Date.now());
  }

  endTimer(requestId) {
    const startTime = this.requestTimers.get(requestId);
    if (startTime) {
      const duration = Date.now() - startTime;
      this.requestTimers.delete(requestId);
      return duration;
    }
    return null;
  }

  // Sanitize sensitive headers
  sanitizeHeaders(headers) {
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key', 'x-auth-token'];
    const sanitized = { ...headers };
    
    sensitiveHeaders.forEach(header => {
      if (sanitized[header]) {
        sanitized[header] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }

  // Express middleware for request logging
  middleware() {
    return (req, res, next) => {
      const startTime = Date.now();
      const requestId = req.headers['x-request-id'] || this.generateRequestId();
      
      // Ensure request ID is set
      req.headers['x-request-id'] = requestId;
      res.setHeader('X-Request-ID', requestId);
      
      // Start timing
      this.startTimer(requestId);
      
      // Log request start
      this.debug('HTTP Request started', {
        request: {
          id: requestId,
          method: req.method,
          url: req.originalUrl || req.url,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        }
      });

      // Override res.end to capture response
      const originalEnd = res.end;
      res.end = (...args) => {
        const responseTime = this.endTimer(requestId) || (Date.now() - startTime);
        
        // Log request completion
        this.httpRequest(req, res, responseTime);
        
        // Call original end method
        originalEnd.apply(res, args);
      };

      next();
    };
  }

  // Generate unique request ID
  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Configure log level at runtime
  setLogLevel(level) {
    if (this.levels.hasOwnProperty(level)) {
      this.logLevel = level;
      this.currentLevel = this.levels[level];
      this.info('Log level changed', { newLevel: level });
      return true;
    }
    return false;
  }

  // Get current configuration
  getConfig() {
    return {
      serviceName: this.serviceName,
      version: this.version,
      environment: this.environment,
      logLevel: this.logLevel,
      enableConsole: this.enableConsole,
      uptime: Math.floor((Date.now() - this.startTime) / 1000)
    };
  }

  // Cleanup method
  cleanup() {
    this.requestTimers.clear();
    this.info('Logger cleanup completed');
  }
}

// Create singleton instance
const logger = new Logger({
  serviceName: 'gateway',
  version: process.env.npm_package_version,
  environment: process.env.NODE_ENV,
  logLevel: process.env.LOG_LEVEL
});

module.exports = logger;