// gateway-service/middleware/errorHandler.js
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

class ErrorHandler {
  constructor() {
    this.errorCategories = {
      // Client errors (4xx)
      VALIDATION_ERROR: { status: 400, type: 'client' },
      AUTHENTICATION_REQUIRED: { status: 401, type: 'client' },
      INVALID_CREDENTIALS: { status: 401, type: 'client' },
      INSUFFICIENT_PERMISSIONS: { status: 403, type: 'client' },
      RESOURCE_NOT_FOUND: { status: 404, type: 'client' },
      METHOD_NOT_ALLOWED: { status: 405, type: 'client' },
      CONFLICT: { status: 409, type: 'client' },
      UNPROCESSABLE_ENTITY: { status: 422, type: 'client' },
      RATE_LIMIT_EXCEEDED: { status: 429, type: 'client' },
      
      // Server errors (5xx)
      INTERNAL_SERVER_ERROR: { status: 500, type: 'server' },
      SERVICE_UNAVAILABLE: { status: 503, type: 'server' },
      GATEWAY_TIMEOUT: { status: 504, type: 'server' },
      
      // Custom gateway errors
      CORS_POLICY_VIOLATION: { status: 403, type: 'client' },
      SERVICE_DISCOVERY_FAILED: { status: 503, type: 'server' },
      CIRCUIT_BREAKER_OPEN: { status: 503, type: 'server' },
      PROXY_ERROR: { status: 502, type: 'server' },
      CONFIGURATION_ERROR: { status: 500, type: 'server' }
    };

    this.errorMessages = {
      VALIDATION_ERROR: {
        message: 'Request validation failed',
        suggestion: 'Please check your request parameters and try again'
      },
      AUTHENTICATION_REQUIRED: {
        message: 'Authentication is required to access this resource',
        suggestion: 'Please provide a valid authentication token in the Authorization header'
      },
      INVALID_CREDENTIALS: {
        message: 'The provided credentials are invalid',
        suggestion: 'Please check your credentials and try again'
      },
      INSUFFICIENT_PERMISSIONS: {
        message: 'You do not have sufficient permissions to access this resource',
        suggestion: 'Contact your administrator if you believe you should have access'
      },
      RESOURCE_NOT_FOUND: {
        message: 'The requested resource could not be found',
        suggestion: 'Please check the URL and try again'
      },
      METHOD_NOT_ALLOWED: {
        message: 'The HTTP method is not allowed for this resource',
        suggestion: 'Please check the API documentation for allowed methods'
      },
      CONFLICT: {
        message: 'The request conflicts with the current state of the resource',
        suggestion: 'Please refresh the resource and try again'
      },
      UNPROCESSABLE_ENTITY: {
        message: 'The request is well-formed but contains semantic errors',
        suggestion: 'Please review the request data and correct any validation errors'
      },
      RATE_LIMIT_EXCEEDED: {
        message: 'Rate limit exceeded',
        suggestion: 'Please wait before making additional requests'
      },
      INTERNAL_SERVER_ERROR: {
        message: 'An unexpected error occurred',
        suggestion: 'Please try again later or contact support if the problem persists'
      },
      SERVICE_UNAVAILABLE: {
        message: 'The service is temporarily unavailable',
        suggestion: 'Please try again in a few moments'
      },
      GATEWAY_TIMEOUT: {
        message: 'The request timed out',
        suggestion: 'Please try again with a smaller request or contact support'
      },
      CORS_POLICY_VIOLATION: {
        message: 'Cross-origin request blocked by CORS policy',
        suggestion: 'Ensure your origin is allowed or contact the API administrator'
      },
      SERVICE_DISCOVERY_FAILED: {
        message: 'Unable to locate the requested service',
        suggestion: 'The service may be temporarily unavailable. Please try again later'
      },
      CIRCUIT_BREAKER_OPEN: {
        message: 'Service is temporarily unavailable due to repeated failures',
        suggestion: 'Please try again in a few minutes'
      },
      PROXY_ERROR: {
        message: 'Gateway encountered an error while processing your request',
        suggestion: 'Please try again or contact support if the problem continues'
      },
      CONFIGURATION_ERROR: {
        message: 'Server configuration error',
        suggestion: 'Please contact support'
      }
    };

    // Error rate tracking
    this.errorRates = new Map();
    this.errorThresholds = {
      warning: 0.05, // 5% error rate
      critical: 0.15  // 15% error rate
    };

    this.initializeMetrics();
  }

  initializeMetrics() {
    // Create custom metrics for error tracking
    this.errorCounter = metrics.createCustomCounter(
      'errors_total',
      'Total number of errors by type and status',
      ['error_type', 'status_code', 'method', 'path']
    );

    this.errorRateGauge = metrics.createCustomGauge(
      'error_rate',
      'Current error rate by service',
      ['service', 'time_window']
    );
  }

  // Create standardized error response following shared knowledge format
  createErrorResponse(errorCode, customMessage = null, details = null, requestId = null, additionalMetadata = {}) {
    const errorConfig = this.errorCategories[errorCode];
    const errorContent = this.errorMessages[errorCode];
    
    if (!errorConfig || !errorContent) {
      // Fallback for unknown error codes
      return this.createErrorResponse('INTERNAL_SERVER_ERROR', customMessage || 'Unknown error occurred', details, requestId, additionalMetadata);
    }

    return {
      success: false,
      error: {
        code: errorCode,
        message: customMessage || errorContent.message,
        suggestion: errorContent.suggestion,
        ...(details && { details })
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: requestId || 'unknown',
        service: 'gateway',
        ...additionalMetadata
      }
    };
  }

  // Main error handling middleware
  handleError() {
    return (err, req, res, next) => {
      const requestId = req.headers['x-request-id'] || 'unknown';
      const startTime = Date.now();

      // Determine error code and status
      const { errorCode, statusCode, message, details } = this.categorizeError(err);
      
      // Record error metrics
      this.recordErrorMetrics(errorCode, statusCode, req.method, req.path);
      
      // Log error with context
      this.logError(err, req, errorCode, statusCode, requestId);
      
      // Update error rates
      this.updateErrorRates(req.path, statusCode >= 500);
      
      // Create standardized response
      const errorResponse = this.createErrorResponse(
        errorCode,
        message,
        details,
        requestId,
        {
          path: req.path,
          method: req.method,
          userAgent: req.get('User-Agent'),
          ...(req.userContext && { userId: req.userContext.userId })
        }
      );

      // Add additional headers for debugging (development only)
      if (process.env.NODE_ENV === 'development') {
        res.setHeader('X-Error-Code', errorCode);
        res.setHeader('X-Error-Category', this.errorCategories[errorCode]?.type || 'unknown');
      }

      // Security headers for error responses
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-store');

      // Send error response
      if (!res.headersSent) {
        res.status(statusCode).json(errorResponse);
      }

      // Check for error rate thresholds
      this.checkErrorRateThresholds(req.path);
    };
  }

  // Categorize different types of errors
  categorizeError(err) {
    let errorCode = 'INTERNAL_SERVER_ERROR';
    let statusCode = 500;
    let message = null;
    let details = null;

    // Handle known error types
    if (err.code) {
      // Use predefined error code if available
      if (this.errorCategories[err.code]) {
        errorCode = err.code;
        statusCode = this.errorCategories[err.code].status;
      }
    } else if (err.status || err.statusCode) {
      // Map HTTP status codes to error codes
      statusCode = err.status || err.statusCode;
      errorCode = this.mapStatusToErrorCode(statusCode);
    } else if (err.name) {
      // Handle specific error types by name
      switch (err.name) {
        case 'ValidationError':
          errorCode = 'VALIDATION_ERROR';
          statusCode = 400;
          details = err.details || err.message;
          break;
        case 'UnauthorizedError':
        case 'JsonWebTokenError':
        case 'TokenExpiredError':
          errorCode = 'INVALID_CREDENTIALS';
          statusCode = 401;
          break;
        case 'ForbiddenError':
          errorCode = 'INSUFFICIENT_PERMISSIONS';
          statusCode = 403;
          break;
        case 'NotFoundError':
          errorCode = 'RESOURCE_NOT_FOUND';
          statusCode = 404;
          break;
        case 'ConflictError':
          errorCode = 'CONFLICT';
          statusCode = 409;
          break;
        case 'RateLimitError':
          errorCode = 'RATE_LIMIT_EXCEEDED';
          statusCode = 429;
          break;
        case 'TimeoutError':
        case 'RequestTimeoutError':
          errorCode = 'GATEWAY_TIMEOUT';
          statusCode = 504;
          break;
        case 'ServiceUnavailableError':
          errorCode = 'SERVICE_UNAVAILABLE';
          statusCode = 503;
          break;
        case 'CircuitBreakerError':
          errorCode = 'CIRCUIT_BREAKER_OPEN';
          statusCode = 503;
          break;
      }
    }

    // Handle network and proxy errors
    if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
      errorCode = 'SERVICE_UNAVAILABLE';
      statusCode = 503;
    } else if (err.code === 'ETIMEDOUT' || err.code === 'ECONNRESET') {
      errorCode = 'GATEWAY_TIMEOUT';
      statusCode = 504;
    }

    // Use custom message if provided
    if (err.message && !message) {
      message = err.message;
    }

    return { errorCode, statusCode, message, details };
  }

  // Map HTTP status codes to error codes
  mapStatusToErrorCode(statusCode) {
    const statusMap = {
      400: 'VALIDATION_ERROR',
      401: 'AUTHENTICATION_REQUIRED',
      403: 'INSUFFICIENT_PERMISSIONS',
      404: 'RESOURCE_NOT_FOUND',
      405: 'METHOD_NOT_ALLOWED',
      409: 'CONFLICT',
      422: 'UNPROCESSABLE_ENTITY',
      429: 'RATE_LIMIT_EXCEEDED',
      500: 'INTERNAL_SERVER_ERROR',
      502: 'PROXY_ERROR',
      503: 'SERVICE_UNAVAILABLE',
      504: 'GATEWAY_TIMEOUT'
    };

    return statusMap[statusCode] || 'INTERNAL_SERVER_ERROR';
  }

  // Enhanced error logging with context
  logError(err, req, errorCode, statusCode, requestId) {
    const isServerError = statusCode >= 500;
    const logLevel = isServerError ? 'error' : 'warn';
    
    const errorContext = {
      error: {
        code: errorCode,
        name: err.name,
        message: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        statusCode
      },
      request: {
        id: requestId,
        method: req.method,
        url: req.originalUrl || req.url,
        path: req.path,
        query: Object.keys(req.query || {}).length > 0 ? req.query : undefined,
        headers: this.sanitizeHeaders(req.headers),
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        contentLength: req.get('Content-Length') || 0
      },
      user: req.userContext ? {
        userId: req.userContext.userId,
        email: req.userContext.email,
        roles: req.userContext.roles
      } : undefined,
      service: req.targetService ? {
        name: req.targetService,
        proxyStartTime: req.proxyStartTime
      } : undefined
    };

    logger.log(logLevel, `Request failed: ${errorCode}`, errorContext, err);

    // Log security-related errors with higher priority
    if (['INSUFFICIENT_PERMISSIONS', 'INVALID_CREDENTIALS', 'CORS_POLICY_VIOLATION'].includes(errorCode)) {
      logger.security('error_occurred', req, {
        errorCode,
        statusCode,
        severity: 'medium'
      });
    }
  }

  // Record error metrics
  recordErrorMetrics(errorCode, statusCode, method, path) {
    if (this.errorCounter) {
      this.errorCounter.inc({
        error_type: errorCode,
        status_code: statusCode.toString(),
        method,
        path: this.normalizePath(path)
      });
    }

    // Record in metrics system
    metrics.recordHttpRequest(method, path, statusCode, 0);
  }

  // Update error rates for monitoring
  updateErrorRates(path, isServerError) {
    const normalizedPath = this.normalizePath(path);
    const now = Date.now();
    const windowMs = 60000; // 1 minute window
    
    if (!this.errorRates.has(normalizedPath)) {
      this.errorRates.set(normalizedPath, {
        total: 0,
        errors: 0,
        serverErrors: 0,
        windowStart: now
      });
    }

    const stats = this.errorRates.get(normalizedPath);
    
    // Reset window if needed
    if (now - stats.windowStart > windowMs) {
      stats.total = 0;
      stats.errors = 0;
      stats.serverErrors = 0;
      stats.windowStart = now;
    }

    stats.total++;
    stats.errors++;
    
    if (isServerError) {
      stats.serverErrors++;
    }

    // Update gauge metric
    if (this.errorRateGauge && stats.total > 0) {
      this.errorRateGauge.set(
        { service: 'gateway', time_window: '1m' },
        stats.errors / stats.total
      );
    }
  }

  // Check error rate thresholds and alert
  checkErrorRateThresholds(path) {
    const normalizedPath = this.normalizePath(path);
    const stats = this.errorRates.get(normalizedPath);
    
    if (!stats || stats.total < 10) return; // Need minimum requests for meaningful rate
    
    const errorRate = stats.errors / stats.total;
    const serverErrorRate = stats.serverErrors / stats.total;
    
    if (serverErrorRate > this.errorThresholds.critical) {
      logger.error('Critical server error rate detected', {
        monitoring: {
          path: normalizedPath,
          errorRate,
          serverErrorRate,
          threshold: this.errorThresholds.critical,
          totalRequests: stats.total,
          timeWindow: '1m'
        }
      });
    } else if (errorRate > this.errorThresholds.warning) {
      logger.warn('High error rate detected', {
        monitoring: {
          path: normalizedPath,
          errorRate,
          serverErrorRate,
          threshold: this.errorThresholds.warning,
          totalRequests: stats.total,
          timeWindow: '1m'
        }
      });
    }
  }

  // Validation error handler for request validation
  handleValidationError() {
    return (err, req, res, next) => {
      if (err.name === 'ValidationError' || err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
        const errorCode = 'VALIDATION_ERROR';
        const requestId = req.headers['x-request-id'] || 'unknown';
        
        let details = err.message;
        let customMessage = null;
        
        if (err.type === 'entity.too.large') {
          customMessage = 'Request payload too large';
          details = `Maximum allowed size exceeded. Limit: ${err.limit || 'unknown'}`;
        } else if (err.type === 'entity.parse.failed') {
          customMessage = 'Invalid request format';
          details = 'Please ensure request body is valid JSON';
        }
        
        const errorResponse = this.createErrorResponse(
          errorCode,
          customMessage,
          details,
          requestId
        );
        
        this.recordErrorMetrics(errorCode, 400, req.method, req.path);
        
        logger.warn('Request validation failed', {
          request: {
            id: requestId,
            method: req.method,
            path: req.path,
            contentType: req.get('Content-Type'),
            contentLength: req.get('Content-Length')
          },
          validation: {
            errorType: err.type,
            message: err.message
          }
        });
        
        return res.status(400).json(errorResponse);
      }
      
      next(err);
    };
  }

  // 404 handler for unmatched routes
  handle404() {
    return (req, res) => {
      const requestId = req.headers['x-request-id'] || 'unknown';
      
      // Determine if this is an API request or static file request
      const isApiRequest = req.originalUrl.startsWith('/api/');
      const errorCode = 'RESOURCE_NOT_FOUND';
      
      this.recordErrorMetrics(errorCode, 404, req.method, req.path);
      
      logger.warn('Resource not found', {
        request: {
          id: requestId,
          method: req.method,
          url: req.originalUrl,
          path: req.path,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          isApiRequest
        }
      });
      
      if (isApiRequest) {
        const errorResponse = this.createErrorResponse(
          errorCode,
          'The requested API endpoint does not exist',
          'Check the API documentation for available endpoints',
          requestId
        );
        
        return res.status(404).json(errorResponse);
      }
      
      // For non-API requests, try to serve index.html (SPA support)
      const path = require('path');
      res.sendFile(path.join(__dirname, '../../public/index.html'), (err) => {
        if (err) {
          const errorResponse = this.createErrorResponse(
            errorCode,
            'The requested resource could not be found',
            'Check the URL and try again',
            requestId
          );
          
          res.status(404).json(errorResponse);
        }
      });
    };
  }

  // Method not allowed handler
  handleMethodNotAllowed() {
    return (req, res, next) => {
      const errorCode = 'METHOD_NOT_ALLOWED';
      const requestId = req.headers['x-request-id'] || 'unknown';
      
      const errorResponse = this.createErrorResponse(
        errorCode,
        `Method ${req.method} is not allowed for this endpoint`,
        'Please check the API documentation for allowed methods',
        requestId
      );
      
      this.recordErrorMetrics(errorCode, 405, req.method, req.path);
      
      logger.warn('Method not allowed', {
        request: {
          id: requestId,
          method: req.method,
          path: req.path
        }
      });
      
      res.setHeader('Allow', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      res.status(405).json(errorResponse);
    };
  }

  // Async error wrapper for route handlers
  asyncErrorHandler(fn) {
    return (req, res, next) => {
      Promise.resolve(fn(req, res, next)).catch(next);
    };
  }

  // Sanitize headers for logging (remove sensitive data)
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

  // Normalize path for metrics (remove dynamic segments)
  normalizePath(path) {
    if (!path) return 'unknown';
    
    // Replace UUIDs, IDs, and other dynamic segments
    return path
      .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:uuid')
      .replace(/\/\d+/g, '/:id')
      .replace(/\/[a-zA-Z0-9_-]{20,}/g, '/:token');
  }

  // Get error statistics
  getErrorStats() {
    const stats = {
      errorRates: {},
      thresholds: this.errorThresholds,
      errorCategories: Object.keys(this.errorCategories),
      totalPaths: this.errorRates.size
    };

    for (const [path, pathStats] of this.errorRates.entries()) {
      if (pathStats.total > 0) {
        stats.errorRates[path] = {
          total: pathStats.total,
          errors: pathStats.errors,
          serverErrors: pathStats.serverErrors,
          errorRate: pathStats.errors / pathStats.total,
          serverErrorRate: pathStats.serverErrors / pathStats.total,
          windowStart: new Date(pathStats.windowStart).toISOString()
        };
      }
    }

    return stats;
  }

  // Cleanup expired error rate data
  cleanup() {
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes
    
    for (const [path, stats] of this.errorRates.entries()) {
      if (now - stats.windowStart > maxAge) {
        this.errorRates.delete(path);
      }
    }
    
    logger.debug('Error handler cleanup completed', {
      remainingPaths: this.errorRates.size
    });
  }
}

module.exports = ErrorHandler;