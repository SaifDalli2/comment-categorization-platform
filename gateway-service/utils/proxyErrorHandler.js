// gateway-service/utils/proxyErrorHandler.js
const logger = require('./logger');
const metrics = require('./metrics');

class ProxyErrorHandler {
  constructor(errorHandler) {
    this.errorHandler = errorHandler;
    this.serviceRetryAttempts = new Map();
    this.maxRetryAttempts = parseInt(process.env.MAX_RETRY_ATTEMPTS) || 3;
    this.retryDelay = parseInt(process.env.RETRY_DELAY_MS) || 1000;
  }

  // Enhanced proxy error handler with retry logic and circuit breaker support
  handleProxyError(serviceName, serviceRegistry) {
    return (err, req, res) => {
      const responseTime = Date.now() - (req.proxyStartTime || Date.now());
      const requestId = req.headers['x-request-id'] || 'unknown';
      
      // Record failed request in service registry
      const service = serviceRegistry.getService(serviceName);
      if (service) {
        serviceRegistry.recordRequest(serviceName, service.id, false, responseTime);
      }

      // Determine error type and appropriate response
      const { errorCode, statusCode, shouldRetry } = this.categorizeProxyError(err, serviceName);
      
      // Record metrics
      metrics.recordServiceRequest(serviceName, req.method, statusCode, responseTime, false);
      
      // Log the proxy error with context
      this.logProxyError(err, req, serviceName, errorCode, statusCode, responseTime, requestId);
      
      // Check if we should attempt retry
      if (shouldRetry && this.shouldRetryRequest(req, serviceName)) {
        return this.attemptRetry(req, res, serviceName, serviceRegistry, errorCode);
      }
      
      // No retry or max retries reached - return error response
      this.sendProxyErrorResponse(req, res, errorCode, statusCode, serviceName, err, requestId);
    };
  }

  // Categorize different types of proxy errors
  categorizeProxyError(err, serviceName) {
    let errorCode = 'PROXY_ERROR';
    let statusCode = 502;
    let shouldRetry = false;

    if (err.code) {
      switch (err.code) {
        case 'ECONNREFUSED':
        case 'ENOTFOUND':
          errorCode = 'SERVICE_UNAVAILABLE';
          statusCode = 503;
          shouldRetry = true;
          break;
        case 'ETIMEDOUT':
        case 'ECONNRESET':
        case 'EPIPE':
          errorCode = 'GATEWAY_TIMEOUT';
          statusCode = 504;
          shouldRetry = true;
          break;
        case 'DEPTH_ZERO_SELF_SIGNED_CERT':
        case 'SELF_SIGNED_CERT_IN_CHAIN':
        case 'CERT_HAS_EXPIRED':
          errorCode = 'PROXY_ERROR';
          statusCode = 502;
          shouldRetry = false;
          break;
        default:
          errorCode = 'PROXY_ERROR';
          statusCode = 502;
          shouldRetry = false;
      }
    } else if (err.name === 'CircuitBreakerError') {
      errorCode = 'CIRCUIT_BREAKER_OPEN';
      statusCode = 503;
      shouldRetry = false; // Circuit breaker handles its own retry logic
    } else if (err.status || err.statusCode) {
      statusCode = err.status || err.statusCode;
      if (statusCode >= 500) {
        errorCode = 'SERVICE_UNAVAILABLE';
        shouldRetry = true;
      } else if (statusCode === 404) {
        errorCode = 'RESOURCE_NOT_FOUND';
        shouldRetry = false;
      } else if (statusCode === 401 || statusCode === 403) {
        errorCode = statusCode === 401 ? 'AUTHENTICATION_REQUIRED' : 'INSUFFICIENT_PERMISSIONS';
        shouldRetry = false;
      } else {
        errorCode = 'PROXY_ERROR';
        shouldRetry = false;
      }
    }

    return { errorCode, statusCode, shouldRetry };
  }

  // Check if request should be retried
  shouldRetryRequest(req, serviceName) {
    const retryKey = `${serviceName}-${req.headers['x-request-id']}`;
    const attempts = this.serviceRetryAttempts.get(retryKey) || 0;
    
    // Don't retry non-idempotent methods unless explicitly configured
    const isIdempotent = ['GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE'].includes(req.method);
    const allowNonIdempotentRetry = process.env.ALLOW_NON_IDEMPOTENT_RETRY === 'true';
    
    if (!isIdempotent && !allowNonIdempotentRetry) {
      return false;
    }
    
    return attempts < this.maxRetryAttempts;
  }

  // Attempt to retry the request with a different service instance
  async attemptRetry(req, res, serviceName, serviceRegistry, originalErrorCode) {
    const retryKey = `${serviceName}-${req.headers['x-request-id']}`;
    const attempts = this.serviceRetryAttempts.get(retryKey) || 0;
    
    // Increment retry count
    this.serviceRetryAttempts.set(retryKey, attempts + 1);
    
    // Add delay before retry (exponential backoff)
    const delay = this.retryDelay * Math.pow(2, attempts);
    
    logger.info('Retrying proxy request', {
      proxy: {
        serviceName,
        attempt: attempts + 1,
        maxAttempts: this.maxRetryAttempts,
        delay,
        originalError: originalErrorCode,
        requestId: req.headers['x-request-id']
      }
    });

    setTimeout(() => {
      // Try to get a different healthy service instance
      const newService = serviceRegistry.getService(serviceName);
      
      if (!newService) {
        // No healthy instances available
        logger.warn('No healthy service instances available for retry', {
          proxy: {
            serviceName,
            attempt: attempts + 1,
            requestId: req.headers['x-request-id']
          }
        });
        
        return this.sendProxyErrorResponse(
          req, 
          res, 
          'SERVICE_UNAVAILABLE', 
          503, 
          serviceName, 
          new Error('No healthy service instances available'), 
          req.headers['x-request-id']
        );
      }

      // Forward the request to the new instance
      // Note: This would require integration with the proxy middleware
      // For now, we'll return an error indicating retry failed
      this.sendProxyErrorResponse(
        req, 
        res, 
        originalErrorCode, 
        503, 
        serviceName, 
        new Error('Retry limit reached'), 
        req.headers['x-request-id']
      );
    }, delay);
  }

  // Send standardized proxy error response
  sendProxyErrorResponse(req, res, errorCode, statusCode, serviceName, originalError, requestId) {
    // Clean up retry tracking
    const retryKey = `${serviceName}-${requestId}`;
    this.serviceRetryAttempts.delete(retryKey);

    if (res.headersSent) {
      return; // Response already sent
    }

    // Create error response using the error handler
    const errorResponse = this.errorHandler.createErrorResponse(
      errorCode,
      this.getServiceSpecificMessage(errorCode, serviceName),
      this.getServiceSpecificDetails(errorCode, serviceName, originalError),
      requestId,
      {
        targetService: serviceName,
        path: req.path,
        method: req.method
      }
    );

    // Add service-specific headers
    res.setHeader('X-Target-Service', serviceName);
    res.setHeader('X-Proxy-Error', 'true');
    
    if (process.env.NODE_ENV === 'development') {
      res.setHeader('X-Original-Error', originalError.message);
      res.setHeader('X-Error-Code', originalError.code || 'unknown');
    }

    res.status(statusCode).json(errorResponse);
  }

  // Get service-specific error messages
  getServiceSpecificMessage(errorCode, serviceName) {
    const serviceMessages = {
      SERVICE_UNAVAILABLE: `The ${serviceName} service is temporarily unavailable`,
      GATEWAY_TIMEOUT: `Request to ${serviceName} service timed out`,
      CIRCUIT_BREAKER_OPEN: `The ${serviceName} service is temporarily unavailable due to repeated failures`,
      PROXY_ERROR: `Unable to connect to ${serviceName} service`
    };

    return serviceMessages[errorCode] || null;
  }

  // Get service-specific error details and suggestions
  getServiceSpecificDetails(errorCode, serviceName, originalError) {
    const serviceDetails = {
      'auth': {
        SERVICE_UNAVAILABLE: 'Authentication service is down. You may not be able to login or validate tokens.',
        GATEWAY_TIMEOUT: 'Authentication request took too long. This may affect login and token validation.',
        CIRCUIT_BREAKER_OPEN: 'Authentication service is experiencing issues. Please try again in a few minutes.'
      },
      'comment': {
        SERVICE_UNAVAILABLE: 'Comment processing service is down. Comment categorization is temporarily unavailable.',
        GATEWAY_TIMEOUT: 'Comment processing is taking longer than expected. Try with fewer comments or try again later.',
        CIRCUIT_BREAKER_OPEN: 'Comment processing service is experiencing issues. Please try again in a few minutes.'
      },
      'industry': {
        SERVICE_UNAVAILABLE: 'Industry configuration service is down. Industry-specific features may not work.',
        GATEWAY_TIMEOUT: 'Industry data request timed out. Please try again.',
        CIRCUIT_BREAKER_OPEN: 'Industry service is experiencing issues. Default configurations will be used.'
      },
      'nps': {
        SERVICE_UNAVAILABLE: 'NPS analytics service is down. NPS data and dashboards are temporarily unavailable.',
        GATEWAY_TIMEOUT: 'NPS data processing is taking longer than expected. Try again later.',
        CIRCUIT_BREAKER_OPEN: 'NPS service is experiencing issues. Analytics may be temporarily unavailable.'
      }
    };

    return serviceDetails[serviceName]?.[errorCode] || originalError.message;
  }

  // Log detailed proxy errors
  logProxyError(err, req, serviceName, errorCode, statusCode, responseTime, requestId) {
    const logLevel = statusCode >= 500 ? 'error' : 'warn';
    
    logger.log(logLevel, 'Proxy request failed', {
      proxy: {
        serviceName,
        errorCode,
        statusCode,
        responseTime,
        success: false
      },
      request: {
        id: requestId,
        method: req.method,
        path: req.path,
        url: req.originalUrl,
        userAgent: req.get('User-Agent'),
        ip: req.ip
      },
      error: {
        name: err.name,
        message: err.message,
        code: err.code,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
      },
      user: req.userContext ? {
        userId: req.userContext.userId,
        email: req.userContext.email
      } : undefined
    }, err);

    // Log specific patterns for monitoring
    if (errorCode === 'CIRCUIT_BREAKER_OPEN') {
      logger.warn('Circuit breaker is open', {
        proxy: {
          serviceName,
          requestId,
          suggestion: 'Service may be overloaded or experiencing issues'
        }
      });
    } else if (statusCode >= 500) {
      logger.error('Server error in downstream service', {
        proxy: {
          serviceName,
          statusCode,
          requestId,
          suggestion: 'Check downstream service health and logs'
        }
      });
    }
  }

  // Get retry statistics
  getRetryStats() {
    const stats = {
      activeRetries: this.serviceRetryAttempts.size,
      maxRetryAttempts: this.maxRetryAttempts,
      retryDelay: this.retryDelay,
      retryAttempts: {}
    };

    for (const [key, attempts] of this.serviceRetryAttempts.entries()) {
      const [serviceName] = key.split('-');
      if (!stats.retryAttempts[serviceName]) {
        stats.retryAttempts[serviceName] = { total: 0, requests: 0 };
      }
      stats.retryAttempts[serviceName].total += attempts;
      stats.retryAttempts[serviceName].requests += 1;
    }

    return stats;
  }

  // Cleanup expired retry attempts
  cleanup() {
    // Clear old retry attempts (older than 5 minutes)
    const now = Date.now();
    const maxAge = 5 * 60 * 1000;
    
    for (const [key, attempts] of this.serviceRetryAttempts.entries()) {
      // Extract timestamp from request ID if possible
      const requestId = key.split('-').slice(1).join('-');
      if (requestId.startsWith('req_')) {
        const timestamp = parseInt(requestId.split('_')[1]);
        if (now - timestamp > maxAge) {
          this.serviceRetryAttempts.delete(key);
        }
      }
    }

    logger.debug('Proxy error handler cleanup completed', {
      remainingRetries: this.serviceRetryAttempts.size
    });
  }
}

module.exports = ProxyErrorHandler;