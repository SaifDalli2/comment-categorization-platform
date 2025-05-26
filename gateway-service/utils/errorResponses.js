// gateway-service/utils/errorResponses.js

/**
 * Centralized error response utilities following shared knowledge standards
 * Provides consistent error response formats across the gateway service
 */

class ErrorResponses {
  constructor() {
    // Common error scenarios with their details
    this.commonErrors = {
      // Authentication & Authorization
      TOKEN_MISSING: {
        code: 'AUTHENTICATION_REQUIRED',
        status: 401,
        message: 'Authentication token is required',
        suggestion: 'Please provide a valid Bearer token in the Authorization header'
      },
      TOKEN_INVALID: {
        code: 'INVALID_CREDENTIALS',
        status: 401,
        message: 'The provided authentication token is invalid or expired',
        suggestion: 'Please login again to get a new token'
      },
      TOKEN_EXPIRED: {
        code: 'INVALID_CREDENTIALS',
        status: 401,
        message: 'Your authentication token has expired',
        suggestion: 'Please login again to get a new token'
      },
      INSUFFICIENT_PERMISSIONS: {
        code: 'INSUFFICIENT_PERMISSIONS',
        status: 403,
        message: 'You do not have permission to access this resource',
        suggestion: 'Contact your administrator if you believe you should have access'
      },
      
      // API Key Validation
      API_KEY_MISSING: {
        code: 'AUTHENTICATION_REQUIRED',
        status: 401,
        message: 'API key is required for this request',
        suggestion: 'Please provide a valid API key in the x-api-key header'
      },
      API_KEY_INVALID: {
        code: 'INVALID_CREDENTIALS',
        status: 401,
        message: 'The provided API key is invalid',
        suggestion: 'Please check your API key format and try again'
      },
      
      // Rate Limiting
      RATE_LIMIT_GENERAL: {
        code: 'RATE_LIMIT_EXCEEDED',
        status: 429,
        message: 'Too many requests from your IP address',
        suggestion: 'Please wait before making additional requests'
      },
      RATE_LIMIT_AUTH: {
        code: 'RATE_LIMIT_EXCEEDED',
        status: 429,
        message: 'Too many authentication attempts',
        suggestion: 'Please wait 15 minutes before trying to authenticate again'
      },
      RATE_LIMIT_COMMENTS: {
        code: 'RATE_LIMIT_EXCEEDED',
        status: 429,
        message: 'Comment processing rate limit exceeded',
        suggestion: 'You can process more comments in an hour. Please wait or upgrade your plan'
      },
      
      // CORS
      CORS_BLOCKED: {
        code: 'CORS_POLICY_VIOLATION',
        status: 403,
        message: 'Cross-origin request blocked by CORS policy',
        suggestion: 'Ensure your domain is whitelisted or contact the API administrator'
      },
      
      // Input Validation
      INVALID_JSON: {
        code: 'VALIDATION_ERROR',
        status: 400,
        message: 'Invalid JSON in request body',
        suggestion: 'Please ensure your request body contains valid JSON'
      },
      PAYLOAD_TOO_LARGE: {
        code: 'VALIDATION_ERROR',
        status: 413,
        message: 'Request payload is too large',
        suggestion: 'Please reduce the size of your request and try again'
      },
      MISSING_REQUIRED_FIELD: {
        code: 'VALIDATION_ERROR',
        status: 400,
        message: 'Required field is missing',
        suggestion: 'Please check the API documentation for required fields'
      },
      
      // Service Errors
      SERVICE_UNAVAILABLE: {
        code: 'SERVICE_UNAVAILABLE',
        status: 503,
        message: 'Service is temporarily unavailable',
        suggestion: 'Please try again in a few moments'
      },
      SERVICE_TIMEOUT: {
        code: 'GATEWAY_TIMEOUT',
        status: 504,
        message: 'Service request timed out',
        suggestion: 'Please try again with a smaller request or wait a moment'
      },
      CIRCUIT_BREAKER: {
        code: 'CIRCUIT_BREAKER_OPEN',
        status: 503,
        message: 'Service is temporarily unavailable due to repeated failures',
        suggestion: 'Please try again in a few minutes'
      },
      
      // Resource Errors
      NOT_FOUND: {
        code: 'RESOURCE_NOT_FOUND',
        status: 404,
        message: 'The requested resource was not found',
        suggestion: 'Please check the URL and try again'
      },
      ENDPOINT_NOT_FOUND: {
        code: 'RESOURCE_NOT_FOUND',
        status: 404,
        message: 'The requested API endpoint does not exist',
        suggestion: 'Please check the API documentation for available endpoints'
      },
      METHOD_NOT_ALLOWED: {
        code: 'METHOD_NOT_ALLOWED',
        status: 405,
        message: 'HTTP method not allowed for this endpoint',
        suggestion: 'Please check the API documentation for allowed methods'
      },
      
      // Server Errors
      INTERNAL_ERROR: {
        code: 'INTERNAL_SERVER_ERROR',
        status: 500,
        message: 'An unexpected error occurred',
        suggestion: 'Please try again later or contact support if the problem persists'
      },
      CONFIGURATION_ERROR: {
        code: 'CONFIGURATION_ERROR',
        status: 500,
        message: 'Server configuration error',
        suggestion: 'Please contact support'
      }
    };
  }

  // Create a standardized error response following shared knowledge format
  create(errorKey, customMessage = null, details = null, requestId = null, additionalMetadata = {}) {
    const errorConfig = this.commonErrors[errorKey];
    
    if (!errorConfig) {
      // Fallback for unknown error keys
      return this.create('INTERNAL_ERROR', customMessage || `Unknown error: ${errorKey}`, details, requestId, additionalMetadata);
    }

    const response = {
      success: false,
      error: {
        code: errorConfig.code,
        message: customMessage || errorConfig.message,
        suggestion: errorConfig.suggestion
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: requestId || 'unknown',
        service: 'gateway',
        ...additionalMetadata
      }
    };

    // Add details if provided
    if (details) {
      response.error.details = details;
    }

    return {
      response,
      status: errorConfig.status
    };
  }

  // Quick response methods for common scenarios
  unauthorized(message = null, requestId = null) {
    return this.create('TOKEN_MISSING', message, null, requestId);
  }

  forbidden(message = null, requestId = null) {
    return this.create('INSUFFICIENT_PERMISSIONS', message, null, requestId);
  }

  notFound(message = null, requestId = null) {
    return this.create('NOT_FOUND', message, null, requestId);
  }

  validation(details = null, requestId = null) {
    return this.create('MISSING_REQUIRED_FIELD', null, details, requestId);
  }

  rateLimit(type = 'general', requestId = null) {
    const key = `RATE_LIMIT_${type.toUpperCase()}`;
    return this.create(key, null, null, requestId);
  }

  serviceError(serviceName, errorType = 'unavailable', requestId = null) {
    const keyMap = {
      unavailable: 'SERVICE_UNAVAILABLE',
      timeout: 'SERVICE_TIMEOUT',
      circuit: 'CIRCUIT_BREAKER'
    };
    
    const key = keyMap[errorType] || 'SERVICE_UNAVAILABLE';
    const customMessage = this.getServiceSpecificMessage(serviceName, errorType);
    
    return this.create(key, customMessage, null, requestId, {
      targetService: serviceName
    });
  }

  // Service-specific error messages
  getServiceSpecificMessage(serviceName, errorType) {
    const messages = {
      auth: {
        unavailable: 'Authentication service is temporarily unavailable',
        timeout: 'Authentication request timed out',
        circuit: 'Authentication service is experiencing issues'
      },
      comment: {
        unavailable: 'Comment processing service is temporarily unavailable', 
        timeout: 'Comment processing request timed out',
        circuit: 'Comment processing service is experiencing issues'
      },
      industry: {
        unavailable: 'Industry configuration service is temporarily unavailable',
        timeout: 'Industry data request timed out', 
        circuit: 'Industry service is experiencing issues'
      },
      nps: {
        unavailable: 'NPS analytics service is temporarily unavailable',
        timeout: 'NPS analytics request timed out',
        circuit: 'NPS service is experiencing issues'
      }
    };

    return messages[serviceName]?.[errorType];
  }

  // Validation error with field details
  validationWithFields(fieldErrors, requestId = null) {
    const details = Array.isArray(fieldErrors) 
      ? fieldErrors.join(', ')
      : fieldErrors;
      
    return this.create('MISSING_REQUIRED_FIELD', 
      'Request validation failed', 
      details, 
      requestId
    );
  }

  // Create error response for Express middleware
  send(res, errorKey, customMessage = null, details = null, requestId = null, additionalMetadata = {}) {
    const { response, status } = this.create(errorKey, customMessage, details, requestId, additionalMetadata);
    
    // Set security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    
    // Add error tracking headers for development
    if (process.env.NODE_ENV === 'development') {
      res.setHeader('X-Error-Key', errorKey);
      res.setHeader('X-Error-Code', response.error.code);
    }
    
    return res.status(status).json(response);
  }

  // Express middleware for handling async route errors
  asyncHandler(fn) {
    return (req, res, next) => {
      Promise.resolve(fn(req, res, next)).catch(next);
    };
  }

  // Middleware to inject error response utilities into request
  middleware() {
    return (req, res, next) => {
      // Add error response methods to response object
      res.error = {
        send: (errorKey, customMessage = null, details = null, additionalMetadata = {}) => {
          return this.send(res, errorKey, customMessage, details, req.headers['x-request-id'], additionalMetadata);
        },
        unauthorized: (message = null) => {
          return this.send(res, 'TOKEN_MISSING', message, null, req.headers['x-request-id']);
        },
        forbidden: (message = null) => {
          return this.send(res, 'INSUFFICIENT_PERMISSIONS', message, null, req.headers['x-request-id']);
        },
        notFound: (message = null) => {
          return this.send(res, 'NOT_FOUND', message, null, req.headers['x-request-id']);
        },
        validation: (details = null) => {
          return this.send(res, 'MISSING_REQUIRED_FIELD', null, details, req.headers['x-request-id']);
        },
        rateLimit: (type = 'general') => {
          return this.send(res, `RATE_LIMIT_${type.toUpperCase()}`, null, null, req.headers['x-request-id']);
        },
        serviceError: (serviceName, errorType = 'unavailable') => {
          const { response, status } = this.serviceError(serviceName, errorType, req.headers['x-request-id']);
          return res.status(status).json(response);
        }
      };
      
      next();
    };
  }

  // Get error statistics and patterns
  getErrorPatterns() {
    return {
      categories: Object.keys(this.commonErrors).reduce((acc, key) => {
        const error = this.commonErrors[key];
        const category = this.categorizeError(error.code);
        if (!acc[category]) acc[category] = [];
        acc[category].push(key);
        return acc;
      }, {}),
      statusCodes: Object.values(this.commonErrors).reduce((acc, error) => {
        acc[error.status] = (acc[error.status] || 0) + 1;
        return acc;
      }, {}),
      totalErrors: Object.keys(this.commonErrors).length
    };
  }

  // Categorize error by type
  categorizeError(errorCode) {
    if (errorCode.includes('AUTHENTICATION') || errorCode.includes('CREDENTIALS')) {
      return 'authentication';
    } else if (errorCode.includes('PERMISSION') || errorCode.includes('FORBIDDEN')) {
      return 'authorization';
    } else if (errorCode.includes('VALIDATION') || errorCode.includes('REQUIRED')) {
      return 'validation';
    } else if (errorCode.includes('RATE_LIMIT')) {
      return 'rate_limiting';
    } else if (errorCode.includes('SERVICE') || errorCode.includes('TIMEOUT') || errorCode.includes('CIRCUIT')) {
      return 'service';
    } else if (errorCode.includes('NOT_FOUND') || errorCode.includes('METHOD')) {
      return 'resource';
    } else if (errorCode.includes('CORS')) {
      return 'cors';
    } else {
      return 'server';
    }
  }

  // Validate error response format
  isValidErrorResponse(response) {
    return (
      response &&
      typeof response === 'object' &&
      response.success === false &&
      response.error &&
      typeof response.error === 'object' &&
      response.error.code &&
      response.error.message &&
      response.error.suggestion &&
      response.metadata &&
      typeof response.metadata === 'object' &&
      response.metadata.timestamp &&
      response.metadata.requestId &&
      response.metadata.service
    );
  }

  // Convert legacy error objects to standard format
  normalize(error, requestId = null) {
    if (this.isValidErrorResponse(error)) {
      return error;
    }

    // Handle Express/HTTP errors
    if (error.status || error.statusCode) {
      const status = error.status || error.statusCode;
      const errorKey = this.mapStatusToErrorKey(status);
      return this.create(errorKey, error.message, null, requestId).response;
    }

    // Handle validation errors
    if (error.name === 'ValidationError' || error.type === 'validation') {
      return this.create('MISSING_REQUIRED_FIELD', error.message, error.details, requestId).response;
    }

    // Handle JWT errors
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      const errorKey = error.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID';
      return this.create(errorKey, error.message, null, requestId).response;
    }

    // Handle network/proxy errors
    if (error.code) {
      switch (error.code) {
        case 'ECONNREFUSED':
        case 'ENOTFOUND':
          return this.create('SERVICE_UNAVAILABLE', error.message, null, requestId).response;
        case 'ETIMEDOUT':
        case 'ECONNRESET':
          return this.create('SERVICE_TIMEOUT', error.message, null, requestId).response;
        default:
          return this.create('INTERNAL_ERROR', error.message, null, requestId).response;
      }
    }

    // Fallback for unknown errors
    return this.create('INTERNAL_ERROR', error.message || 'An unexpected error occurred', null, requestId).response;
  }

  // Map HTTP status codes to error keys
  mapStatusToErrorKey(status) {
    const statusMap = {
      400: 'MISSING_REQUIRED_FIELD',
      401: 'TOKEN_MISSING',
      403: 'INSUFFICIENT_PERMISSIONS',
      404: 'NOT_FOUND',
      405: 'METHOD_NOT_ALLOWED',
      409: 'VALIDATION_ERROR',
      413: 'PAYLOAD_TOO_LARGE',
      422: 'VALIDATION_ERROR',
      429: 'RATE_LIMIT_GENERAL',
      500: 'INTERNAL_ERROR',
      502: 'SERVICE_UNAVAILABLE',
      503: 'SERVICE_UNAVAILABLE',
      504: 'SERVICE_TIMEOUT'
    };

    return statusMap[status] || 'INTERNAL_ERROR';
  }

  // Helper method for creating user-friendly error messages
  createUserFriendlyMessage(errorCode, context = {}) {
    const templates = {
      AUTHENTICATION_REQUIRED: 'Please sign in to continue',
      INVALID_CREDENTIALS: 'Invalid username or password',
      INSUFFICIENT_PERMISSIONS: context.resource ? `You don't have access to ${context.resource}` : 'Access denied',
      RATE_LIMIT_EXCEEDED: context.retryAfter ? `Please wait ${context.retryAfter} seconds before trying again` : 'Too many requests, please slow down',
      SERVICE_UNAVAILABLE: context.service ? `${context.service} is temporarily down` : 'Service temporarily unavailable',
      VALIDATION_ERROR: context.field ? `Please check the ${context.field} field` : 'Please check your input',
      RESOURCE_NOT_FOUND: context.resource ? `${context.resource} not found` : 'Page not found'
    };

    return templates[errorCode] || 'Something went wrong';
  }
}

// Create singleton instance
const errorResponses = new ErrorResponses();

module.exports = errorResponses;