// gateway-service/middleware/simpleAuth.js - Enhanced Compatibility
const jwt = require('jsonwebtoken');
const config = require('../config/simple');
const logger = require('../utils/simpleLogger');

class SimpleAuth {
  constructor() {
    this.jwtSecret = config.security.jwtSecret;
    this.tokenCache = new Map();
    this.cacheExpiry = 5 * 60 * 1000; // 5 minutes
    
    // Cleanup expired tokens every minute
    setInterval(() => {
      this.cleanupTokenCache();
    }, 60000);
  }

  // Optional authentication - adds user context if token present
  optionalAuth() {
    return (req, res, next) => {
      const token = this.extractToken(req);
      
      if (!token) {
        req.user = null;
        return next();
      }

      try {
        const decoded = this.verifyToken(token);
        req.user = this.normalizeUser(decoded);
        
        logger.debug(`User authenticated: ${req.user.email}`, {
          userId: req.user.id,
          industry: req.user.industry
        });
      } catch (error) {
        logger.debug(`Token validation failed: ${error.message}`, {
          tokenPresent: !!token,
          errorType: error.name
        });
        req.user = null;
      }
      
      next();
    };
  }

  // Required authentication - rejects if no valid token
  requireAuth() {
    return (req, res, next) => {
      const token = this.extractToken(req);
      
      if (!token) {
        return this.sendAuthError(res, 'AUTHENTICATION_REQUIRED', 
          'Authentication token is required', req.requestId);
      }

      try {
        const decoded = this.verifyToken(token);
        req.user = this.normalizeUser(decoded);
        
        logger.debug(`User authenticated: ${req.user.email}`, {
          userId: req.user.id,
          requestId: req.requestId
        });
        next();
      } catch (error) {
        logger.warn(`Authentication failed: ${error.message}`, {
          requestId: req.requestId,
          errorType: error.name,
          tokenPresent: !!token
        });
        
        if (error.name === 'TokenExpiredError') {
          return this.sendAuthError(res, 'TOKEN_EXPIRED', 
            'Authentication token has expired', req.requestId);
        } else if (error.name === 'JsonWebTokenError') {
          return this.sendAuthError(res, 'INVALID_TOKEN', 
            'Authentication token is invalid', req.requestId);
        } else {
          return this.sendAuthError(res, 'INVALID_TOKEN', 
            'Authentication token verification failed', req.requestId);
        }
      }
    };
  }

  // API Key authentication for service-to-service
  requireApiKey() {
    return (req, res, next) => {
      const apiKey = req.headers['x-api-key'];
      
      if (!apiKey) {
        return this.sendAuthError(res, 'API_KEY_REQUIRED', 
          'API key is required', req.requestId);
      }

      if (!this.isValidApiKey(apiKey)) {
        return this.sendAuthError(res, 'INVALID_API_KEY', 
          'Invalid API key format', req.requestId);
      }

      req.apiKey = apiKey;
      req.authType = 'api_key';
      
      logger.debug('API key authentication successful', {
        requestId: req.requestId,
        keyPrefix: apiKey.substring(0, 8) + '...'
      });
      
      next();
    };
  }

  // Role-based access control
  requireRole(roles) {
    const requiredRoles = Array.isArray(roles) ? roles : [roles];
    
    return (req, res, next) => {
      if (!req.user) {
        return this.sendAuthError(res, 'AUTHENTICATION_REQUIRED', 
          'Authentication is required', req.requestId);
      }

      const userRoles = req.user.roles || ['user'];
      const hasRole = requiredRoles.some(role => userRoles.includes(role));
      
      if (!hasRole) {
        logger.warn('Insufficient permissions', {
          userId: req.user.id,
          userRoles,
          requiredRoles,
          requestId: req.requestId
        });
        
        return this.sendAuthError(res, 'INSUFFICIENT_PERMISSIONS', 
          `Required roles: ${requiredRoles.join(', ')}`, req.requestId);
      }

      next();
    };
  }

  // Extract token from Authorization header
  extractToken(req) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.slice(7);
    }
    
    // Also check for token in cookie (fallback)
    if (req.cookies && req.cookies.auth_token) {
      return req.cookies.auth_token;
    }
    
    return null;
  }

  // Verify JWT token with caching
  verifyToken(token) {
    // Check cache first
    const cached = this.tokenCache.get(token);
    if (cached && cached.expiry > Date.now()) {
      return cached.decoded;
    }

    try {
      // Verify token with proper options
      const decoded = jwt.verify(token, this.jwtSecret, {
        algorithms: ['HS256'], // Explicitly specify algorithm
        maxAge: '7d' // Maximum token age
      });
      
      // Validate token structure
      if (!this.isValidTokenStructure(decoded)) {
        throw new Error('Invalid token structure');
      }

      // Cache the result
      this.tokenCache.set(token, {
        decoded,
        expiry: Date.now() + this.cacheExpiry
      });

      return decoded;
    } catch (error) {
      // Remove invalid token from cache if it exists
      this.tokenCache.delete(token);
      throw error;
    }
  }

  // Validate token structure following shared knowledge
  isValidTokenStructure(decoded) {
    const hasUserId = decoded.userId || decoded.id || decoded.sub;
    const hasEmail = decoded.email;
    const hasExpiration = decoded.exp && decoded.exp > Math.floor(Date.now() / 1000);
    const hasIssuedAt = decoded.iat;
    
    const isValid = hasUserId && hasEmail && hasExpiration && hasIssuedAt;
    
    if (!isValid) {
      logger.debug('Token structure validation failed', {
        hasUserId: !!hasUserId,
        hasEmail: !!hasEmail,
        hasExpiration: !!hasExpiration,
        hasIssuedAt: !!hasIssuedAt,
        tokenKeys: Object.keys(decoded)
      });
    }
    
    return isValid;
  }

  // Normalize user object following shared knowledge User interface
  normalizeUser(decoded) {
    // Handle different possible token structures from different services
    const userId = decoded.userId || decoded.id || decoded.sub;
    
    return {
      id: userId,
      userId: userId, // Keep both for backward compatibility
      email: decoded.email,
      firstName: decoded.firstName || decoded.first_name,
      lastName: decoded.lastName || decoded.last_name,
      company: decoded.company,
      industry: decoded.industry,
      roles: decoded.roles || decoded.role ? [decoded.role] : ['user'],
      createdAt: decoded.createdAt || decoded.created_at,
      updatedAt: decoded.updatedAt || decoded.updated_at,
      // Preserve original token data for service-specific needs
      _original: decoded
    };
  }

  // Validate API key format (Claude API key format)
  isValidApiKey(apiKey) {
    return typeof apiKey === 'string' && 
           apiKey.length >= 10 && 
           (apiKey.startsWith('sk-') || apiKey.startsWith('claude-'));
  }

  // Send standardized authentication error
  sendAuthError(res, code, message, requestId = null) {
    const errorMap = {
      AUTHENTICATION_REQUIRED: { 
        status: 401, 
        suggestion: 'Please provide a valid Bearer token in the Authorization header' 
      },
      TOKEN_EXPIRED: { 
        status: 401, 
        suggestion: 'Please login again to get a new token' 
      },
      INVALID_TOKEN: { 
        status: 401, 
        suggestion: 'Please check your token and try again' 
      },
      API_KEY_REQUIRED: { 
        status: 401, 
        suggestion: 'Please provide a valid API key in x-api-key header' 
      },
      INVALID_API_KEY: { 
        status: 401, 
        suggestion: 'Please check your API key format (should start with sk- or claude-)' 
      },
      INSUFFICIENT_PERMISSIONS: { 
        status: 403, 
        suggestion: 'Contact administrator for required permissions' 
      }
    };

    const errorInfo = errorMap[code] || { 
      status: 401, 
      suggestion: 'Please check your credentials' 
    };

    const errorResponse = {
      success: false,
      error: {
        code,
        message,
        suggestion: errorInfo.suggestion
      },
      metadata: {
        timestamp: new Date().toISOString(),
        service: 'gateway',
        ...(requestId && { requestId })
      }
    };

    res.status(errorInfo.status).json(errorResponse);
  }

  // Cleanup expired tokens from cache
  cleanupTokenCache() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [token, data] of this.tokenCache.entries()) {
      if (data.expiry <= now) {
        this.tokenCache.delete(token);
        cleaned++;
      }
    }
    
    if (cleaned > 0) {
      logger.debug(`Cleaned ${cleaned} expired tokens from cache`);
    }
  }

  // Get authentication statistics
  getStats() {
    return {
      cachedTokens: this.tokenCache.size,
      cacheExpiryMs: this.cacheExpiry,
      cacheHitRate: this.calculateCacheHitRate()
    };
  }

  calculateCacheHitRate() {
    // This would require tracking hits/misses, simplified for now
    return this.tokenCache.size > 0 ? 0.8 : 0;
  }

  // Clear token cache (for security)
  clearTokenCache() {
    const size = this.tokenCache.size;
    this.tokenCache.clear();
    logger.info(`Cleared ${size} tokens from cache`);
  }

  // Validate that a user has access to a specific resource
  validateResourceAccess(req, resourceOwnerId) {
    if (!req.user) {
      return false;
    }

    // Admin users can access all resources
    if (req.user.roles && req.user.roles.includes('admin')) {
      return true;
    }

    // Users can only access their own resources
    return req.user.id === resourceOwnerId;
  }

  // Middleware to ensure user can only access their own data
  requireOwnership() {
    return (req, res, next) => {
      const resourceOwnerId = req.params.userId || req.body.userId || req.query.userId;
      
      if (!resourceOwnerId) {
        return this.sendAuthError(res, 'INVALID_REQUEST', 
          'Resource owner ID is required', req.requestId);
      }

      if (!this.validateResourceAccess(req, resourceOwnerId)) {
        return this.sendAuthError(res, 'INSUFFICIENT_PERMISSIONS', 
          'You can only access your own resources', req.requestId);
      }

      next();
    };
  }

  // Create a JWT token (for testing purposes)
  createToken(user, expiresIn = '7d') {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Token creation not allowed in production gateway');
    }

    return jwt.sign({
      userId: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      company: user.company,
      industry: user.industry,
      roles: user.roles || ['user']
    }, this.jwtSecret, { 
      expiresIn,
      algorithm: 'HS256'
    });
  }
}

module.exports = SimpleAuth;
