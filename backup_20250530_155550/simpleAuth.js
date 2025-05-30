// gateway-service/middleware/simpleAuth.js
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
        
        logger.debug(`User authenticated: ${req.user.email}`);
      } catch (error) {
        logger.debug(`Token validation failed: ${error.message}`);
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
          'Authentication token is required');
      }

      try {
        const decoded = this.verifyToken(token);
        req.user = this.normalizeUser(decoded);
        
        logger.debug(`User authenticated: ${req.user.email}`);
        next();
      } catch (error) {
        logger.debug(`Authentication failed: ${error.message}`);
        
        if (error.name === 'TokenExpiredError') {
          return this.sendAuthError(res, 'TOKEN_EXPIRED', 
            'Authentication token has expired');
        } else {
          return this.sendAuthError(res, 'INVALID_TOKEN', 
            'Authentication token is invalid');
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
          'API key is required');
      }

      if (!this.isValidApiKey(apiKey)) {
        return this.sendAuthError(res, 'INVALID_API_KEY', 
          'Invalid API key format');
      }

      req.apiKey = apiKey;
      req.authType = 'api_key';
      next();
    };
  }

  // Role-based access control
  requireRole(roles) {
    const requiredRoles = Array.isArray(roles) ? roles : [roles];
    
    return (req, res, next) => {
      if (!req.user) {
        return this.sendAuthError(res, 'AUTHENTICATION_REQUIRED', 
          'Authentication is required');
      }

      const userRoles = req.user.roles || [];
      const hasRole = requiredRoles.some(role => userRoles.includes(role));
      
      if (!hasRole) {
        return this.sendAuthError(res, 'INSUFFICIENT_PERMISSIONS', 
          `Required roles: ${requiredRoles.join(', ')}`);
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
    return null;
  }

  // Verify JWT token with caching
  verifyToken(token) {
    // Check cache first
    const cached = this.tokenCache.get(token);
    if (cached && cached.expiry > Date.now()) {
      return cached.decoded;
    }

    // Verify token
    const decoded = jwt.verify(token, this.jwtSecret);
    
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
  }

  // Validate token structure following shared knowledge
  isValidTokenStructure(decoded) {
    return (
      decoded &&
      (decoded.userId || decoded.id) &&
      decoded.email &&
      decoded.exp &&
      decoded.iat &&
      decoded.exp > Math.floor(Date.now() / 1000)
    );
  }

  // Normalize user object following shared knowledge User interface
  normalizeUser(decoded) {
    return {
      id: decoded.userId || decoded.id,
      email: decoded.email,
      firstName: decoded.firstName,
      lastName: decoded.lastName,
      company: decoded.company,
      industry: decoded.industry,
      roles: decoded.roles || ['user'],
      createdAt: decoded.createdAt,
      updatedAt: decoded.updatedAt
    };
  }

  // Validate API key format (Claude API key format)
  isValidApiKey(apiKey) {
    return typeof apiKey === 'string' && 
           apiKey.length >= 10 && 
           apiKey.startsWith('sk-');
  }

  // Send standardized authentication error
  sendAuthError(res, code, message) {
    const errorMap = {
      AUTHENTICATION_REQUIRED: { status: 401, suggestion: 'Please provide a valid Bearer token' },
      TOKEN_EXPIRED: { status: 401, suggestion: 'Please login again to get a new token' },
      INVALID_TOKEN: { status: 401, suggestion: 'Please check your token and try again' },
      API_KEY_REQUIRED: { status: 401, suggestion: 'Please provide a valid API key in x-api-key header' },
      INVALID_API_KEY: { status: 401, suggestion: 'Please check your API key format (should start with sk-)' },
      INSUFFICIENT_PERMISSIONS: { status: 403, suggestion: 'Contact administrator for required permissions' }
    };

    const errorInfo = errorMap[code] || { status: 401, suggestion: 'Please check your credentials' };

    res.status(errorInfo.status).json({
      success: false,
      error: {
        code,
        message,
        suggestion: errorInfo.suggestion
      },
      metadata: {
        timestamp: new Date().toISOString(),
        service: 'gateway'
      }
    });
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
      cacheExpiryMs: this.cacheExpiry
    };
  }

  // Clear token cache (for security)
  clearTokenCache() {
    const size = this.tokenCache.size;
    this.tokenCache.clear();
    logger.info(`Cleared ${size} tokens from cache`);
  }
}

module.exports = SimpleAuth;