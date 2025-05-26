// gateway-service/middleware/auth.js
const jwt = require('jsonwebtoken');
const axios = require('axios');

class AuthenticationManager {
  constructor(serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
    this.tokenCache = new Map();
    this.cacheExpiry = 5 * 60 * 1000; // 5 minutes
    
    // Start cache cleanup
    this.startCacheCleanup();
  }

  // Main authentication middleware
  authenticate(options = {}) {
    const { 
      optional = false, 
      skipPaths = ['/health', '/api/status'],
      requireRoles = []
    } = options;

    return async (req, res, next) => {
      // Skip authentication for certain paths
      if (skipPaths.some(path => req.path.startsWith(path))) {
        return next();
      }

      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];

      // Handle missing token
      if (!token) {
        if (optional) {
          req.user = null;
          return next();
        }
        
        return res.status(401).json({
          success: false,
          error: {
            code: 'AUTH_TOKEN_REQUIRED',
            message: 'Please provide a valid authentication token',
            suggestion: 'Include Authorization: Bearer <token> in request headers'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'] || this.generateRequestId(),
            service: 'gateway'
          }
        });
      }

      try {
        // Verify and decode token
        const decoded = await this.verifyToken(token);
        
        if (!decoded) {
          if (optional) {
            req.user = null;
            return next();
          }
          
          return res.status(401).json({
            success: false,
            error: {
              code: 'AUTH_TOKEN_INVALID',
              message: 'Authentication token is invalid or expired',
              suggestion: 'Please login again to get a new token'
            },
            metadata: {
              timestamp: new Date().toISOString(),
              requestId: req.headers['x-request-id'] || this.generateRequestId(),
              service: 'gateway'
            }
          });
        }

        // Check role requirements
        if (requireRoles.length > 0 && !this.hasRequiredRoles(decoded, requireRoles)) {
          return res.status(403).json({
            success: false,
            error: {
              code: 'INSUFFICIENT_PERMISSIONS',
              message: 'You do not have the required permissions for this resource',
              details: `Required roles: ${requireRoles.join(', ')}`
            },
            metadata: {
              timestamp: new Date().toISOString(),
              requestId: req.headers['x-request-id'] || this.generateRequestId(),
              service: 'gateway'
            }
          });
        }

        // Attach user info to request (following shared knowledge User interface)
        req.user = {
          id: decoded.userId || decoded.id,
          email: decoded.email,
          firstName: decoded.firstName,
          lastName: decoded.lastName,
          company: decoded.company,
          industry: decoded.industry,
          createdAt: decoded.createdAt,
          updatedAt: decoded.updatedAt,
          roles: decoded.roles || []
        };
        
        req.token = token;
        
        // Add user context for logging
        req.userContext = {
          userId: req.user.id,
          email: req.user.email,
          roles: req.user.roles
        };

        // Add service-to-service auth headers for forwarding
        req.serviceHeaders = {
          'Authorization': `Bearer ${token}`,
          'X-Service-Name': 'gateway',
          'X-Request-ID': req.headers['x-request-id'] || this.generateRequestId()
        };

        next();
      } catch (error) {
        console.error('Authentication error:', {
          timestamp: new Date().toISOString(),
          level: 'error',
          service: 'gateway',
          message: 'Authentication failed',
          error: {
            name: error.name,
            message: error.message,
            stack: error.stack
          },
          metadata: {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            path: req.path
          }
        });
        
        if (optional) {
          req.user = null;
          return next();
        }
        
        return res.status(401).json({
          success: false,
          error: {
            code: 'AUTH_FAILED',
            message: 'Failed to authenticate user',
            suggestion: 'Please check your authentication token and try again'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'] || this.generateRequestId(),
            service: 'gateway'
          }
        });
      }
    };
  }

  // Verify JWT token with caching and remote validation
  async verifyToken(token) {
    // Check cache first
    const cached = this.tokenCache.get(token);
    if (cached && cached.expiry > Date.now()) {
      return cached.decoded;
    }

    try {
      // First try local JWT verification
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Validate token structure according to shared knowledge
      if (!this.isValidTokenStructure(decoded)) {
        console.warn('Token structure invalid:', {
          timestamp: new Date().toISOString(),
          level: 'warn',
          service: 'gateway',
          message: 'Invalid token structure detected'
        });
        return null;
      }
      
      // If we have an auth service, verify with it
      const authService = this.serviceRegistry?.getService('auth');
      if (authService && authService.status === 'healthy') {
        const verified = await this.verifyWithAuthService(token, authService);
        if (verified) {
          // Cache the result
          this.tokenCache.set(token, {
            decoded: verified,
            expiry: Date.now() + this.cacheExpiry
          });
          return verified;
        }
      }

      // Cache local verification result
      this.tokenCache.set(token, {
        decoded,
        expiry: Date.now() + this.cacheExpiry
      });
      
      return decoded;
    } catch (error) {
      console.warn('Token verification failed:', {
        timestamp: new Date().toISOString(),
        level: 'warn',
        service: 'gateway',
        message: 'Token verification failed',
        error: {
          name: error.name,
          message: error.message
        }
      });
      return null;
    }
  }

  // Validate token structure according to shared knowledge AuthToken interface
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

  // Verify token with auth service
  async verifyWithAuthService(token, authService) {
    try {
      const response = await axios.get(`${authService.url}/api/auth/verify`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-Service-Name': 'gateway',
          'X-Request-ID': this.generateRequestId(),
          'User-Agent': 'Gateway-Auth-Verification/1.0'
        },
        timeout: 5000
      });

      if (response.status === 200 && response.data.success && response.data.data.user) {
        return response.data.data.user;
      }
      
      return null;
    } catch (error) {
      console.warn('Auth service verification failed:', {
        timestamp: new Date().toISOString(),
        level: 'warn',
        service: 'gateway',
        message: 'Auth service verification failed',
        error: {
          name: error.name,
          message: error.message
        },
        metadata: {
          authServiceUrl: authService.url
        }
      });
      return null;
    }
  }

  // Check if user has required roles
  hasRequiredRoles(user, requiredRoles) {
    if (requiredRoles.length === 0) return true;
    
    const userRoles = user.roles || [];
    return requiredRoles.some(role => userRoles.includes(role));
  }

  // API key authentication middleware
  authenticateApiKey(req, res, next) {
    const apiKey = req.headers[process.env.API_KEY_HEADER || 'x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'API_KEY_REQUIRED',
          message: 'Please provide a valid API key',
          suggestion: `Include ${process.env.API_KEY_HEADER || 'x-api-key'} header in your request`
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'] || this.generateRequestId(),
          service: 'gateway'
        }
      });
    }

    // Basic API key validation
    if (!this.isValidApiKey(apiKey)) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'API_KEY_INVALID',
          message: 'The provided API key is invalid',
          suggestion: 'Ensure your API key follows the correct format (sk-...)'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'] || this.generateRequestId(),
          service: 'gateway'
        }
      });
    }

    // Store API key for forwarding to services
    req.apiKey = apiKey;
    req.authType = 'api_key';
    
    // Add service headers for API key auth
    req.serviceHeaders = {
      [process.env.API_KEY_HEADER || 'x-api-key']: apiKey,
      'X-Service-Name': 'gateway',
      'X-Request-ID': req.headers['x-request-id'] || this.generateRequestId()
    };
    
    next();
  }

  // Validate API key format (Claude API key format)
  isValidApiKey(apiKey) {
    return typeof apiKey === 'string' && 
           apiKey.length >= 10 && 
           apiKey.startsWith('sk-');
  }

  // Role-based access control middleware
  requireRole(roles) {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'AUTH_REQUIRED',
            message: 'You must be authenticated to access this resource',
            suggestion: 'Please login and include your authentication token'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'] || this.generateRequestId(),
            service: 'gateway'
          }
        });
      }

      const userRoles = req.user.roles || [];
      const hasRole = Array.isArray(roles) 
        ? roles.some(role => userRoles.includes(role))
        : userRoles.includes(roles);

      if (!hasRole) {
        return res.status(403).json({
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'You do not have the required role to access this resource',
            details: `Required roles: ${Array.isArray(roles) ? roles.join(', ') : roles}`
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'] || this.generateRequestId(),
            service: 'gateway',
            userRoles: userRoles
          }
        });
      }

      next();
    };
  }

  // Admin access middleware
  requireAdmin() {
    return this.requireRole(['admin', 'super_admin']);
  }

  // Service-to-service authentication
  authenticateService(req, res, next) {
    const serviceToken = req.headers['x-service-token'];
    const serviceId = req.headers['x-service-id'];
    
    if (!serviceToken || !serviceId) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'SERVICE_AUTH_REQUIRED',
          message: 'Service-to-service requests require valid service credentials',
          suggestion: 'Include X-Service-Token and X-Service-ID headers'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'] || this.generateRequestId(),
          service: 'gateway'
        }
      });
    }

    // Verify service token
    const expectedToken = this.generateServiceToken(serviceId);
    if (serviceToken !== expectedToken) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'SERVICE_AUTH_INVALID',
          message: 'Service authentication failed',
          suggestion: 'Verify your service credentials'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'] || this.generateRequestId(),
          service: 'gateway'
        }
      });
    }

    req.serviceAuth = {
      serviceId,
      authenticated: true
    };

    next();
  }

  // Generate service token for inter-service communication
  generateServiceToken(serviceId) {
    const secret = process.env.SERVICE_SECRET || 'default-service-secret';
    return jwt.sign(
      { 
        serviceId, 
        type: 'service',
        iat: Math.floor(Date.now() / 1000)
      }, 
      secret,
      { expiresIn: '1h' }
    );
  }

  // User session middleware
  attachUserSession(req, res, next) {
    if (req.user) {
      // Enhance request with user session info (following shared knowledge)
      req.session = {
        userId: req.user.id,
        email: req.user.email,
        roles: req.user.roles,
        industry: req.user.industry,
        company: req.user.company,
        sessionStart: Date.now()
      };
    }
    
    next();
  }

  // Generate request ID for tracing
  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Start cache cleanup process
  startCacheCleanup() {
    setInterval(() => {
      this.cleanupTokenCache();
    }, 60000); // Cleanup every minute
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
      console.log(`Cleaned ${cleaned} expired tokens from cache`, {
        timestamp: new Date().toISOString(),
        level: 'info',
        service: 'gateway',
        message: 'Token cache cleanup completed',
        metadata: {
          tokensRemoved: cleaned,
          remainingTokens: this.tokenCache.size
        }
      });
    }
  }

  // Get authentication statistics
  getAuthStats() {
    return {
      cachedTokens: this.tokenCache.size,
      cacheExpiryMs: this.cacheExpiry,
      timestamp: new Date().toISOString()
    };
  }

  // Clear all cached tokens (for security reasons)
  clearTokenCache() {
    const size = this.tokenCache.size;
    this.tokenCache.clear();
    
    console.log(`Cleared all tokens from cache`, {
      timestamp: new Date().toISOString(),
      level: 'info',
      service: 'gateway',
      message: 'Token cache cleared',
      metadata: {
        tokensRemoved: size
      }
    });
  }

  // Middleware to add request tracing headers
  addTracingHeaders() {
    return (req, res, next) => {
      // Generate or use existing request ID
      const requestId = req.headers['x-request-id'] || this.generateRequestId();
      const traceId = req.headers['x-trace-id'] || `trace_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      
      // Set headers for request tracking
      req.headers['x-request-id'] = requestId;
      req.headers['x-trace-id'] = traceId;
      req.headers['x-service-name'] = 'gateway';
      
      // Add to response headers for client tracking
      res.setHeader('X-Request-ID', requestId);
      res.setHeader('X-Trace-ID', traceId);
      
      next();
    };
  }
}

module.exports = AuthenticationManager;