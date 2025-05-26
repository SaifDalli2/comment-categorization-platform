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
          error: 'Authentication Required',
          message: 'Please provide a valid authentication token',
          timestamp: new Date().toISOString()
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
            error: 'Invalid Token',
            message: 'Authentication token is invalid or expired',
            timestamp: new Date().toISOString()
          });
        }

        // Check role requirements
        if (requireRoles.length > 0 && !this.hasRequiredRoles(decoded, requireRoles)) {
          return res.status(403).json({
            error: 'Insufficient Permissions', 
            message: 'You do not have the required permissions for this resource',
            requiredRoles: requireRoles,
            timestamp: new Date().toISOString()
          });
        }

        // Attach user info to request
        req.user = decoded;
        req.token = token;
        
        // Add user context to logs
        req.userContext = {
          userId: decoded.userId || decoded.id,
          email: decoded.email,
          roles: decoded.roles || []
        };

        next();
      } catch (error) {
        console.error('Authentication error:', error.message);
        
        if (optional) {
          req.user = null;
          return next();
        }
        
        return res.status(401).json({
          error: 'Authentication Failed',
          message: 'Failed to authenticate user',
          timestamp: new Date().toISOString()
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
      console.warn('Token verification failed:', error.message);
      return null;
    }
  }

  // Verify token with auth service
  async verifyWithAuthService(token, authService) {
    try {
      const response = await axios.get(`${authService.url}/api/auth/verify`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'User-Agent': 'Gateway-Auth-Verification/1.0'
        },
        timeout: 5000
      });

      if (response.status === 200 && response.data.user) {
        return response.data.user;
      }
      
      return null;
    } catch (error) {
      console.warn('Auth service verification failed:', error.message);
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
        error: 'API Key Required',
        message: 'Please provide a valid API key',
        header: process.env.API_KEY_HEADER || 'x-api-key',
        timestamp: new Date().toISOString()
      });
    }

    // Basic API key validation
    if (!this.isValidApiKey(apiKey)) {
      return res.status(401).json({
        error: 'Invalid API Key',
        message: 'The provided API key is invalid',
        timestamp: new Date().toISOString()
      });
    }

    // Store API key for forwarding to services
    req.apiKey = apiKey;
    req.authType = 'api_key';
    
    next();
  }

  // Validate API key format
  isValidApiKey(apiKey) {
    // Claude API key format validation
    return typeof apiKey === 'string' && 
           apiKey.length >= 10 && 
           apiKey.startsWith('sk-');
  }

  // Role-based access control middleware
  requireRole(roles) {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({
          error: 'Authentication Required',
          message: 'You must be authenticated to access this resource',
          timestamp: new Date().toISOString()
        });
      }

      const userRoles = req.user.roles || [];
      const hasRole = Array.isArray(roles) 
        ? roles.some(role => userRoles.includes(role))
        : userRoles.includes(roles);

      if (!hasRole) {
        return res.status(403).json({
          error: 'Insufficient Permissions',
          message: 'You do not have the required role to access this resource',
          requiredRoles: Array.isArray(roles) ? roles : [roles],
          userRoles: userRoles,
          timestamp: new Date().toISOString()
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
        error: 'Service Authentication Required',
        message: 'Service-to-service requests require valid service credentials',
        timestamp: new Date().toISOString()
      });
    }

    // Verify service token
    const expectedToken = this.generateServiceToken(serviceId);
    if (serviceToken !== expectedToken) {
      return res.status(401).json({
        error: 'Invalid Service Credentials',
        message: 'Service authentication failed',
        timestamp: new Date().toISOString()
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
      // Enhance request with user session info
      req.session = {
        userId: req.user.userId || req.user.id,
        email: req.user.email,
        roles: req.user.roles || [],
        industry: req.user.industry,
        company: req.user.company,
        sessionStart: Date.now()
      };
    }
    
    next();
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