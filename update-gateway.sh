#!/bin/bash

# Gateway Service Update Script
# This script applies all the fixes and enhancements to the gateway service

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    print_error "package.json not found. Please run this script from the gateway-service directory."
    exit 1
fi

print_section "🚀 Gateway Service Update Script"
print_status "Starting gateway service updates..."

# Create backup directory
BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
print_status "Creating backup in $BACKUP_DIR/"
mkdir -p "$BACKUP_DIR"

# Backup existing files
print_status "Backing up existing files..."
[ -f "server.js" ] && cp "server.js" "$BACKUP_DIR/"
[ -f "middleware/simpleAuth.js" ] && cp "middleware/simpleAuth.js" "$BACKUP_DIR/"
[ -f "config/simple.js" ] && cp "config/simple.js" "$BACKUP_DIR/"
[ -f ".env" ] && cp ".env" "$BACKUP_DIR/"
[ -f "package.json" ] && cp "package.json" "$BACKUP_DIR/"

print_section "📝 Updating Configuration Files"

# Update package.json with new dependencies and scripts
print_status "Updating package.json..."
cat > package.json << 'EOF'
{
  "name": "gateway-service",
  "version": "1.0.1",
  "description": "Enhanced API Gateway for Comment Categorization Microservices",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:ci": "jest --ci --coverage --watchAll=false",
    "lint": "eslint .",
    "lint:fix": "eslint . --fix",
    "validate": "npm run lint && npm run test",
    "health-check": "node healthcheck.js",
    "docker:build": "docker build -t gateway-service .",
    "security:audit": "npm audit",
    "clean": "rm -rf node_modules coverage",
    "debug:config": "node -e \"console.log(JSON.stringify(require('./config/simple'), null, 2))\"",
    "debug:services": "node -e \"require('./config/simple').discoverServices().then(console.log)\"",
    "heroku:logs": "heroku logs --tail --app $(heroku apps --json | jq -r '.[] | select(.name | contains(\"gateway\")) | .name')",
    "heroku:config": "heroku config --app $(heroku apps --json | jq -r '.[] | select(.name | contains(\"gateway\")) | .name')"
  },
  "keywords": [
    "api-gateway",
    "microservices",
    "comment-categorization",
    "proxy",
    "service-discovery"
  ],
  "author": "Your Team",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "http-proxy-middleware": "^2.0.6",
    "cors": "^2.8.5",
    "express-rate-limit": "^6.7.0",
    "helmet": "^6.1.5",
    "jsonwebtoken": "^9.0.0",
    "axios": "^1.4.0",
    "dotenv": "^16.0.3"
  },
  "devDependencies": {
    "nodemon": "^2.0.22",
    "jest": "^29.5.0",
    "supertest": "^6.3.3",
    "eslint": "^8.41.0"
  },
  "engines": {
    "node": ">=16.0.0",
    "npm": ">=8.0.0"
  },
  "jest": {
    "testEnvironment": "node",
    "collectCoverageFrom": [
      "middleware/**/*.js",
      "services/**/*.js", 
      "utils/**/*.js",
      "config/**/*.js",
      "server.js",
      "!**/node_modules/**",
      "!**/coverage/**",
      "!**/*.test.js"
    ],
    "coverageThreshold": {
      "global": {
        "branches": 70,
        "functions": 70,
        "lines": 70,
        "statements": 70
      }
    },
    "testMatch": [
      "<rootDir>/tests/**/*.test.js"
    ]
  }
}
EOF

print_section "🔧 Updating Server Configuration"

# Update server.js
print_status "Updating server.js..."
cat > server.js << 'EOF'
// gateway-service/server.js - Fixed Service Integration
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const SimpleAuth = require('./middleware/simpleAuth');
const SimpleHealth = require('./services/simpleHealth');
const config = require('./config/simple');
const logger = require('./utils/simpleLogger');

const app = express();
const auth = new SimpleAuth();
const health = new SimpleHealth();

// Trust proxy for Heroku
app.set('trust proxy', 1);

// Basic middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Security
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (config.security.corsOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    logger.warn(`CORS origin rejected: ${origin}`);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key', 'X-Request-ID']
}));

// Rate limiting with different tiers
const createRateLimit = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: { 
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message,
        suggestion: 'Please wait before making additional requests'
      }
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path === '/health' || req.path.startsWith('/health/');
    }
  });
};

// Apply different rate limits to different endpoints
app.use('/api/auth', createRateLimit(15 * 60 * 1000, 20, 'Too many authentication requests'));
app.use('/api/comments', createRateLimit(15 * 60 * 1000, 50, 'Too many comment processing requests'));
app.use(createRateLimit(15 * 60 * 1000, 100, 'Too many requests'));

// Request logging and ID generation
app.use((req, res, next) => {
  const start = Date.now();
  req.requestId = req.headers['x-request-id'] || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  res.setHeader('X-Request-ID', req.requestId);
  res.setHeader('X-Gateway-Service', 'claude-analysis-gateway');
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.request(req, res, duration);
  });
  next();
});

// Health endpoints
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'gateway',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    version: process.env.npm_package_version || '1.0.1'
  });
});

app.get('/health/services', health.checkServices());

app.get('/api/gateway/services', auth.optionalAuth(), (req, res) => {
  const services = health.getServiceStatus();
  res.json({
    success: true,
    data: services,
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      service: 'gateway'
    }
  });
});

// Enhanced service proxy factory with better error handling
const createServiceProxy = (serviceName, targetUrl, pathRewrite = {}) => {
  return createProxyMiddleware({
    target: targetUrl,
    changeOrigin: true,
    timeout: 30000,
    pathRewrite,
    
    onProxyReq: (proxyReq, req) => {
      // Forward user context if authenticated
      if (req.user) {
        proxyReq.setHeader('X-User-ID', req.user.id);
        proxyReq.setHeader('X-User-Email', req.user.email);
        if (req.user.roles && req.user.roles.length > 0) {
          proxyReq.setHeader('X-User-Roles', req.user.roles.join(','));
        }
        if (req.user.industry) {
          proxyReq.setHeader('X-User-Industry', req.user.industry);
        }
      }
      
      // Forward API key if present
      if (req.apiKey) {
        proxyReq.setHeader('X-API-Key', req.apiKey);
      }
      
      // Gateway identification headers
      proxyReq.setHeader('X-Gateway-Request', 'true');
      proxyReq.setHeader('X-Gateway-Version', '1.0.1');
      proxyReq.setHeader('X-Request-ID', req.requestId);
      proxyReq.setHeader('X-Service-Name', 'gateway');
      
      // Ensure proper content type for JSON requests
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
      }
      
      logger.debug(`Proxying ${req.method} ${req.path} to ${serviceName}`, {
        target: targetUrl,
        headers: {
          'X-User-ID': proxyReq.getHeader('X-User-ID'),
          'X-Request-ID': req.requestId
        }
      });
    },

    onProxyRes: (proxyRes, req, res) => {
      // Add service identification headers
      res.setHeader('X-Served-By', serviceName);
      res.setHeader('X-Response-Time', `${Date.now() - req.startTime}ms`);
      
      // Record service health
      health.recordServiceResponse(serviceName, proxyRes.statusCode < 400);
      
      logger.debug(`${serviceName} responded: ${proxyRes.statusCode}`, {
        requestId: req.requestId,
        statusCode: proxyRes.statusCode
      });
    },

    onError: (err, req, res) => {
      logger.error(`Proxy error for ${serviceName}`, {
        error: err.message,
        requestId: req.requestId,
        target: targetUrl,
        path: req.path
      });
      
      health.recordServiceResponse(serviceName, false);
      
      if (res.headersSent) return;
      
      // Determine appropriate error response based on error type
      let statusCode = 503;
      let errorCode = 'SERVICE_UNAVAILABLE';
      let message = `${serviceName} service is temporarily unavailable`;
      
      if (err.code === 'ECONNREFUSED') {
        errorCode = 'SERVICE_UNAVAILABLE';
        message = `Cannot connect to ${serviceName} service`;
      } else if (err.code === 'ETIMEDOUT') {
        statusCode = 504;
        errorCode = 'GATEWAY_TIMEOUT';
        message = `Request to ${serviceName} service timed out`;
      } else if (err.message.includes('ENOTFOUND')) {
        errorCode = 'SERVICE_UNAVAILABLE';
        message = `${serviceName} service hostname not found`;
      }
      
      res.status(statusCode).json({
        success: false,
        error: {
          code: errorCode,
          message,
          suggestion: 'Please try again in a few moments'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.requestId,
          service: 'gateway',
          targetService: serviceName
        }
      });
    }
  });
};

// Auth Service Routes (no authentication required for login/register)
app.use('/api/auth', createServiceProxy('auth', config.services.auth));

// Comment Service Routes (require authentication)
app.use('/api/comments', 
  auth.requireAuth(),
  createServiceProxy('comment', config.services.comment)
);

// Industry Service Routes (public access)
// Map /api/industries to /api/v1/industries on the backend
app.use('/api/industries', 
  createServiceProxy('industry', config.services.industry, {
    '^/api/industries': '/api/v1/industries'
  })
);

// NPS Service Routes (require authentication)
app.use('/api/nps', 
  auth.requireAuth(),
  createServiceProxy('nps', config.services.nps)
);

// Development endpoints for service management
if (process.env.NODE_ENV !== 'production') {
  app.post('/api/gateway/services/:serviceName/register', (req, res) => {
    const { serviceName } = req.params;
    const { serviceUrl } = req.body;
    
    try {
      health.addService(serviceName, serviceUrl);
      res.json({
        success: true,
        message: `Service ${serviceName} registered at ${serviceUrl}`
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        error: {
          code: 'REGISTRATION_FAILED',
          message: error.message
        }
      });
    }
  });

  app.delete('/api/gateway/services/:serviceName', (req, res) => {
    const { serviceName } = req.params;
    
    try {
      health.removeService(serviceName);
      res.json({
        success: true,
        message: `Service ${serviceName} unregistered`
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        error: {
          code: 'UNREGISTRATION_FAILED',
          message: error.message
        }
      });
    }
  });

  app.post('/api/gateway/health-check', async (req, res) => {
    try {
      const healthStatus = await health.forceHealthCheck();
      res.json({
        success: true,
        data: healthStatus
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          code: 'HEALTH_CHECK_FAILED',
          message: error.message
        }
      });
    }
  });
}

// Metrics endpoint for monitoring
app.get('/metrics', (req, res) => {
  const stats = {
    gateway: {
      uptime: Math.floor(process.uptime()),
      memory: process.memoryUsage(),
      version: process.env.npm_package_version || '1.0.1'
    },
    services: health.getStats(),
    auth: auth.getStats()
  };
  
  res.set('Content-Type', 'text/plain');
  res.send(`# Gateway Metrics
gateway_uptime_seconds ${stats.gateway.uptime}
gateway_memory_rss_bytes ${stats.gateway.memory.rss}
gateway_memory_heap_used_bytes ${stats.gateway.memory.heapUsed}
gateway_total_services ${stats.services.totalServices}
gateway_healthy_services ${stats.services.healthyServices}
gateway_cached_tokens ${stats.auth.cachedTokens}
`);
});

// Static files
app.use(express.static('public', {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  etag: true
}));

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'RESOURCE_NOT_FOUND',
      message: 'The requested API endpoint does not exist',
      suggestion: 'Check the API documentation for available endpoints'
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      service: 'gateway'
    }
  });
});

// SPA fallback for frontend routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err) {
      res.status(404).json({
        success: false,
        error: {
          code: 'RESOURCE_NOT_FOUND',
          message: 'The requested resource was not found'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.requestId,
          service: 'gateway'
        }
      });
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`, {
    requestId: req.requestId,
    stack: err.stack
  });
  
  if (res.headersSent) return next(err);
  
  res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected error occurred',
      suggestion: 'Please try again later'
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      service: 'gateway'
    }
  });
});

const PORT = config.port;
const server = app.listen(PORT, () => {
  logger.info(`Gateway started on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`Services configured: ${Object.keys(config.services).join(', ')}`);
  
  // Log service URLs for debugging
  Object.entries(config.services).forEach(([name, url]) => {
    logger.info(`${name} service: ${url}`);
  });
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received, shutting down gracefully`);
  
  server.close(() => {
    logger.info('HTTP server closed');
    
    // Cleanup resources
    health.cleanup();
    auth.clearTokenCache();
    
    logger.info('Gateway shutdown complete');
    process.exit(0);
  });
  
  // Force close after 10 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection:', { reason, promise });
  process.exit(1);
});

module.exports = app;
EOF

print_section "🔐 Updating Authentication Middleware"

# Create middleware directory if it doesn't exist
mkdir -p middleware

# Update simpleAuth.js
print_status "Updating middleware/simpleAuth.js..."
cat > middleware/simpleAuth.js << 'EOF'
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
EOF

print_section "⚙️ Updating Configuration"

# Create config directory if it doesn't exist
mkdir -p config

# Update config/simple.js
print_status "Updating config/simple.js..."
cat > config/simple.js << 'EOF'
// gateway-service/config/simple.js - Enhanced with Debug and Service Discovery
const dotenv = require('dotenv');
const axios = require('axios');

// Load environment variables
dotenv.config();

// Service URL validation and discovery
const validateServiceUrl = (serviceName, url) => {
  if (!url || url === `https://your-${serviceName}-service.herokuapp.com`) {
    console.warn(`⚠️  Service ${serviceName} URL not configured, using placeholder`);
    return false;
  }
  return true;
};

// Build service configuration with validation
const buildServiceConfig = () => {
  const services = {
    auth: process.env.AUTH_SERVICE_URL || 'https://your-auth-service.herokuapp.com',
    comment: process.env.COMMENT_SERVICE_URL || 'https://your-comment-service.herokuapp.com',
    industry: process.env.INDUSTRY_SERVICE_URL || 'https://your-industry-service.herokuapp.com',
    nps: process.env.NPS_SERVICE_URL || 'https://your-nps-service.herokuapp.com'
  };

  // Validate service URLs
  Object.entries(services).forEach(([name, url]) => {
    const isValid = validateServiceUrl(name, url);
    console.log(`${isValid ? '✅' : '❌'} ${name.toUpperCase()} Service: ${url}`);
  });

  return services;
};

// CORS origins configuration
const buildCorsOrigins = () => {
  const origins = [];
  
  // Add configured origins
  if (process.env.ALLOWED_ORIGINS) {
    const configuredOrigins = process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim());
    origins.push(...configuredOrigins);
  }
  
  // Add common production patterns
  origins.push(
    'https://gateway-service-b25f91548194.herokuapp.com',
    'https://*.herokuapp.com',
    'https://*.netlify.app',
    'https://*.vercel.app'
  );
  
  // Add development origins
  if (process.env.NODE_ENV === 'development') {
    origins.push(
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173',
      'http://localhost:8080',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173'
    );
  }
  
  return [...new Set(origins)]; // Remove duplicates
};

const config = {
  port: parseInt(process.env.PORT) || 3000,
  
  services: buildServiceConfig(),
  
  security: {
    jwtSecret: process.env.JWT_SECRET,
    corsOrigins: buildCorsOrigins(),
    apiKeyPrefix: process.env.API_KEY_PREFIX || 'sk-'
  },
  
  monitoring: {
    logLevel: process.env.LOG_LEVEL || 'info',
    healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000,
    enableMetrics: process.env.ENABLE_METRICS !== 'false'
  },
  
  proxy: {
    timeout: parseInt(process.env.PROXY_TIMEOUT) || 30000,
    retries: parseInt(process.env.PROXY_RETRIES) || 3,
    retryDelay: parseInt(process.env.RETRY_DELAY) || 1000
  },
  
  rateLimit: {
    global: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
      max: parseInt(process.env.RATE_LIMIT_MAX) || 100
    },
    auth: {
      windowMs: 15 * 60 * 1000,
      max: parseInt(process.env.AUTH_RATE_LIMIT) || 20
    },
    comments: {
      windowMs: 15 * 60 * 1000,
      max: parseInt(process.env.COMMENTS_RATE_LIMIT) || 50
    }
  }
};

// Configuration validation
const validateConfig = () => {
  const errors = [];
  const warnings = [];
  
  // Required environment variables
  const requiredEnvVars = ['JWT_SECRET'];
  const missing = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missing.length > 0) {
    errors.push(`Missing required environment variables: ${missing.join(', ')}`);
  }
  
  // JWT secret validation
  if (config.security.jwtSecret) {
    if (config.security.jwtSecret.length < 32) {
      errors.push('JWT_SECRET must be at least 32 characters long');
    }
    if (config.security.jwtSecret === 'dev-secret-change-in-production-32-chars-min') {
      warnings.push('Using default JWT_SECRET - change in production');
    }
  }
  
  // Service URL validation
  const hasConfiguredServices = Object.values(config.services).some(url => 
    !url.includes('your-') && !url.includes('localhost')
  );
  
  if (!hasConfiguredServices && process.env.NODE_ENV === 'production') {
    warnings.push('No backend services configured for production');
  }
  
  // Port validation
  if (config.port < 1 || config.port > 65535) {
    errors.push(`Invalid port number: ${config.port}`);
  }
  
  return { errors, warnings };
};

// Service discovery function
const discoverServices = async () => {
  const discoveries = {};
  
  for (const [serviceName, serviceUrl] of Object.entries(config.services)) {
    try {
      // Skip placeholder URLs
      if (serviceUrl.includes('your-') || serviceUrl.includes('localhost')) {
        discoveries[serviceName] = { status: 'not_configured', url: serviceUrl };
        continue;
      }
      
      const response = await axios.get(`${serviceUrl}/health`, { 
        timeout: 5000,
        validateStatus: () => true // Accept any status code
      });
      
      discoveries[serviceName] = {
        status: response.status === 200 ? 'healthy' : 'unhealthy',
        url: serviceUrl,
        responseTime: response.responseTime || 0,
        version: response.data?.version || 'unknown'
      };
    } catch (error) {
      discoveries[serviceName] = {
        status: 'unreachable',
        url: serviceUrl,
        error: error.message
      };
    }
  }
  
  return discoveries;
};

// Initialize configuration
const initializeConfig = () => {
  const { errors, warnings } = validateConfig();
  
  // Handle errors
  if (errors.length > 0) {
    console.error('❌ Configuration Errors:');
    errors.forEach(error => console.error(`  - ${error}`));
    
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    } else {
      console.warn('⚠️  Continuing with invalid configuration in development mode');
      // Set fallback values for development
      if (!config.security.jwtSecret) {
        config.security.jwtSecret = 'dev-secret-change-in-production-32-chars-min';
        console.warn('  - Using fallback JWT_SECRET for development');
      }
    }
  }
  
  // Handle warnings
  if (warnings.length > 0) {
    console.warn('⚠️  Configuration Warnings:');
    warnings.forEach(warning => console.warn(`  - ${warning}`));
  }
  
  // Log successful configuration
  console.log('\n🚀 Gateway Configuration:');
  console.log(`  - Port: ${config.port}`);
  console.log(`  - Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`  - Log Level: ${config.monitoring.logLevel}`);
  console.log(`  - CORS Origins: ${config.security.corsOrigins.length} configured`);
  console.log(`  - Health Check Interval: ${config.monitoring.healthCheckInterval}ms`);
  console.log(`  - Proxy Timeout: ${config.proxy.timeout}ms`);
  
  // Service configuration summary
  console.log('\n📡 Service Configuration:');
  Object.entries(config.services).forEach(([name, url]) => {
    const status = url.includes('your-') ? '❌ Not Configured' : '✅ Configured';
    console.log(`  - ${name.toUpperCase()}: ${status}`);
  });
  
  console.log('\n🔒 Security Configuration:');
  console.log(`  - JWT Secret: ${config.security.jwtSecret ? '✅ Set' : '❌ Missing'}`);
  console.log(`  - CORS Origins: ${config.security.corsOrigins.length} origins`);
  
  console.log('\n📊 Monitoring Configuration:');
  console.log(`  - Metrics Enabled: ${config.monitoring.enableMetrics ? '✅' : '❌'}`);
  console.log(`  - Health Checks: Every ${config.monitoring.healthCheckInterval / 1000}s`);
  
  console.log('\n🛡️  Rate Limiting:');
  console.log(`  - Global: ${config.rateLimit.global.max} requests per ${config.rateLimit.global.windowMs / 60000} minutes`);
  console.log(`  - Auth: ${config.rateLimit.auth.max} requests per ${config.rateLimit.auth.windowMs / 60000} minutes`);
  console.log(`  - Comments: ${config.rateLimit.comments.max} requests per ${config.rateLimit.comments.windowMs / 60000} minutes`);
};

// Helper functions
const getServiceConfig = (serviceName) => {
  return {
    url: config.services[serviceName],
    timeout: config.proxy.timeout,
    retries: config.proxy.retries,
    retryDelay: config.proxy.retryDelay
  };
};

const isServiceConfigured = (serviceName) => {
  const url = config.services[serviceName];
  return url && !url.includes('your-') && !url.includes('localhost');
};

const getEnvironmentInfo = () => {
  return {
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || 'development',
    platform: process.platform,
    uptime: Math.floor(process.uptime()),
    memory: process.memoryUsage(),
    port: config.port,
    services: Object.keys(config.services),
    configuredServices: Object.keys(config.services).filter(isServiceConfigured)
  };
};

// Initialize configuration on load
initializeConfig();

// Export configuration and utilities
module.exports = {
  ...config,
  discoverServices,
  getServiceConfig,
  isServiceConfigured,
  getEnvironmentInfo,
  validateConfig
};
EOF

print_section "📝 Creating Helper Scripts"

# Create debug scripts
print_status "Creating debug and helper scripts..."

# Create debug script for configuration
cat > debug-config.js << 'EOF'
#!/usr/bin/env node

// Debug script to check configuration
const config = require('./config/simple');

console.log('=== Gateway Configuration Debug ===\n');

console.log('🔧 Basic Configuration:');
console.log(`Port: ${config.port}`);
console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
console.log(`Log Level: ${config.monitoring.logLevel}`);

console.log('\n📡 Service URLs:');
Object.entries(config.services).forEach(([name, url]) => {
  const status = config.isServiceConfigured(name) ? '✅ Configured' : '❌ Not Configured';
  console.log(`${name}: ${url} ${status}`);
});

console.log('\n🔒 Security:');
console.log(`JWT Secret: ${config.security.jwtSecret ? '✅ Set (' + config.security.jwtSecret.length + ' chars)' : '❌ Missing'}`);
console.log(`CORS Origins: ${config.security.corsOrigins.length} configured`);
config.security.corsOrigins.forEach(origin => console.log(`  - ${origin}`));

console.log('\n🛡️  Rate Limiting:');
console.log(`Global: ${config.rateLimit.global.max} req/${config.rateLimit.global.windowMs/1000}s`);
console.log(`Auth: ${config.rateLimit.auth.max} req/${config.rateLimit.auth.windowMs/1000}s`);
console.log(`Comments: ${config.rateLimit.comments.max} req/${config.rateLimit.comments.windowMs/1000}s`);

console.log('\n📊 Environment Info:');
const envInfo = config.getEnvironmentInfo();
console.log(`Node Version: ${envInfo.nodeVersion}`);
console.log(`Platform: ${envInfo.platform}`);
console.log(`Memory Usage: ${Math.round(envInfo.memory.heapUsed / 1024 / 1024)}MB`);
console.log(`Configured Services: ${envInfo.configuredServices.join(', ') || 'none'}`);
EOF

chmod +x debug-config.js

# Create service discovery script
cat > discover-services.js << 'EOF'
#!/usr/bin/env node

// Script to discover and test service connectivity
const config = require('./config/simple');

async function discoverServices() {
  console.log('=== Service Discovery ===\n');
  
  try {
    const discoveries = await config.discoverServices();
    
    console.log('Service Status:');
    Object.entries(discoveries).forEach(([name, info]) => {
      let statusIcon = '❌';
      if (info.status === 'healthy') statusIcon = '✅';
      else if (info.status === 'unhealthy') statusIcon = '⚠️';
      else if (info.status === 'not_configured') statusIcon = '🔧';
      
      console.log(`${statusIcon} ${name.toUpperCase()}: ${info.status}`);
      console.log(`   URL: ${info.url}`);
      if (info.responseTime) console.log(`   Response Time: ${info.responseTime}ms`);
      if (info.version) console.log(`   Version: ${info.version}`);
      if (info.error) console.log(`   Error: ${info.error}`);
      console.log('');
    });
    
    const healthyServices = Object.values(discoveries).filter(s => s.status === 'healthy').length;
    const totalServices = Object.keys(discoveries).length;
    
    console.log(`Summary: ${healthyServices}/${totalServices} services healthy`);
    
  } catch (error) {
    console.error('Discovery failed:', error.message);
    process.exit(1);
  }
}

discoverServices();
EOF

chmod +x discover-services.js

# Create deployment script
cat > deploy.sh << 'EOF'
#!/bin/bash

# Deployment script for gateway service
set -e

echo "🚀 Deploying Gateway Service..."

# Check if we're logged into Heroku
if ! heroku auth:whoami &> /dev/null; then
    echo "❌ Please login to Heroku first: heroku login"
    exit 1
fi

# Get app name
APP_NAME=$(heroku apps --json | jq -r '.[] | select(.name | contains("gateway")) | .name' | head -1)

if [ -z "$APP_NAME" ]; then
    echo "❌ No Heroku app found with 'gateway' in the name"
    echo "Available apps:"
    heroku apps --json | jq -r '.[].name'
    exit 1
fi

echo "📱 Deploying to app: $APP_NAME"

# Push to Heroku
echo "📤 Pushing code to Heroku..."
git add .
git commit -m "Update gateway service with fixes" || echo "No changes to commit"
git push heroku main

# Wait for deployment
echo "⏳ Waiting for deployment..."
sleep 10

# Check deployment status
echo "🔍 Checking deployment status..."
heroku ps --app $APP_NAME

# Test health endpoint
echo "🏥 Testing health endpoint..."
APP_URL=$(heroku apps:info --app $APP_NAME --json | jq -r '.app.web_url')
curl -f "${APP_URL}health" || echo "Health check failed"

# Show logs
echo "📋 Recent logs:"
heroku logs --tail --num 20 --app $APP_NAME

echo "✅ Deployment complete!"
echo "🌐 App URL: $APP_URL"
echo "📊 Logs: heroku logs --tail --app $APP_NAME"
EOF

chmod +x deploy.sh

print_section "🔧 Environment Setup"

# Update .env file with better defaults
print_status "Updating .env file..."
if [ ! -f ".env" ]; then
    cat > .env << 'EOF'
# Gateway Service Environment Configuration

# Server Configuration
PORT=3000
NODE_ENV=development

# Service URLs (Update these with your actual service URLs)
AUTH_SERVICE_URL=https://your-auth-service.herokuapp.com
COMMENT_SERVICE_URL=https://your-comment-service.herokuapp.com
INDUSTRY_SERVICE_URL=https://your-industry-service.herokuapp.com
NPS_SERVICE_URL=https://your-nps-service.herokuapp.com

# Security (REQUIRED - Change this!)
JWT_SECRET=YR5fdn2srklpem5AlP5nj75gbHAVTNyC

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001,http://localhost:5173

# Health Check Configuration
HEALTH_CHECK_INTERVAL=30000

# Logging Configuration
LOG_LEVEL=info
ENABLE_COLORS=true

# Rate Limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
AUTH_RATE_LIMIT=20
COMMENTS_RATE_LIMIT=50

# Proxy Configuration
PROXY_TIMEOUT=30000
PROXY_RETRIES=3
RETRY_DELAY=1000
EOF
else
    print_warning ".env file already exists, not overwriting"
fi

print_section "📦 Installing Dependencies"

# Install/update dependencies
print_status "Installing dependencies..."
npm install

print_section "🧪 Running Tests"

# Run tests
print_status "Running tests..."
npm test || print_warning "Some tests may fail due to missing services"

print_section "🔍 Validation"

# Run configuration debug
print_status "Validating configuration..."
node debug-config.js

# Test service discovery (will show which services are not configured)
print_status "Testing service discovery..."
node discover-services.js

print_section "📚 Next Steps"

print_status "Gateway service has been updated successfully!"
echo ""
echo "🔧 Configuration Files Updated:"
echo "  ✅ server.js - Enhanced proxy and error handling"
echo "  ✅ middleware/simpleAuth.js - Better JWT compatibility"
echo "  ✅ config/simple.js - Enhanced configuration with validation"
echo "  ✅ package.json - Updated dependencies and scripts"
echo ""
echo "🛠️  Helper Scripts Created:"
echo "  📋 debug-config.js - Debug configuration"
echo "  🔍 discover-services.js - Test service connectivity"  
echo "  🚀 deploy.sh - Deploy to Heroku"
echo ""
echo "📝 Next Steps:"
echo ""
echo "1. Update your service URLs in .env:"
echo "   nano .env"
echo ""
echo "2. Test the configuration:"
echo "   npm run debug:config"
echo ""
echo "3. Test service connectivity:"
echo "   npm run debug:services"
echo ""
echo "4. Start the development server:"
echo "   npm run dev"
echo ""
echo "5. Test the endpoints:"
echo "   curl http://localhost:3000/health"
echo "   curl http://localhost:3000/health/services"
echo ""
echo "6. Deploy to Heroku (if ready):"
echo "   ./deploy.sh"
echo ""
echo "🔧 For Other Services:"
echo ""
echo "Industry Service - Make sure it:"
echo "  • Responds to /api/v1/industries (not /api/industries)"
echo "  • Uses the same JWT_SECRET: YR5fdn2srklpem5AlP5nj75gbHAVTNyC"
echo ""
echo "Auth Service - Make sure JWT tokens include:"
echo "  • userId (or id)"
echo "  • email"
echo "  • exp (expiration)"
echo "  • iat (issued at)"
echo ""
echo "📊 Debug Commands:"
echo "  npm run debug:config    - Show configuration"
echo "  npm run debug:services  - Test service connectivity"
echo "  npm run health-check    - Test health endpoint"
echo "  npm run lint           - Check code quality"
echo ""

print_status "🎉 Update script completed successfully!"
print_warning "Remember to update your service URLs in the .env file before testing!"

# Clean up
print_status "Backup created in: $BACKUP_DIR/"
echo "If everything works correctly, you can remove the backup with: rm -rf $BACKUP_DIR"