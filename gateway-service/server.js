// gateway-service/server.js
const express = require('express');
const path = require('path');
const compression = require('compression');
require('dotenv').config();

// Import utilities
const logger = require('./utils/logger');
const metrics = require('./utils/metrics');

// Import middleware managers
const CorsManager = require('./middleware/cors');
const SecurityManager = require('./middleware/security');
const AuthenticationManager = require('./middleware/auth');
const MonitoringMiddleware = require('./middleware/monitoring');

// Import routing system
const GatewayRoutes = require('./routes');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize middleware managers
const corsManager = new CorsManager();
const securityManager = new SecurityManager();
const monitoringMiddleware = new MonitoringMiddleware();

// Initialize gateway routing (this creates the service registry)
const gatewayRoutes = new GatewayRoutes();

// Initialize auth manager with service registry
const authManager = new AuthenticationManager(gatewayRoutes.getServiceRegistry());

// Set up service health monitoring
monitoringMiddleware.monitorServiceHealth(gatewayRoutes.getServiceRegistry());

// ===== MIDDLEWARE SETUP (Order is critical for security) =====

// 1. Monitoring and logging (first to capture everything)
app.use(monitoringMiddleware.monitor());

// 2. Security headers first (before any processing)
app.use(securityManager.securityHeaders());

// 2. Compression for performance
if (process.env.ENABLE_COMPRESSION !== 'false') {
  app.use(compression());
}

// 3. Request parsing middleware
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    // Store raw body for webhook verification if needed
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 4. Request logging (structured logging)
if (process.env.ENABLE_REQUEST_LOGGING !== 'false') {
  app.use(morgan(':remote-addr - :remote-user [:date[iso]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :response-time ms', {
    stream: {
      write: (message) => {
        console.log(JSON.stringify({
          timestamp: new Date().toISOString(),
          level: 'info',
          service: 'gateway',
          message: 'HTTP Request',
          details: message.trim(),
          type: 'access_log'
        }));
      }
    }
  }));
}

// 5. Request tracing headers
app.use(authManager.addTracingHeaders());

// 6. CORS handling (must be before routes)
app.use(corsManager.handlePreflight());
app.use(corsManager.dynamicCors());

// 7. Security middleware (rate limiting and suspicious activity detection)
app.use(securityManager.detectSuspiciousActivity());
app.use(securityManager.dynamicRateLimit());

// 8. Request sanitization
app.use(securityManager.sanitizeRequest());

// 9. CORS error handling
app.use(corsManager.handleCorsError());

// ===== ROUTE SETUP =====

// System endpoints (before authentication)
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'gateway',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    uptime: Math.floor(process.uptime()),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Monitoring endpoints
app.get('/metrics', monitoringMiddleware.metricsEndpoint());
app.get('/health/monitoring', monitoringMiddleware.healthCheck());

// Gateway status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    success: true,
    data: {
      service: 'api-gateway',
      status: 'operational',
      version: process.env.npm_package_version || '1.0.0',
      timestamp: new Date().toISOString(),
      cors: corsManager.getCorsInfo(),
      security: securityManager.getSecurityStats(),
      auth: authManager.getAuthStats()
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'],
      service: 'gateway'
    }
  });
});

// CORS configuration endpoint (development only)
if (process.env.NODE_ENV === 'development') {
  app.get('/api/cors/config', (req, res) => {
    res.json({
      success: true,
      data: corsManager.getCorsInfo(),
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'],
        service: 'gateway'
      }
    });
  });

  // Dynamic CORS origin management (development only)
  app.post('/api/cors/origins', authManager.requireRole(['admin']), (req, res) => {
    const { origins } = req.body;
    
    if (!Array.isArray(origins)) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_INPUT',
          message: 'Origins must be an array of strings',
          suggestion: 'Provide an array of origin URLs'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'],
          service: 'gateway'
        }
      });
    }

    const validOrigins = origins.filter(origin => corsManager.isValidOrigin(origin));
    
    if (validOrigins.length !== origins.length) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_ORIGINS',
          message: 'Some origins have invalid format',
          details: 'Origins must be valid URLs with http:// or https:// protocol'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'],
          service: 'gateway'
        }
      });
    }

    const updated = corsManager.updateAllowedOrigins(validOrigins);
    
    res.json({
      success: true,
      data: {
        updated,
        allowedOrigins: corsManager.getCorsInfo().allowedOrigins
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'],
        service: 'gateway'
      }
    });
  });
}

// Apply authentication middleware to API routes
app.use('/api/auth/*', authManager.authenticate({ optional: false }));
app.use('/api/comments/*', authManager.authenticate({ optional: false }));
app.use('/api/industries/*', authManager.authenticate({ optional: true })); // Public access for industry data
app.use('/api/nps/*', authManager.authenticate({ optional: false }));

// Admin routes require admin role
app.use('/admin/*', authManager.authenticate({ optional: false }));
app.use('/admin/*', authManager.requireAdmin());

// Use the intelligent routing system
app.use('/', gatewayRoutes.getRouter());

// Serve static files with proper caching headers
app.use(express.static(path.join(__dirname, '../public'), {
  maxAge: process.env.STATIC_FILES_MAX_AGE || (process.env.NODE_ENV === 'production' ? '1d' : '0'),
  etag: true,
  lastModified: true,
  setHeaders: (res, path) => {
    // Set security headers for static files
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Cache control based on file type
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    } else if (path.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg)$/)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1 year for assets
    }
  }
}));

// ===== ERROR HANDLING =====

// Global error handling middleware (following shared knowledge format)
app.use((err, req, res, next) => {
  // Log error with structured logging
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'error',
    service: 'gateway',
    message: 'Unhandled error',
    error: {
      name: err.name,
      message: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    },
    metadata: {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      requestId: req.headers['x-request-id']
    }
  }));
  
  // Standard error response format (following shared knowledge)
  const errorResponse = {
    success: false,
    error: {
      code: err.code || 'INTERNAL_SERVER_ERROR',
      message: err.message || 'An unexpected error occurred',
      suggestion: err.suggestion || 'Please try again later or contact support if the problem persists'
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || 'unknown',
      service: 'gateway'
    }
  };
  
  // Don't send error details in production unless it's a client error
  if (process.env.NODE_ENV !== 'production' || (err.status >= 400 && err.status < 500)) {
    if (err.details) {
      errorResponse.error.details = err.details;
    }
  }
  
  res.status(err.status || 500).json(errorResponse);
});

// 404 handler for unmatched routes (following shared knowledge format)
app.use('*', (req, res) => {
  // Log 404 for monitoring
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'warn',
    service: 'gateway',
    message: 'Route not found',
    metadata: {
      path: req.originalUrl,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      requestId: req.headers['x-request-id']
    }
  }));

  // If it's an API request, return JSON
  if (req.originalUrl.startsWith('/api/')) {
    return res.status(404).json({
      success: false,
      error: {
        code: 'ENDPOINT_NOT_FOUND',
        message: 'The requested API endpoint does not exist',
        suggestion: 'Check the API documentation for available endpoints'
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'] || 'unknown',
        service: 'gateway'
      }
    });
  }
  
  // For non-API requests, try to serve index.html (SPA support)
  res.sendFile(path.join(__dirname, '../public/index.html'), (err) => {
    if (err) {
      res.status(404).json({
        success: false,
        error: {
          code: 'RESOURCE_NOT_FOUND',
          message: 'The requested resource could not be found',
          suggestion: 'Check the URL and try again'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'] || 'unknown',
          service: 'gateway'
        }
      });
    }
  });
});

// ===== GRACEFUL SHUTDOWN =====
process.on('SIGTERM', async () => {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'info',
    service: 'gateway',
    message: 'Received SIGTERM, initiating graceful shutdown'
  }));
  
  // Cleanup operations
  securityManager.cleanup();
  authManager.clearTokenCache();
  monitoringMiddleware.cleanup();
  await gatewayRoutes.shutdown();
  
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'info',
    service: 'gateway',
    message: 'Received SIGINT, initiating graceful shutdown'
  }));
  
  // Cleanup operations
  securityManager.cleanup();
  authManager.clearTokenCache();
  monitoringMiddleware.cleanup();
  await gatewayRoutes.shutdown();
  
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'error',
    service: 'gateway',
    message: 'Uncaught exception',
    error: {
      name: err.name,
      message: err.message,
      stack: err.stack
    }
  }));
  
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'error',
    service: 'gateway',
    message: 'Unhandled promise rejection',
    error: {
      reason: reason?.toString(),
      stack: reason?.stack
    }
  }));
});

// ===== SERVER STARTUP =====
const server = app.listen(PORT, () => {
  logger.info('API Gateway started successfully', {
    server: {
      port: PORT,
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0'
    },
    endpoints: {
      health: `http://localhost:${PORT}/health`,
      metrics: `http://localhost:${PORT}/metrics`,
      status: `http://localhost:${PORT}/api/status`,
      monitoring: `http://localhost:${PORT}/health/monitoring`
    },
    features: {
      rateLimiting: 'enabled',
      cors: 'enabled',
      helmet: 'enabled',
      authentication: 'enabled',
      monitoring: 'enabled',
      serviceDiscovery: 'enabled'
    }
  });
});

// Graceful shutdown on server close
server.on('close', () => {
  logger.info('Server closed successfully');
});

module.exports = app;