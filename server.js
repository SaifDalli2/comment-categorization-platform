// gateway-service/server.js - Fixed Auth Routes Configuration
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

// ...existing code...

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

// Add this to your server.js file after existing health endpoints

const HealthDiagnostics = require('./services/HealthDiagnostics');

// Initialize health diagnostics service
const healthDiagnostics = new HealthDiagnostics();

// Enhanced health diagnostics endpoint
app.get('/health/diagnostics', healthDiagnostics.healthDiagnosticsEndpoint());

// Quick health summary endpoint (lighter version)
app.get('/health/summary', async (req, res) => {
  try {
    const quickCheck = await healthDiagnostics.performCompleteHealthCheck();
    
    res.json({
      success: true,
      data: {
        overallStatus: quickCheck.summary.overallStatus,
        gatewayStatus: quickCheck.gateway.status,
        healthScore: quickCheck.summary.healthPercentage,
        servicesStatus: Object.fromEntries(
          Object.entries(quickCheck.services).map(([name, service]) => [
            name, 
            { 
              status: service.status, 
              responseTime: service.responseTime,
              url: service.url
            }
          ])
        ),
        summary: quickCheck.summary,
        checkTime: quickCheck.performance.totalCheckTime,
        timestamp: quickCheck.timestamp
      },
      metadata: {
        timestamp: new Date().toISOString(),
        service: 'gateway',
        requestId: req.requestId
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        code: 'HEALTH_SUMMARY_FAILED',
        message: 'Health summary check failed'
      },
      metadata: {
        timestamp: new Date().toISOString(),
        service: 'gateway',
        requestId: req.requestId
      }
    });
  }
});

// Health status for monitoring systems (Prometheus/Grafana compatible)
app.get('/health/metrics', async (req, res) => {
  try {
    const healthCheck = await healthDiagnostics.performCompleteHealthCheck();
    
    // Generate Prometheus-style metrics
    const metrics = [];
    
    // Gateway metrics
    metrics.push(`# HELP gateway_up Gateway service availability`);
    metrics.push(`# TYPE gateway_up gauge`);
    metrics.push(`gateway_up{service="gateway"} ${healthCheck.gateway.status === 'healthy' ? 1 : 0}`);
    
    metrics.push(`# HELP gateway_uptime_seconds Gateway uptime in seconds`);
    metrics.push(`# TYPE gateway_uptime_seconds counter`);
    metrics.push(`gateway_uptime_seconds{service="gateway"} ${healthCheck.gateway.uptime}`);
    
    metrics.push(`# HELP gateway_response_time_ms Gateway response time in milliseconds`);
    metrics.push(`# TYPE gateway_response_time_ms gauge`);
    metrics.push(`gateway_response_time_ms{service="gateway"} ${healthCheck.gateway.responseTime}`);
    
    // Service metrics
    metrics.push(`# HELP service_up Service availability`);
    metrics.push(`# TYPE service_up gauge`);
    
    metrics.push(`# HELP service_response_time_ms Service response time in milliseconds`);
    metrics.push(`# TYPE service_response_time_ms gauge`);
    
    Object.entries(healthCheck.services).forEach(([serviceName, service]) => {
      const isUp = service.status === 'healthy' ? 1 : 0;
      metrics.push(`service_up{service="${serviceName}",url="${service.url}"} ${isUp}`);
      metrics.push(`service_response_time_ms{service="${serviceName}"} ${service.responseTime}`);
    });
    
    // Overall system metrics
    metrics.push(`# HELP system_health_percentage Overall system health percentage`);
    metrics.push(`# TYPE system_health_percentage gauge`);
    metrics.push(`system_health_percentage ${healthCheck.summary.healthPercentage}`);
    
    metrics.push(`# HELP services_total Total number of services`);
    metrics.push(`# TYPE services_total gauge`);
    metrics.push(`services_total ${healthCheck.summary.totalServices}`);
    
    metrics.push(`# HELP services_healthy Number of healthy services`);
    metrics.push(`# TYPE services_healthy gauge`);
    metrics.push(`services_healthy ${healthCheck.summary.healthyServices}`);
    
    res.set('Content-Type', 'text/plain');
    res.send(metrics.join('\n') + '\n');
    
  } catch (error) {
    res.status(500).send('# Health metrics collection failed\n');
  }
});

// Health check history endpoint
app.get('/health/history', (req, res) => {
  try {
    const history = healthDiagnostics.getHealthHistory();
    const trends = healthDiagnostics.getHealthTrends();
    
    res.json({
      success: true,
      data: {
        history,
        trends,
        totalChecks: history.length
      },
      metadata: {
        timestamp: new Date().toISOString(),
        service: 'gateway',
        requestId: req.requestId
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        code: 'HEALTH_HISTORY_FAILED',
        message: 'Failed to retrieve health history'
      },
      metadata: {
        timestamp: new Date().toISOString(),
        service: 'gateway',
        requestId: req.requestId
      }
    });
  }
});

// Force health check endpoint (for admin use)
app.post('/health/check', auth.optionalAuth(), async (req, res) => {
  try {
    // Optional: Add admin check if needed
    // if (req.user && !req.user.roles.includes('admin')) {
    //   return res.status(403).json({ error: 'Admin access required' });
    // }
    
    const healthCheck = await healthDiagnostics.performCompleteHealthCheck();
    
    res.json({
      success: true,
      data: healthCheck,
      metadata: {
        timestamp: new Date().toISOString(),
        service: 'gateway',
        requestId: req.requestId,
        triggeredBy: req.user ? req.user.email : 'anonymous'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        code: 'FORCED_HEALTH_CHECK_FAILED',
        message: 'Forced health check failed'
      },
      metadata: {
        timestamp: new Date().toISOString(),
        service: 'gateway',
        requestId: req.requestId
      }
    });
  }
});

// ...existing code continues...
// When shutting down, add healthDiagnostics cleanup if needed:
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received, shutting down gracefully`);
  
  server.close(() => {
    logger.info('HTTP server closed');
    
    // Cleanup resources
    health.cleanup();
    auth.clearTokenCache();
    if (typeof healthDiagnostics.cleanup === 'function') {
      healthDiagnostics.cleanup();
    }
    
    logger.info('Gateway shutdown complete');
    process.exit(0);
  });
  
  // Force close after 10 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};
// ...existing code...

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

// AUTH SERVICE ROUTES - FIXED: Separate public and protected routes
// Public authentication endpoints (no auth required)
app.use('/api/auth/login', createServiceProxy('auth', config.services.auth));
app.use('/api/auth/register', createServiceProxy('auth', config.services.auth));
app.use('/api/auth/forgot-password', createServiceProxy('auth', config.services.auth));
app.use('/api/auth/reset-password', createServiceProxy('auth', config.services.auth));
app.use('/api/auth/verify-email', createServiceProxy('auth', config.services.auth));

// Protected authentication endpoints (require auth)
app.use('/api/auth/profile', 
  auth.requireAuth(),
  createServiceProxy('auth', config.services.auth)
);
app.use('/api/auth/change-password', 
  auth.requireAuth(),
  createServiceProxy('auth', config.services.auth)
);
app.use('/api/auth/logout', 
  auth.requireAuth(),
  createServiceProxy('auth', config.services.auth)
);
app.use('/api/auth/verify', 
  auth.requireAuth(),
  createServiceProxy('auth', config.services.auth)
);

// Catch-all for other auth routes (protected by default)
app.use('/api/auth', 
  auth.requireAuth(),
  createServiceProxy('auth', config.services.auth)
);

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
  
  // Log auth route configuration
  logger.info('Auth route configuration:');
  logger.info('  Public: /api/auth/login, /api/auth/register, /api/auth/forgot-password, /api/auth/reset-password, /api/auth/verify-email');
  logger.info('  Protected: /api/auth/profile, /api/auth/change-password, /api/auth/logout, /api/auth/verify');
});




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