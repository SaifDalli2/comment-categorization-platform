// gateway-service/server.js - Enhanced Gateway Server (Fixed)
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

// Keep existing imports
const SimpleAuth = require('./middleware/simpleAuth');
const SimpleHealth = require('./services/simpleHealth');
const config = require('./config/simple');
const logger = require('./utils/simpleLogger');

// NEW: Add enhanced service components
const { ServiceRegistry, EnhancedAuth } = require('./src/services/ServiceRegistry');

const app = express();

// Initialize components
const auth = new SimpleAuth();
const health = new SimpleHealth();
const serviceRegistry = new ServiceRegistry();
const enhancedAuth = new EnhancedAuth(serviceRegistry);

// Trust proxy (important for Heroku)
app.set('trust proxy', 1);

// Basic middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced security
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "wss:", "https:"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors({
  origin: config.security.corsOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Requested-With', 
    'X-API-Key', 
    'X-Request-ID'
  ]
}));

// Enhanced rate limiting
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
    skip: (req) => req.path === '/health' || req.path.startsWith('/health/')
  });
};

// Apply rate limits
app.use('/api/auth', createRateLimit(15 * 60 * 1000, 20, 'Too many authentication requests'));
app.use('/api/comments/categorize', createRateLimit(60 * 60 * 1000, 50, 'Too many categorization requests'));
app.use('/api/nps/upload', createRateLimit(60 * 60 * 1000, 10, 'Too many file uploads'));
app.use('/', createRateLimit(15 * 60 * 1000, 100, 'Too many requests'));

// Enhanced request logging - FIXED
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  req.startTime = Date.now(); // Add start time to request
  
  // Set headers immediately when request starts
  res.setHeader('X-Request-ID', req.id);
  
  const originalEnd = res.end;
  res.end = function(...args) {
    const duration = Date.now() - req.startTime;
    
    // Only set headers if they haven't been sent yet
    if (!res.headersSent) {
      res.setHeader('X-Response-Time', `${duration}ms`);
    }
    
    const logData = {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      responseTime: `${duration}ms`,
      requestId: req.id
    };
    
    if (req.user) logData.userId = req.user.id;
    
    const level = res.statusCode >= 500 ? 'error' : 
                  res.statusCode >= 400 ? 'warn' : 'info';
    logger.log(level, `${req.method} ${req.path} ${res.statusCode}`, logData);
    
    // Call original end method
    originalEnd.apply(this, args);
  };
  
  next();
});

// Health endpoints
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'gateway',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/health/services', async (req, res) => {
  try {
    const legacyHealth = health.getOverallHealth();
    const enhancedHealth = await serviceRegistry.healthCheckAll();
    
    const allHealthy = legacyHealth.healthy && 
                      Object.values(enhancedHealth).every(h => h.healthy);
    
    res.status(allHealthy ? 200 : 503).json({
      status: allHealthy ? 'healthy' : 'degraded',
      service: 'gateway',
      timestamp: new Date().toISOString(),
      dependencies: {
        ...legacyHealth.services,
        ...enhancedHealth
      },
      summary: {
        totalServices: legacyHealth.totalServices,
        healthyServices: legacyHealth.healthyServices,
        unhealthyServices: legacyHealth.unhealthyServices
      }
    });
  } catch (error) {
    logger.error('Health check failed:', { error: error.message });
    res.status(503).json({
      status: 'unhealthy',
      service: 'gateway',
      timestamp: new Date().toISOString(),
      error: 'Health check system failure'
    });
  }
});

// NEW: Enhanced gateway management endpoint
app.get('/api/gateway/services', enhancedAuth.optionalAuth(), async (req, res) => {
  try {
    const serviceHealth = await serviceRegistry.healthCheckAll();
    const authStats = enhancedAuth.getStats();
    
    res.json({
      success: true,
      data: {
        services: serviceHealth,
        gateway: {
          uptime: Math.floor(process.uptime()),
          version: process.env.npm_package_version || '1.0.0',
          environment: process.env.NODE_ENV || 'development',
          auth: authStats
        }
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.id,
        service: 'gateway'
      }
    });
  } catch (error) {
    logger.error('Gateway services endpoint failed:', { error: error.message });
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve service information'
      }
    });
  }
});

// Enhanced proxy factory - FIXED
const createEnhancedProxy = (serviceName, targetUrl) => {
  return createProxyMiddleware({
    target: targetUrl,
    changeOrigin: true,
    timeout: 30000,
    
    onProxyReq: (proxyReq, req) => {
      if (req.user) {
        proxyReq.setHeader('X-User-ID', req.user.userId || req.user.id);
        proxyReq.setHeader('X-User-Email', req.user.email);
        proxyReq.setHeader('X-User-Industry', req.user.industry || '');
        
        if (req.user.roles && req.user.roles.length > 0) {
          proxyReq.setHeader('X-User-Roles', req.user.roles.join(','));
        }
      }
      
      proxyReq.setHeader('X-Gateway-Request', 'true');
      proxyReq.setHeader('X-Gateway-Version', '1.0.0');
      proxyReq.setHeader('X-Request-ID', req.id);
      proxyReq.setHeader('X-Service-Name', 'gateway');
      
      if (req.ip) {
        proxyReq.setHeader('X-Forwarded-For', req.ip);
      }
      
      logger.debug(`Proxying to ${serviceName}:`, {
        method: req.method,
        path: req.path,
        userId: req.user?.id,
        requestId: req.id
      });
    },

    onProxyRes: (proxyRes, req, res) => {
      // Only set headers if they haven't been sent yet
      if (!proxyRes.headersSent) {
        proxyRes.headers['x-served-by'] = serviceName;
        proxyRes.headers['x-gateway-service'] = 'claude-analysis-gateway';
      }
      
      const success = proxyRes.statusCode < 400;
      health.recordServiceResponse(serviceName, success);
      
      if (success) {
        logger.debug(`Successful proxy to ${serviceName}:`, {
          statusCode: proxyRes.statusCode,
          requestId: req.id
        });
      }
    },

    onError: (err, req, res) => {
      logger.error(`Proxy error for ${serviceName}:`, {
        error: err.message,
        path: req.path,
        method: req.method,
        requestId: req.id
      });
      
      health.recordServiceResponse(serviceName, false);
      
      if (res.headersSent) return;
      
      let errorCode = 'SERVICE_UNAVAILABLE';
      let statusCode = 503;
      let suggestion = 'Please try again in a few moments';
      
      if (err.code === 'ECONNREFUSED') {
        errorCode = 'SERVICE_UNAVAILABLE';
        suggestion = `${serviceName} service is currently unavailable`;
      } else if (err.code === 'ETIMEDOUT') {
        errorCode = 'GATEWAY_TIMEOUT';
        statusCode = 504;
        suggestion = 'The request took too long to process';
      }
      
      res.status(statusCode).json({
        success: false,
        error: {
          code: errorCode,
          message: `${serviceName} service error: ${err.message}`,
          suggestion
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.id,
          service: 'gateway',
          targetService: serviceName
        }
      });
    }
  });
};

// Service routing
// Auth routes should NOT have authentication middleware
app.use('/api/auth', createEnhancedProxy('auth', config.services.auth));

app.use('/api/comments', 
  enhancedAuth.requireAuth(),
  createEnhancedProxy('comment', config.services.comment)
);

// Add path rewrite middleware BEFORE the proxy
app.use('/api/industries', (req, res, next) => {
  // Rewrite the path from /api/industries to /api/v1/industries
  req.url = req.url.replace('/api/industries', '/api/v1/industries');
  next();
}, enhancedAuth.optionalAuth(), createEnhancedProxy('industry', config.services.industry));

app.use('/api/nps', 
  enhancedAuth.requireAuth(),
  createEnhancedProxy('nps', config.services.nps)
);

// Static files
app.use(express.static('public', {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  etag: true,
  lastModified: true
}));

// API 404 handler
app.use('/api/*', (req, res) => {
  logger.warn('API endpoint not found:', { path: req.path, method: req.method, requestId: req.id });
  
  res.status(404).json({
    success: false,
    error: {
      code: 'RESOURCE_NOT_FOUND',
      message: 'The requested API endpoint does not exist',
      suggestion: 'Check the API documentation for available endpoints'
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.id,
      service: 'gateway'
    }
  });
});

// SPA fallback
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  res.sendFile(indexPath, (err) => {
    if (err) {
      logger.error('Failed to serve index.html:', { error: err.message, requestId: req.id });
      res.status(404).json({
        success: false,
        error: {
          code: 'RESOURCE_NOT_FOUND',
          message: 'The requested resource was not found'
        }
      });
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', { 
    error: err.message, 
    stack: err.stack, 
    requestId: req.id,
    path: req.path,
    method: req.method
  });
  
  if (res.headersSent) {
    return next(err);
  }
  
  const message = process.env.NODE_ENV === 'production' ? 
    'An unexpected error occurred' : 
    err.message;
  
  res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message,
      suggestion: 'Please try again later'
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.id,
      service: 'gateway'
    }
  });
});

// Server startup
const PORT = config.port;
const server = app.listen(PORT, () => {
  logger.info(`Enhanced Gateway server started:`, {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    enhancedMode: process.env.USE_ENHANCED_AUTH === 'true',
    version: process.env.npm_package_version || '1.0.0'
  });
  
  logger.systemInfo();
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received, shutting down gracefully`);
  
  server.close((err) => {
    if (err) {
      logger.error('Error during server shutdown:', { error: err.message });
      process.exit(1);
    }
    
    logger.info('Gateway server closed successfully');
    process.exit(0);
  });
  
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', { 
    error: err.message, 
    stack: err.stack 
  });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection:', { 
    reason: reason instanceof Error ? reason.message : reason,
    stack: reason instanceof Error ? reason.stack : undefined
  });
  process.exit(1);
});

module.exports = app;
