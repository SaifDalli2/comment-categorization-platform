// gateway-service/server.js - Enhanced with better synchronization
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const SimpleAuth = require('./middleware/simpleAuth');
const EnhancedHealth = require('./services/enhancedHealth');
const ServiceOrchestrator = require('./services/serviceOrchestrator');
const config = require('./config/simple');
const logger = require('./utils/simpleLogger');

const app = express();
const auth = new SimpleAuth();
const health = new EnhancedHealth();
const orchestrator = new ServiceOrchestrator();

// Basic middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Security
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: config.security.corsOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
}));

// Enhanced rate limiting with service-specific limits
const createRateLimit = (windowMs, max, keyGenerator = null) => {
  return rateLimit({
    windowMs,
    max,
    keyGenerator: keyGenerator || ((req) => req.ip),
    message: { 
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests',
        suggestion: 'Please wait before making additional requests'
      }
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        path: req.path,
        userAgent: req.get('User-Agent')
      });
      res.status(429).json({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests',
          suggestion: 'Please wait before making additional requests'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          service: 'gateway',
          retryAfter: Math.ceil(windowMs / 1000)
        }
      });
    }
  });
};

// General rate limiting
app.use(createRateLimit(15 * 60 * 1000, 100)); // 100 requests per 15 minutes

// Request correlation and logging
app.use((req, res, next) => {
  const requestId = req.get('X-Request-ID') || 
    `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  req.requestId = requestId;
  res.set('X-Request-ID', requestId);
  res.set('X-Gateway-Service', 'claude-analysis-gateway');
  res.set('X-Gateway-Version', '1.0.0');
  
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.request(req, res, duration);
  });
  
  next();
});

// Health endpoints with enhanced sync status
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

app.get('/health/services', health.checkServices());

app.get('/health/sync', health.checkSyncStatus());

// Gateway management endpoints
app.get('/api/gateway/services', auth.requireAuth(), (req, res) => {
  const services = health.getServiceStatus();
  const syncStatus = health.getSyncStatus();
  
  res.json({
    success: true,
    data: {
      services,
      synchronization: syncStatus,
      gateway: {
        uptime: Math.floor(process.uptime()),
        requestsHandled: health.getStats().totalRequests || 0,
        lastSync: syncStatus.lastSync
      }
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      service: 'gateway'
    }
  });
});

app.get('/api/gateway/stats', auth.requireAuth(), (req, res) => {
  const stats = health.getStats();
  
  res.json({
    success: true,
    data: {
      ...stats,
      orchestration: orchestrator.getStats(),
      synchronization: health.getSyncStatus()
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      service: 'gateway'
    }
  });
});

// Enhanced service proxy with better error handling and sync
const createEnhancedServiceProxy = (serviceName, targetUrl) => {
  return createProxyMiddleware({
    target: targetUrl,
    changeOrigin: true,
    timeout: 30000,
    
    onProxyReq: (proxyReq, req) => {
      // Forward user context
      if (req.user) {
        proxyReq.setHeader('X-User-ID', req.user.id);
        proxyReq.setHeader('X-User-Email', req.user.email);
        proxyReq.setHeader('X-User-Industry', req.user.industry || '');
        if (req.user.roles) {
          proxyReq.setHeader('X-User-Roles', req.user.roles.join(','));
        }
      }
      
      // Gateway identification and tracing
      proxyReq.setHeader('X-Gateway-Request', 'true');
      proxyReq.setHeader('X-Gateway-Version', '1.0.0');
      proxyReq.setHeader('X-Request-ID', req.requestId);
      proxyReq.setHeader('X-Service-Name', 'gateway');
      
      // Timestamp for tracking
      proxyReq.setHeader('X-Gateway-Timestamp', new Date().toISOString());
      
      logger.debug(`Proxying ${req.method} ${req.path} to ${serviceName}`, {
        requestId: req.requestId,
        targetService: serviceName,
        userId: req.user?.id
      });
    },

    onProxyRes: (proxyRes, req, res) => {
      // Add response headers
      proxyRes.headers['x-served-by'] = serviceName;
      proxyRes.headers['x-gateway-service'] = 'claude-analysis-gateway';
      proxyRes.headers['x-request-id'] = req.requestId;
      
      // Record service response for health monitoring
      const responseTime = Date.now() - req.startTime;
      health.recordServiceResponse(serviceName, proxyRes.statusCode < 400, responseTime);
      
      // Check for sync-related headers from services
      const syncVersion = proxyRes.headers['x-shared-knowledge-version'];
      if (syncVersion) {
        health.recordServiceSyncVersion(serviceName, syncVersion);
      }
    },

    onError: (err, req, res) => {
      logger.error(`Proxy error for ${serviceName}`, {
        error: err.message,
        requestId: req.requestId,
        path: req.path,
        method: req.method
      }, err);
      
      health.recordServiceResponse(serviceName, false);
      
      if (res.headersSent) return;
      
      // Determine error type and appropriate response
      let errorCode = 'SERVICE_UNAVAILABLE';
      let statusCode = 503;
      let suggestion = 'Please try again in a few moments';
      
      if (err.code === 'ECONNREFUSED') {
        errorCode = 'SERVICE_UNAVAILABLE';
        suggestion = 'The service is temporarily unavailable';
      } else if (err.code === 'ETIMEDOUT') {
        errorCode = 'GATEWAY_TIMEOUT';
        statusCode = 504;
        suggestion = 'The request timed out, please try again';
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
          requestId: req.requestId,
          service: 'gateway',
          targetService: serviceName
        }
      });
    }
  });
};

// Service routes with enhanced authentication and rate limiting

// Auth service - no auth required for login/register
app.use('/api/auth', 
  createRateLimit(15 * 60 * 1000, 20), // 20 auth requests per 15 minutes
  createEnhancedServiceProxy('auth', config.services.auth)
);

// Comment service - requires auth and has job-specific rate limiting
app.use('/api/comments', 
  auth.requireAuth(),
  createRateLimit(60 * 60 * 1000, 10, (req) => `${req.user?.id || req.ip}_comments`), // 10 jobs per hour per user
  createEnhancedServiceProxy('comment', config.services.comment)
);

// Industry service - minimal rate limiting
app.use('/api/industries', 
  createRateLimit(60 * 1000, 30), // 30 requests per minute
  createEnhancedServiceProxy('industry', config.services.industry)
);

// NPS service - requires auth
app.use('/api/nps', 
  auth.requireAuth(),
  createRateLimit(60 * 60 * 1000, 20, (req) => `${req.user?.id || req.ip}_nps`), // 20 NPS requests per hour per user
  createEnhancedServiceProxy('nps', config.services.nps)
);

// Orchestrated endpoints for better service synchronization
app.get('/api/orchestration/user/:userId/dashboard', 
  auth.requireAuth(),
  async (req, res) => {
    try {
      const { userId } = req.params;
      
      // Ensure user can only access their own dashboard or is admin
      if (req.user.id !== userId && !req.user.roles.includes('admin')) {
        return res.status(403).json({
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'You can only access your own dashboard',
            suggestion: 'Contact administrator if you need broader access'
          }
        });
      }
      
      const dashboard = await orchestrator.getUserDashboard(userId, req.requestId);
      
      res.json({
        success: true,
        data: dashboard,
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.requestId,
          service: 'gateway'
        }
      });
      
    } catch (error) {
      logger.error('Dashboard orchestration failed', {
        userId: req.params.userId,
        requestId: req.requestId,
        error: error.message
      }, error);
      
      res.status(500).json({
        success: false,
        error: {
          code: 'ORCHESTRATION_ERROR',
          message: 'Failed to load user dashboard',
          suggestion: 'Please try again later'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.requestId,
          service: 'gateway'
        }
      });
    }
  }
);

// Sync status endpoint for monitoring
app.get('/api/gateway/sync/status', auth.requireAuth(), (req, res) => {
  const syncStatus = health.getSyncStatus();
  
  res.json({
    success: true,
    data: {
      overallStatus: syncStatus.status,
      services: syncStatus.services,
      lastGlobalSync: syncStatus.lastSync,
      outOfSyncServices: syncStatus.services.filter(s => !s.inSync),
      recommendations: health.getSyncRecommendations()
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      service: 'gateway'
    }
  });
});

// Force sync endpoint (admin only)
app.post('/api/gateway/sync/force', 
  auth.requireAuth(),
  auth.requireRole(['admin']),
  async (req, res) => {
    try {
      logger.info('Force sync initiated', { userId: req.user.id, requestId: req.requestId });
      
      const syncResult = await health.forceSyncCheck();
      
      res.json({
        success: true,
        data: syncResult,
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.requestId,
          service: 'gateway'
        }
      });
      
    } catch (error) {
      logger.error('Force sync failed', { requestId: req.requestId }, error);
      
      res.status(500).json({
        success: false,
        error: {
          code: 'SYNC_ERROR',
          message: 'Failed to force synchronization',
          suggestion: 'Check service health and try again'
        }
      });
    }
  }
);

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
  const path = require('path');
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err) {
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
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    requestId: req.requestId,
    path: req.path,
    method: req.method,
    userId: req.user?.id
  }, err);
  
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
  logger.info(`Enhanced Gateway started on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`Services configured: ${Object.keys(config.services).join(', ')}`);
  
  // Initialize health checks and sync monitoring
  health.initialize();
  orchestrator.initialize();
});

// Graceful shutdown with cleanup
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received, shutting down gracefully`);
  
  server.close(async () => {
    try {
      await health.cleanup();
      await orchestrator.cleanup();
      logger.info('Gateway server closed cleanly');
      process.exit(0);
    } catch (error) {
      logger.error('Error during shutdown', {}, error);
      process.exit(1);
    }
  });
  
  // Force exit after 30 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;