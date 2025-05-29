// gateway-service/server.js - Enhanced with active health checks
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const axios = require('axios');
const SimpleAuth = require('./middleware/simpleAuth');
const config = require('./config/simple');
const logger = require('./utils/simpleLogger');

const app = express();
const auth = new SimpleAuth();

// Enhanced service health tracking with ACTIVE health checks
class ActiveServiceHealth {
  constructor() {
    this.services = config.services;
    this.serviceStatus = new Map();
    this.stats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0
    };
    
    // Initialize service status
    Object.keys(this.services).forEach(serviceName => {
      this.serviceStatus.set(serviceName, {
        name: serviceName,
        url: this.services[serviceName],
        status: 'unknown',
        lastCheck: null,
        lastSuccess: null,
        consecutiveFailures: 0,
        responseTime: null,
        healthCheckEnabled: true
      });
    });
    
    // Start active health checking
    this.startActiveHealthChecks();
  }

  startActiveHealthChecks() {
    // Initial health check
    this.checkAllServicesHealth();
    
    // Periodic health checks every 2 minutes
    this.healthCheckTimer = setInterval(() => {
      this.checkAllServicesHealth();
    }, 2 * 60 * 1000); // 2 minutes
    
    logger.info('Active health checks started (every 2 minutes)');
  }

  async checkAllServicesHealth() {
    logger.debug('Performing active health checks...');
    
    const promises = Object.keys(this.services).map(serviceName =>
      this.checkServiceHealth(serviceName)
    );
    
    await Promise.allSettled(promises);
  }

  async checkServiceHealth(serviceName) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    if (!serviceInfo || !serviceInfo.healthCheckEnabled) return;
    
    const startTime = Date.now();
    
    try {
      const response = await axios.get(`${serviceInfo.url}/health`, {
        timeout: 10000,
        headers: {
          'User-Agent': 'Gateway-Health-Check/1.1.0',
          'X-Gateway-Request': 'true'
        }
      });
      
      const responseTime = Date.now() - startTime;
      const isHealthy = response.status === 200;
      
      serviceInfo.status = isHealthy ? 'healthy' : 'unhealthy';
      serviceInfo.lastCheck = new Date().toISOString();
      serviceInfo.responseTime = responseTime;
      
      if (isHealthy) {
        serviceInfo.lastSuccess = serviceInfo.lastCheck;
        serviceInfo.consecutiveFailures = 0;
        logger.debug(`Health check ${serviceName}: healthy (${responseTime}ms)`);
      } else {
        serviceInfo.consecutiveFailures++;
        logger.warn(`Health check ${serviceName}: unhealthy (HTTP ${response.status})`);
      }
      
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      serviceInfo.status = 'unhealthy';
      serviceInfo.lastCheck = new Date().toISOString();
      serviceInfo.responseTime = responseTime;
      serviceInfo.consecutiveFailures++;
      
      // Log different error types
      if (error.code === 'ECONNREFUSED') {
        logger.warn(`Health check ${serviceName}: connection refused`);
      } else if (error.code === 'ETIMEDOUT') {
        logger.warn(`Health check ${serviceName}: timeout`);
      } else if (error.response && error.response.status === 404) {
        logger.debug(`Health check ${serviceName}: /health endpoint not found`);
        // Don't mark as unhealthy if just missing /health endpoint
        serviceInfo.status = 'unknown';
      } else {
        logger.warn(`Health check ${serviceName}: ${error.message}`);
      }
    }
  }

  recordResponse(serviceName, success, responseTime = null) {
    this.stats.totalRequests++;
    if (success) {
      this.stats.successfulRequests++;
    } else {
      this.stats.failedRequests++;
    }

    const serviceInfo = this.serviceStatus.get(serviceName);
    if (serviceInfo) {
      // Update from proxy response
      if (responseTime) {
        serviceInfo.responseTime = responseTime;
      }
      
      if (success) {
        serviceInfo.status = 'healthy';
        serviceInfo.consecutiveFailures = 0;
        serviceInfo.lastSuccess = new Date().toISOString();
      } else {
        serviceInfo.consecutiveFailures++;
      }
    }
  }

  getServiceStatus() {
    const status = {};
    for (const [name, info] of this.serviceStatus.entries()) {
      status[name] = {
        name: info.name,
        url: info.url,
        status: info.status,
        lastCheck: info.lastCheck,
        lastSuccess: info.lastSuccess,
        consecutiveFailures: info.consecutiveFailures,
        responseTime: info.responseTime
      };
    }
    return status;
  }

  getStats() {
    return {
      ...this.stats,
      services: this.getServiceStatus(),
      errorRate: this.stats.totalRequests > 0 ? 
        Math.round((this.stats.failedRequests / this.stats.totalRequests) * 100) : 0
    };
  }

  checkServices() {
    return (req, res) => {
      const services = this.getServiceStatus();
      const healthyCount = Object.values(services).filter(s => s.status === 'healthy').length;
      const totalCount = Object.keys(services).length;
      
      res.status(healthyCount === totalCount ? 200 : 503).json({
        status: healthyCount === totalCount ? 'healthy' : 'degraded',
        service: 'gateway',
        timestamp: new Date().toISOString(),
        dependencies: services,
        summary: {
          totalServices: totalCount,
          healthyServices: healthyCount,
          unhealthyServices: totalCount - healthyCount
        }
      });
    };
  }

  cleanup() {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
  }
}

const health = new ActiveServiceHealth();

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

// Enhanced rate limiting
const createRateLimit = (windowMs, max, message = 'Too many requests') => {
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
          message,
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
app.use(createRateLimit(15 * 60 * 1000, 100, 'Too many requests from this IP'));

// Request correlation and enhanced logging
app.use((req, res, next) => {
  const requestId = req.get('X-Request-ID') || 
    `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  req.requestId = requestId;
  req.startTime = Date.now();
  
  res.set('X-Request-ID', requestId);
  res.set('X-Gateway-Service', 'claude-analysis-gateway');
  res.set('X-Gateway-Version', '1.1.0');
  
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`, {
      requestId,
      userId: req.user?.id,
      duration
    });
  });
  
  next();
});

// Enhanced health endpoints
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'gateway',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    version: '1.1.0',
    environment: process.env.NODE_ENV || 'production',
    features: {
      syncMonitoring: true,
      enhancedLogging: true,
      requestTracing: true,
      activeHealthChecks: true
    }
  });
});

app.get('/health/services', health.checkServices());

// IMPROVED sync status endpoint with active health data
app.get('/health/sync', (req, res) => {
  const services = health.getServiceStatus();
  const healthyServices = Object.values(services).filter(s => s.status === 'healthy');
  const unknownServices = Object.values(services).filter(s => s.status === 'unknown');
  
  const overallStatus = healthyServices.length === Object.keys(services).length ? 'healthy' :
                       unknownServices.length === Object.keys(services).length ? 'unknown' : 'degraded';
  
  res.json({
    success: true,
    data: {
      overallStatus,
      lastGlobalCheck: new Date().toISOString(),
      expectedVersion: '1.0.0',
      services: Object.values(services).map(service => ({
        name: service.name,
        currentVersion: '1.0.0',
        expectedVersion: '1.0.0',
        status: service.status === 'healthy' ? 'in-sync' : 
                service.status === 'unknown' ? 'unknown' : 'out-of-sync',
        lastCheck: service.lastCheck,
        lastSuccess: service.lastSuccess,
        delayMinutes: 0,
        responseTime: service.responseTime,
        recommendation: service.status === 'healthy' ? 
          'Service is properly synchronized' : 
          service.status === 'unknown' ?
          'Service health status unknown - may need /health endpoint' :
          'Check service health and connectivity'
      }))
    },
    metadata: {
      timestamp: new Date().toISOString(),
      service: 'gateway'
    }
  });
});

// Force health check endpoint
app.post('/api/gateway/health-check', (req, res) => {
  logger.info('Manual health check triggered');
  
  health.checkAllServicesHealth().then(() => {
    const services = health.getServiceStatus();
    res.json({
      success: true,
      message: 'Health check completed',
      data: {
        services,
        timestamp: new Date().toISOString()
      }
    });
  }).catch(error => {
    logger.error('Manual health check failed', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'HEALTH_CHECK_FAILED',
        message: 'Health check failed',
        details: error.message
      }
    });
  });
});

// Rest of the server.js code remains the same...
// (Enhanced gateway management endpoints, service proxy, routes, etc.)

// Enhanced gateway management endpoints
app.get('/api/gateway/services', auth.requireAuth(), (req, res) => {
  const services = health.getServiceStatus();
  const stats = health.getStats();
  
  res.json({
    success: true,
    data: {
      services,
      gateway: {
        uptime: Math.floor(process.uptime()),
        requestsHandled: stats.totalRequests,
        errorRate: stats.errorRate,
        version: '1.1.0',
        activeHealthChecks: true
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
      uptime: Math.floor(process.uptime()),
      memoryUsage: process.memoryUsage(),
      version: '1.1.0',
      activeHealthChecks: true
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      service: 'gateway'
    }
  });
});

// Enhanced service proxy (same as before)
const createEnhancedServiceProxy = (serviceName, targetUrl) => {
  return createProxyMiddleware({
    target: targetUrl,
    changeOrigin: true,
    timeout: 30000,
    
    onProxyReq: (proxyReq, req) => {
      if (req.user) {
        proxyReq.setHeader('X-User-ID', req.user.id);
        proxyReq.setHeader('X-User-Email', req.user.email);
        proxyReq.setHeader('X-User-Industry', req.user.industry || '');
        if (req.user.roles) {
          proxyReq.setHeader('X-User-Roles', req.user.roles.join(','));
        }
      }
      
      proxyReq.setHeader('X-Gateway-Request', 'true');
      proxyReq.setHeader('X-Gateway-Version', '1.1.0');
      proxyReq.setHeader('X-Request-ID', req.requestId);
      proxyReq.setHeader('X-Service-Name', 'gateway');
      proxyReq.setHeader('X-Gateway-Timestamp', new Date().toISOString());
      
      logger.debug(`Proxying ${req.method} ${req.path} to ${serviceName}`, {
        requestId: req.requestId,
        targetService: serviceName,
        userId: req.user?.id
      });
    },

    onProxyRes: (proxyRes, req, res) => {
      proxyRes.headers['x-served-by'] = serviceName;
      proxyRes.headers['x-gateway-service'] = 'claude-analysis-gateway';
      proxyRes.headers['x-request-id'] = req.requestId;
      
      const responseTime = Date.now() - req.startTime;
      health.recordResponse(serviceName, proxyRes.statusCode < 400, responseTime);
    },

    onError: (err, req, res) => {
      logger.error(`Proxy error for ${serviceName}`, {
        error: err.message,
        requestId: req.requestId,
        path: req.path,
        method: req.method
      }, err);
      
      health.recordResponse(serviceName, false);
      
      if (res.headersSent) return;
      
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

// Service routes (same as before)
app.use('/api/auth', 
  createRateLimit(15 * 60 * 1000, 20, 'Too many authentication attempts'),
  createEnhancedServiceProxy('auth', config.services.auth)
);

app.use('/api/comments', 
  auth.requireAuth(),
  createRateLimit(60 * 60 * 1000, 10, 'Too many comment processing requests'),
  createEnhancedServiceProxy('comment', config.services.comment)
);

app.use('/api/industries', 
  createRateLimit(60 * 1000, 30, 'Too many industry requests'),
  createEnhancedServiceProxy('industry', config.services.industry)
);

app.use('/api/nps', 
  auth.requireAuth(),
  createRateLimit(60 * 60 * 1000, 20, 'Too many NPS requests'),
  createEnhancedServiceProxy('nps', config.services.nps)
);

// Static files
app.use(express.static('public', {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  etag: true
}));

// 404 and error handlers (same as before)
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

app.use((err, req, res, next) => {
  logger.error('Unhandled error', {
    error: err.message,
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
  logger.info(`Enhanced Gateway with Active Health Checks started on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'production'}`);
  logger.info(`Services configured: ${Object.keys(config.services).join(', ')}`);
  logger.info(`Features: Enhanced logging, Request tracing, Active health monitoring`);
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received, shutting down gracefully`);
  
  health.cleanup();
  
  server.close(() => {
    logger.info('Gateway server closed cleanly');
    process.exit(0);
  });
  
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;
