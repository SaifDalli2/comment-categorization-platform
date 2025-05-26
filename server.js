// gateway-service/server.js - Optimized Gateway
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const SimpleAuth = require('./middleware/simpleAuth');
const SimpleHealth = require('./services/simpleHealth');
const config = require('./config/simple');
const logger = require('./utils/simpleLogger');

const app = express();
const auth = new SimpleAuth();
const health = new SimpleHealth();

// Basic middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Security
app.use(helmet({
  contentSecurityPolicy: false, // Let frontend handle CSP
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: config.security.corsOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
}));

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests', retryAfter: 900 },
  standardHeaders: true,
  legacyHeaders: false
}));

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
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
    version: process.env.npm_package_version || '1.0.0'
  });
});

app.get('/health/services', health.checkServices());

app.get('/api/gateway/services', (req, res) => {
  const services = health.getServiceStatus();
  res.json({
    success: true,
    data: services,
    metadata: {
      timestamp: new Date().toISOString(),
      service: 'gateway'
    }
  });
});

// Service proxy factory
const createServiceProxy = (serviceName, targetUrl) => {
  return createProxyMiddleware({
    target: targetUrl,
    changeOrigin: true,
    timeout: 30000,
    
    onProxyReq: (proxyReq, req) => {
      // Forward auth headers
      if (req.user) {
        proxyReq.setHeader('X-User-ID', req.user.userId || req.user.id);
        proxyReq.setHeader('X-User-Email', req.user.email);
        if (req.user.roles) {
          proxyReq.setHeader('X-User-Roles', req.user.roles.join(','));
        }
      }
      
      // Gateway identification
      proxyReq.setHeader('X-Gateway-Request', 'true');
      proxyReq.setHeader('X-Gateway-Version', '1.0.0');
      
      logger.debug(`Proxying ${req.method} ${req.path} to ${serviceName}`);
    },

    onProxyRes: (proxyRes, req) => {
      // Add response headers
      proxyRes.headers['x-served-by'] = serviceName;
      proxyRes.headers['x-gateway-service'] = 'claude-analysis-gateway';
      
      health.recordServiceResponse(serviceName, proxyRes.statusCode < 400);
    },

    onError: (err, req, res) => {
      logger.error(`Proxy error for ${serviceName}: ${err.message}`);
      health.recordServiceResponse(serviceName, false);
      
      if (res.headersSent) return;
      
      res.status(503).json({
        success: false,
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: `${serviceName} service is temporarily unavailable`,
          suggestion: 'Please try again in a few moments'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          service: 'gateway',
          targetService: serviceName
        }
      });
    }
  });
};

// Service routes with optional authentication
app.use('/api/auth', createServiceProxy('auth', config.services.auth));

app.use('/api/comments', 
  auth.requireAuth(), // Comments need authentication
  createServiceProxy('comment', config.services.comment)
);

app.use('/api/industries', createServiceProxy('industry', config.services.industry));

app.use('/api/nps', 
  auth.requireAuth(), // NPS needs authentication
  createServiceProxy('nps', config.services.nps)
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
        }
      });
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`, err);
  
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
      service: 'gateway'
    }
  });
});

const PORT = config.port;
const server = app.listen(PORT, () => {
  logger.info(`Gateway started on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`Services configured: ${Object.keys(config.services).join(', ')}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Gateway server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    logger.info('Gateway server closed');
    process.exit(0);
  });
});

module.exports = app;