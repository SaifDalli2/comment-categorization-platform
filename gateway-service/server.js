// gateway-service/server.js - Streamlined version
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const SecurityMiddleware = require('./middleware/security');
const SimpleHealthChecker = require('./services/SimpleHealthChecker');
const config = require('./config/simple');
const logger = require('./utils/logger');
const metrics = require('./utils/metrics');

const app = express();
const security = new SecurityMiddleware();
const healthChecker = new SimpleHealthChecker();

// Essential middleware only
app.use(express.json({ limit: '10mb' }));
app.use(metrics.middleware());
app.use(...security.apply());

// Health endpoints
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'gateway',
    timestamp: new Date().toISOString(),
    services: healthChecker.getHealthStatus()
  });
});

app.get('/metrics', async (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.end(await metrics.getMetrics());
});

// Service proxy routes
const createProxy = (serviceName) => {
  return createProxyMiddleware({
    target: 'http://placeholder',
    changeOrigin: true,
    router: (req) => {
      const serviceUrl = healthChecker.getServiceUrl(serviceName);
      if (!serviceUrl) {
        throw new Error(`Service ${serviceName} unavailable`);
      }
      return serviceUrl;
    },
    onError: (err, req, res) => {
      logger.error(`Proxy error for ${serviceName}`, { error: err.message });
      res.status(503).json({
        success: false,
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: `${serviceName} service is temporarily unavailable`
        }
      });
    },
    onProxyReq: (proxyReq, req) => {
      // Forward auth headers
      if (req.userContext?.token) {
        proxyReq.setHeader('Authorization', `Bearer ${req.userContext.token}`);
      }
      proxyReq.setHeader('X-Gateway-Request', 'true');
    }
  });
};

// Route setup
app.use('/api/auth', createProxy('auth'));
app.use('/api/comments', createProxy('comment'));
app.use('/api/industries', createProxy('industry'));
app.use('/api/nps', createProxy('nps'));

// Static files
app.use(express.static('public'));

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'RESOURCE_NOT_FOUND',
      message: 'The requested resource was not found'
    }
  });
});

// Start server
const PORT = config.get('server.port');
app.listen(PORT, () => {
  logger.info(`Gateway started on port ${PORT}`);
});

module.exports = app;