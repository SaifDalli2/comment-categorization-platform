// gateway-service/routes/index.js
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const ServiceRegistry = require('../services/ServiceRegistry');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

class GatewayRoutes {
  constructor() {
    this.router = express.Router();
    this.serviceRegistry = new ServiceRegistry();
    this.setupRoutes();
    this.setupServiceRegistryEvents();
  }

  setupServiceRegistryEvents() {
    // Listen for service health events
    this.serviceRegistry.on('serviceRecovered', ({ serviceName, instance }) => {
      logger.info('Service recovered - routing resumed', {
        service: {
          name: serviceName,
          instanceId: instance.id,
          url: instance.url
        }
      });
    });

    this.serviceRegistry.on('serviceUnhealthy', ({ serviceName, instance, error }) => {
      logger.warn('Service unhealthy - routing affected', {
        service: {
          name: serviceName,
          instanceId: instance.id,
          url: instance.url
        },
        error: {
          message: error.message
        }
      });
    });
  }

  setupRoutes() {
    // Service registry endpoints
    this.router.get('/api/gateway/services', (req, res) => {
      res.json({
        success: true,
        data: this.serviceRegistry.getAllServices(),
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'],
          service: 'gateway'
        }
      });
    });

    this.router.get('/api/gateway/stats', (req, res) => {
      res.json({
        success: true,
        data: this.serviceRegistry.getStats(),
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'],
          service: 'gateway'
        }
      });
    });

    // Enhanced health check with service dependencies
    this.router.get('/health/services', (req, res) => {
      const stats = this.serviceRegistry.getStats();
      const isHealthy = stats.healthyInstances > 0 && stats.openCircuitBreakers === 0;
      
      res.status(isHealthy ? 200 : 503).json({
        status: isHealthy ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        service: 'gateway',
        dependencies: stats.services,
        summary: {
          totalServices: stats.totalServices,
          healthyInstances: stats.healthyInstances,
          unhealthyInstances: stats.unhealthyInstances,
          openCircuitBreakers: stats.openCircuitBreakers
        }
      });
    });

    // Authentication service routes
    this.router.use('/api/auth', this.createServiceProxy('auth'));

    // Comment processing service routes
    this.router.use('/api/comments', this.createServiceProxy('comment'));

    // Industry configuration service routes
    this.router.use('/api/industries', this.createServiceProxy('industry'));

    // NPS analytics service routes
    this.router.use('/api/nps', this.createServiceProxy('nps'));

    // Legacy monolith support (if configured)
    if (process.env.MONOLITH_SERVICE_URL) {
      this.router.use('/api/legacy', this.createServiceProxy('monolith'));
    }

    // Development endpoints
    if (process.env.NODE_ENV === 'development') {
      this.setupDevelopmentRoutes();
    }
  }

  createServiceProxy(serviceName) {
    return createProxyMiddleware({
      target: 'http://placeholder', // This will be overridden by router function
      changeOrigin: true,
      timeout: parseInt(process.env.SERVICE_TIMEOUT) || 30000,
      
      // Dynamic target selection using service registry
      router: (req) => {
        const service = this.serviceRegistry.getService(serviceName);
        
        if (!service) {
          throw new Error(`Service ${serviceName} not available`);
        }
        
        return service.url;
      },

      // Request transformation
      onProxyReq: (proxyReq, req, res) => {
        const startTime = Date.now();
        req.proxyStartTime = startTime;
        
        // Add service-to-service headers following shared knowledge
        if (req.serviceHeaders) {
          Object.entries(req.serviceHeaders).forEach(([key, value]) => {
            proxyReq.setHeader(key, value);
          });
        }

        // Add gateway identification
        proxyReq.setHeader('X-Forwarded-By', 'claude-analysis-gateway');
        proxyReq.setHeader('X-Gateway-Version', process.env.npm_package_version || '1.0.0');
        
        // Forward user context if available
        if (req.userContext) {
          proxyReq.setHeader('X-User-ID', req.userContext.userId);
          proxyReq.setHeader('X-User-Email', req.userContext.email);
          if (req.userContext.roles && req.userContext.roles.length > 0) {
            proxyReq.setHeader('X-User-Roles', req.userContext.roles.join(','));
          }
        }

        logger.info('Proxying request', {
          proxy: {
            serviceName,
            method: req.method,
            path: req.path,
            target: proxyReq.getHeader('host'),
            requestId: req.headers['x-request-id'],
            userId: req.userContext?.userId
          }
        });
      },

      // Response transformation and metrics
      onProxyRes: (proxyRes, req, res) => {
        const responseTime = Date.now() - req.proxyStartTime;
        const isSuccess = proxyRes.statusCode < 400;
        
        // Get the service instance that handled this request
        const service = this.serviceRegistry.getService(serviceName);
        if (service) {
          this.serviceRegistry.recordRequest(serviceName, service.id, isSuccess, responseTime);
        }

        // Add response headers
        proxyRes.headers['X-Served-By'] = serviceName;
        proxyRes.headers['X-Response-Time'] = `${responseTime}ms`;
        proxyRes.headers['X-Gateway-Service'] = 'claude-analysis-gateway';

        // Record service metrics
        metrics.recordServiceRequest(serviceName, req.method, proxyRes.statusCode, responseTime, isSuccess);

        logger.info('Request completed', {
          proxy: {
            serviceName,
            method: req.method,
            path: req.path,
            statusCode: proxyRes.statusCode,
            responseTime,
            success: isSuccess,
            requestId: req.headers['x-request-id'],
            userId: req.userContext?.userId
          }
        });
      },

      // Error handling
      onError: (err, req, res) => {
        const responseTime = Date.now() - (req.proxyStartTime || Date.now());
        
        // Record failed request
        const service = this.serviceRegistry.getService(serviceName);
        if (service) {
          this.serviceRegistry.recordRequest(serviceName, service.id, false, responseTime);
        }

        logger.error('Proxy request failed', {
          proxy: {
            serviceName,
            method: req.method,
            path: req.path,
            responseTime,
            requestId: req.headers['x-request-id'],
            userId: req.userContext?.userId
          }
        }, err);

        // Record failed service metrics
        metrics.recordServiceRequest(serviceName, req.method, statusCode, responseTime, false);
            code: err.code
          },
          metadata: {
            serviceName,
            method: req.method,
            path: req.path,
            responseTime,
            requestId: req.headers['x-request-id'],
            userId: req.userContext?.userId
          }
        }));

        // Return standardized error response
        if (!res.headersSent) {
          const errorResponse = {
            success: false,
            error: {
              code: 'SERVICE_UNAVAILABLE',
              message: `The ${serviceName} service is currently unavailable`,
              suggestion: 'Please try again later or contact support if the problem persists'
            },
            metadata: {
              timestamp: new Date().toISOString(),
              requestId: req.headers['x-request-id'] || 'unknown',
              service: 'gateway',
              targetService: serviceName
            }
          };

          // Determine appropriate status code
          let statusCode = 503; // Service Unavailable
          if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
            statusCode = 503;
          } else if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT') {
            statusCode = 504; // Gateway Timeout
          }

          res.status(statusCode).json(errorResponse);
        }
      },

      // Logging
      logLevel: process.env.NODE_ENV === 'development' ? 'debug' : 'warn',
      
      // Security
      secure: process.env.NODE_ENV === 'production',
      
      // Path rewriting (remove /api prefix for services)
      pathRewrite: {
        [`^/api/${serviceName}`]: ''
      }
    });
  }

  setupDevelopmentRoutes() {
    // Service registry management endpoints for development
    this.router.post('/api/gateway/services/:serviceName/register', (req, res) => {
      try {
        const { serviceName } = req.params;
        const { urls, healthPath, readyPath, metadata } = req.body;
        
        if (!urls || !Array.isArray(urls) || urls.length === 0) {
          return res.status(400).json({
            success: false,
            error: {
              code: 'INVALID_INPUT',
              message: 'URLs array is required for service registration'
            }
          });
        }

        const service = this.serviceRegistry.dynamicRegister(serviceName, {
          urls,
          healthPath: healthPath || '/health',
          readyPath: readyPath || '/ready',
          metadata: metadata || {}
        });

        res.json({
          success: true,
          data: {
            serviceName,
            registered: !!service,
            message: 'Service registered successfully'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        res.status(400).json({
          success: false,
          error: {
            code: 'REGISTRATION_FAILED',
            message: error.message
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      }
    });

    this.router.delete('/api/gateway/services/:serviceName', (req, res) => {
      try {
        const { serviceName } = req.params;
        const removed = this.serviceRegistry.unregisterService(serviceName);
        
        res.json({
          success: true,
          data: {
            serviceName,
            removed,
            message: removed ? 'Service unregistered successfully' : 'Service not found'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        res.status(400).json({
          success: false,
          error: {
            code: 'UNREGISTRATION_FAILED',
            message: error.message
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      }
    });

    // Force health check endpoint
    this.router.post('/api/gateway/health-check', async (req, res) => {
      try {
        await this.serviceRegistry.performHealthChecks();
        
        res.json({
          success: true,
          data: {
            message: 'Health checks performed',
            results: this.serviceRegistry.getAllServices()
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          error: {
            code: 'HEALTH_CHECK_FAILED',
            message: error.message
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      }
    });
  }

  // Get the router instance
  getRouter() {
    return this.router;
  }

  // Get service registry instance (for auth middleware integration)
  getServiceRegistry() {
    return this.serviceRegistry;
  }

  // Graceful shutdown
  async shutdown() {
    logger.info('Gateway routes shutting down');
    await this.serviceRegistry.shutdown();
  }
}

module.exports = GatewayRoutes;