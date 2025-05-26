// gateway-service/middleware/monitoring.js
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

class MonitoringMiddleware {
  constructor() {
    this.requestsInProgress = new Map();
    this.performanceThresholds = {
      slow: parseInt(process.env.SLOW_REQUEST_THRESHOLD) || 5000, // 5 seconds
      critical: parseInt(process.env.CRITICAL_REQUEST_THRESHOLD) || 10000 // 10 seconds
    };
    this.serviceMetricsInterval = null;
  }

  // Main monitoring middleware that combines logging and metrics
  monitor() {
    return (req, res, next) => {
      const startTime = Date.now();
      const requestId = req.headers['x-request-id'] || this.generateRequestId();
      
      // Ensure request ID is set
      req.headers['x-request-id'] = requestId;
      res.setHeader('X-Request-ID', requestId);
      
      // Track request in progress
      this.requestsInProgress.set(requestId, {
        startTime,
        method: req.method,
        url: req.originalUrl || req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.userContext?.userId
      });
      
      // Update active connections metric
      metrics.updateActiveConnections(this.requestsInProgress.size);
      
      // Log request start
      logger.debug('Request started', {
        request: {
          id: requestId,
          method: req.method,
          url: req.originalUrl || req.url,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          contentLength: req.get('Content-Length') || 0
        }
      });

      // Override res.end to capture completion metrics
      const originalEnd = res.end;
      res.end = (...args) => {
        const responseTime = Date.now() - startTime;
        
        // Remove from in-progress tracking
        this.requestsInProgress.delete(requestId);
        metrics.updateActiveConnections(this.requestsInProgress.size);
        
        // Record metrics
        this.recordRequestMetrics(req, res, responseTime);
        
        // Log request completion
        this.logRequestCompletion(req, res, responseTime);
        
        // Check for performance issues
        this.checkPerformance(req, res, responseTime);
        
        // Call original end method
        originalEnd.apply(res, args);
      };

      next();
    };
  }

  // Service proxy monitoring middleware
  serviceProxyMonitor(serviceName) {
    return (req, res, next) => {
      const startTime = Date.now();
      const requestId = req.headers['x-request-id'];
      
      // Store proxy start time for later use
      req.proxyStartTime = startTime;
      req.targetService = serviceName;
      
      logger.debug('Service proxy request started', {
        proxy: {
          serviceName,
          requestId,
          method: req.method,
          path: req.path
        }
      });
      
      next();
    };
  }

  // Authentication monitoring
  authMonitor() {
    return (req, res, next) => {
      const originalUser = req.user;
      
      // Monitor auth state changes
      Object.defineProperty(req, 'user', {
        get: () => originalUser,
        set: (value) => {
          if (value && !originalUser) {
            // User just authenticated
            logger.authentication('token_validation', req, true, null, {
              userId: value.id,
              email: value.email
            });
            
            metrics.recordAuthRequest('token_validation', true);
          }
          // Update the original value
          req._user = value;
        },
        configurable: true
      });
      
      next();
    };
  }

  // CORS monitoring
  corsMonitor() {
    return (req, res, next) => {
      const origin = req.get('Origin');
      
      if (req.method === 'OPTIONS') {
        // CORS preflight request
        metrics.recordCorsPreflight(origin, req.get('Access-Control-Request-Method'));
        
        logger.debug('CORS preflight request', {
          cors: {
            origin,
            requestedMethod: req.get('Access-Control-Request-Method'),
            requestedHeaders: req.get('Access-Control-Request-Headers')
          }
        });
      }
      
      // Monitor response for CORS headers
      const originalEnd = res.end;
      res.end = (...args) => {
        const corsAllowed = res.getHeader('Access-Control-Allow-Origin') !== undefined;
        
        if (origin) {
          metrics.recordCorsRequest(origin, corsAllowed);
          
          if (!corsAllowed) {
            logger.warn('CORS request blocked', {
              cors: {
                origin,
                method: req.method,
                path: req.path
              }
            });
          }
        }
        
        originalEnd.apply(res, args);
      };
      
      next();
    };
  }

  // Rate limiting monitoring
  rateLimitMonitor() {
    return (req, res, next) => {
      const originalStatus = res.status;
      
      res.status = function(code) {
        if (code === 429) {
          // Rate limit hit
          const limitType = this.getHeader('X-RateLimit-Limit') ? 'general' : 'unknown';
          
          metrics.recordRateLimit(limitType, req.path, true);
          
          logger.warn('Rate limit exceeded', {
            rateLimit: {
              limitType,
              path: req.path,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
              userId: req.userContext?.userId
            }
          });
        }
        
        return originalStatus.call(this, code);
      };
      
      next();
    };
  }

  // Security event monitoring
  securityMonitor() {
    return (req, res, next) => {
      // Monitor for suspicious patterns in URLs
      const suspiciousPatterns = [
        /\.\.\//g,
        /<script/gi,
        /union.*select/gi,
        /exec\(/gi,
        /eval\(/gi
      ];

      const url = req.originalUrl || req.url;
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(url)) {
          logger.security('suspicious_request', req, {
            pattern: pattern.toString(),
            url
          }, 'high');
          break;
        }
      }

      // Monitor authentication failures
      const originalStatus = res.status;
      res.status = function(code) {
        if (code === 401) {
          logger.security('authentication_failure', req, {
            statusCode: code,
            path: req.path
          }, 'medium');
        } else if (code === 403) {
          logger.security('authorization_failure', req, {
            statusCode: code,
            path: req.path,
            userId: req.userContext?.userId
          }, 'medium');
        }
        
        return originalStatus.call(this, code);
      };
      
      next();
    };
  }

  // Record request metrics
  recordRequestMetrics(req, res, responseTime) {
    const route = req.route?.path || req.path || 'unknown';
    const requestSize = parseInt(req.get('Content-Length')) || 0;
    const responseSize = parseInt(res.get('Content-Length')) || 0;
    
    metrics.recordHttpRequest(
      req.method,
      route,
      res.statusCode,
      responseTime,
      requestSize,
      responseSize
    );
  }

  // Log request completion with structured data
  logRequestCompletion(req, res, responseTime) {
    const metadata = {
      request: {
        id: req.headers['x-request-id'],
        method: req.method,
        url: req.originalUrl || req.url,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        contentLength: parseInt(req.get('Content-Length')) || 0
      },
      response: {
        statusCode: res.statusCode,
        statusMessage: res.statusMessage,
        contentLength: parseInt(res.get('Content-Length')) || 0,
        responseTime
      },
      user: req.userContext ? {
        userId: req.userContext.userId,
        email: req.userContext.email,
        roles: req.userContext.roles
      } : undefined,
      performance: {
        category: this.getPerformanceCategory(responseTime)
      }
    };

    // Add proxy information if this was a proxied request
    if (req.targetService) {
      metadata.proxy = {
        targetService: req.targetService,
        success: res.statusCode < 400
      };
    }

    // Determine log level based on status and performance
    let level = 'info';
    if (res.statusCode >= 500) {
      level = 'error';
    } else if (res.statusCode >= 400) {
      level = 'warn';
    } else if (responseTime > this.performanceThresholds.slow) {
      level = 'warn';
    }

    logger.log(level, 'Request completed', metadata);
  }

  // Check for performance issues
  checkPerformance(req, res, responseTime) {
    if (responseTime > this.performanceThresholds.critical) {
      logger.performance('critical_slow_request', responseTime, {
        request: {
          method: req.method,
          path: req.path,
          id: req.headers['x-request-id']
        },
        threshold: this.performanceThresholds.critical
      });
    } else if (responseTime > this.performanceThresholds.slow) {
      logger.performance('slow_request', responseTime, {
        request: {
          method: req.method,
          path: req.path,
          id: req.headers['x-request-id']
        },
        threshold: this.performanceThresholds.slow
      });
    }
  }

  // Get performance category for request
  getPerformanceCategory(responseTime) {
    if (responseTime > this.performanceThresholds.critical) {
      return 'critical';
    } else if (responseTime > this.performanceThresholds.slow) {
      return 'slow';
    } else if (responseTime < 100) {
      return 'fast';
    } else {
      return 'normal';
    }
  }

  // Service health monitoring
  monitorServiceHealth(serviceRegistry) {
    // Listen to service registry events
    serviceRegistry.on('serviceRecovered', ({ serviceName, instance }) => {
      logger.info('Service recovered', {
        service: {
          name: serviceName,
          instanceId: instance.id,
          url: instance.url
        }
      });

      metrics.recordServiceHealth(serviceName, instance.id, true, 0);
      metrics.recordCircuitBreakerState(serviceName, instance.id, 'closed');
    });

    serviceRegistry.on('serviceUnhealthy', ({ serviceName, instance, error }) => {
      logger.warn('Service became unhealthy', {
        service: {
          name: serviceName,
          instanceId: instance.id,
          url: instance.url
        },
        error: {
          message: error.message
        }
      });

      metrics.recordServiceHealth(serviceName, instance.id, false, 0);
    });

    // Periodically update service instance metrics
    const updateServiceMetrics = () => {
      try {
        const allServices = serviceRegistry.getAllServices();
        
        for (const [serviceName, serviceData] of Object.entries(allServices)) {
          metrics.updateServiceInstanceCount(
            serviceName,
            'healthy',
            serviceData.healthyInstances
          );
          
          metrics.updateServiceInstanceCount(
            serviceName,
            'unhealthy',
            serviceData.totalInstances - serviceData.healthyInstances
          );
        }
      } catch (error) {
        logger.error('Failed to update service metrics', {}, error);
      }
    };

    // Update every 30 seconds
    this.serviceMetricsInterval = setInterval(updateServiceMetrics, 30000);
    
    // Initial update
    updateServiceMetrics();
  }

  // Business metrics collection
  recordBusinessMetric(metric, value, tags = {}) {
    logger.businessMetric(metric, value, tags);
    
    // Create or update custom metric
    let customMetric = metrics.getCustomMetric(metric);
    if (!customMetric) {
      customMetric = metrics.createCustomGauge(metric, `Business metric: ${metric}`, Object.keys(tags));
    }
    
    if (customMetric && typeof customMetric.set === 'function') {
      customMetric.set(tags, value);
    }
  }

  // Metrics endpoint middleware
  metricsEndpoint() {
    return async (req, res) => {
      try {
        const metricsData = await metrics.getMetrics();
        res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
        res.end(metricsData);
        
        logger.debug('Metrics endpoint accessed', {
          request: {
            id: req.headers['x-request-id'],
            ip: req.ip
          }
        });
      } catch (error) {
        logger.error('Failed to generate metrics', {
          request: {
            id: req.headers['x-request-id']
          }
        }, error);
        
        res.status(500).json({
          success: false,
          error: {
            code: 'METRICS_ERROR',
            message: 'Failed to generate metrics'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      }
    };
  }

  // Health check for monitoring system
  healthCheck() {
    return (req, res) => {
      const isHealthy = metrics.isHealthy();
      const loggerConfig = logger.getConfig();
      
      const status = {
        monitoring: isHealthy ? 'healthy' : 'unhealthy',
        logger: {
          level: loggerConfig.logLevel,
          uptime: loggerConfig.uptime
        },
        metrics: {
          status: isHealthy ? 'operational' : 'degraded'
        },
        activeRequests: this.requestsInProgress.size,
        thresholds: this.performanceThresholds
      };
      
      res.status(isHealthy ? 200 : 503).json({
        status: isHealthy ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        service: 'gateway-monitoring',
        details: status
      });
      
      logger.debug('Monitoring health check', { healthStatus: status });
    };
  }

  // Generate request ID
  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Get monitoring statistics
  getStats() {
    return {
      activeRequests: this.requestsInProgress.size,
      performanceThresholds: this.performanceThresholds,
      metricsHealthy: metrics.isHealthy(),
      loggerConfig: logger.getConfig()
    };
  }

  // Cleanup method
  cleanup() {
    this.requestsInProgress.clear();
    
    if (this.serviceMetricsInterval) {
      clearInterval(this.serviceMetricsInterval);
      this.serviceMetricsInterval = null;
    }
    
    metrics.cleanup();
    logger.cleanup();
    
    logger.info('Monitoring middleware cleanup completed');
  }
}

module.exports = MonitoringMiddleware;