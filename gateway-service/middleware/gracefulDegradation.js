// gateway-service/middleware/gracefulDegradation.js
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

class GracefulDegradationManager {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.fallbackTimeoutMs = options.fallbackTimeoutMs || 5000;
    this.maxRetries = options.maxRetries || 2;
    this.degradationStrategies = new Map();
    this.serviceHealth = new Map();
    this.failureThresholds = {
      errorRate: 0.5, // 50% error rate
      responseTime: 10000, // 10 seconds
      consecutiveFailures: 5
    };
    
    this.setupDefaultStrategies();
    this.initializeMetrics();
  }

  initializeMetrics() {
    this.degradationCounter = metrics.createCustomCounter(
      'degradation_events_total',
      'Total degradation events',
      ['service_name', 'strategy', 'reason']
    );

    this.fallbackCounter = metrics.createCustomCounter(
      'fallback_responses_total',
      'Total fallback responses served',
      ['service_name', 'fallback_type']
    );
  }

  setupDefaultStrategies() {
    // Authentication service degradation
    this.addDegradationStrategy('auth', {
      '/api/auth/verify': {
        strategy: 'cache_fallback',
        fallback: this.cachedTokenValidation,
        timeout: 3000,
        essential: true
      },
      '/api/auth/login': {
        strategy: 'queue_request',
        fallback: this.queueAuthRequest,
        timeout: 10000,
        essential: true
      }
    });

    // Comment service degradation
    this.addDegradationStrategy('comment', {
      '/api/comments/categorize': {
        strategy: 'partial_processing',
        fallback: this.partialCommentProcessing,
        timeout: 30000,
        essential: false
      },
      '/api/comments/job/*/status': {
        strategy: 'cached_status',
        fallback: this.cachedJobStatus,
        timeout: 2000,
        essential: false
      }
    });

    // Industry service degradation
    this.addDegradationStrategy('industry', {
      '/api/industries': {
        strategy: 'static_fallback',
        fallback: this.staticIndustryList,
        timeout: 2000,
        essential: false
      },
      '/api/industries/*/categories': {
        strategy: 'static_fallback',
        fallback: this.staticCategoryList,
        timeout: 2000,
        essential: false
      }
    });

    // NPS service degradation
    this.addDegradationStrategy('nps', {
      '/api/nps/dashboard/*': {
        strategy: 'cached_dashboard',
        fallback: this.cachedNPSDashboard,
        timeout: 5000,
        essential: false
      },
      '/api/nps/upload': {
        strategy: 'queue_request',
        fallback: this.queueNPSUpload,
        timeout: 15000,
        essential: false
      }
    });
  }

  addDegradationStrategy(serviceName, strategies) {
    this.degradationStrategies.set(serviceName, strategies);
  }

  // Main degradation middleware
  middleware() {
    return async (req, res, next) => {
      if (!this.enabled) {
        return next();
      }

      const serviceName = this.extractServiceName(req.path);
      const strategy = this.getDegradationStrategy(serviceName, req.path);
      
      if (!strategy) {
        return next();
      }

      // Check if service is healthy
      const isHealthy = this.isServiceHealthy(serviceName);
      
      if (isHealthy) {
        // Wrap the request with degradation fallback
        return this.wrapWithFallback(req, res, next, serviceName, strategy);
      }

      // Service is unhealthy, apply degradation immediately
      return this.applyDegradation(req, res, serviceName, strategy);
    };
  }

  wrapWithFallback(req, res, next, serviceName, strategy) {
    const originalSend = res.send;
    const originalJson = res.json;
    const originalEnd = res.end;
    let responseHandled = false;

    // Set timeout for the request
    const timeoutId = setTimeout(() => {
      if (!responseHandled) {
        responseHandled = true;
        this.recordServiceFailure(serviceName, 'timeout');
        this.applyDegradation(req, res, serviceName, strategy);
      }
    }, strategy.timeout);

    // Override response methods to detect completion
    const wrapResponse = (originalMethod) => {
      return function(...args) {
        if (!responseHandled) {
          responseHandled = true;
          clearTimeout(timeoutId);
          
          // Check if response indicates failure
          if (res.statusCode >= 500) {
            this.recordServiceFailure(serviceName, 'server_error');
          } else {
            this.recordServiceSuccess(serviceName);
          }
        }
        return originalMethod.apply(this, args);
      };
    };

    res.send = wrapResponse(originalSend);
    res.json = wrapResponse(originalJson);
    res.end = wrapResponse(originalEnd);

    // Handle errors
    const errorHandler = (error) => {
      if (!responseHandled) {
        responseHandled = true;
        clearTimeout(timeoutId);
        this.recordServiceFailure(serviceName, 'request_error');
        this.applyDegradation(req, res, serviceName, strategy);
      }
    };

    req.on('error', errorHandler);
    res.on('error', errorHandler);

    next();
  }

  async applyDegradation(req, res, serviceName, strategy) {
    logger.warn('Applying graceful degradation', {
      degradation: {
        serviceName,
        path: req.path,
        strategy: strategy.strategy,
        essential: strategy.essential
      }
    });

    this.degradationCounter.inc({
      service_name: serviceName,
      strategy: strategy.strategy,
      reason: 'service_degraded'
    });

    try {
      const fallbackResponse = await strategy.fallback.call(this, req, res, serviceName);
      
      if (fallbackResponse) {
        this.fallbackCounter.inc({
          service_name: serviceName,
          fallback_type: strategy.strategy
        });

        // Add degradation headers
        res.setHeader('X-Degraded-Service', serviceName);
        res.setHeader('X-Fallback-Strategy', strategy.strategy);
        res.setHeader('X-Service-Essential', strategy.essential.toString());

        if (typeof fallbackResponse === 'object') {
          res.json(fallbackResponse);
        } else {
          res.send(fallbackResponse);
        }
      } else {
        throw new Error('Fallback strategy returned no response');
      }

    } catch (error) {
      logger.error('Degradation fallback failed', {
        degradation: {
          serviceName,
          strategy: strategy.strategy,
          error: error.message
        }
      }, error);

      if (strategy.essential) {
        res.status(503).json({
          success: false,
          error: {
            code: 'ESSENTIAL_SERVICE_UNAVAILABLE',
            message: `Essential service ${serviceName} is temporarily unavailable`,
            suggestion: 'Please try again in a few moments'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway',
            degradedService: serviceName
          }
        });
      } else {
        res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_DEGRADED',
            message: `Service ${serviceName} is experiencing issues`,
            suggestion: 'Some features may be limited. Please try again later.'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway',
            degradedService: serviceName
          }
        });
      }
    }
  }

  // Fallback strategies implementation
  async cachedTokenValidation(req, res, serviceName) {
    // Try to validate token from cache or local JWT verification
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      throw new Error('No token provided');
    }

    try {
      const jwt = require('jsonwebtoken');
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      return {
        success: true,
        data: {
          valid: true,
          user: {
            id: decoded.userId,
            email: decoded.email,
            roles: decoded.roles || ['user']
          }
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'],
          service: 'gateway',
          fallback: 'cached_validation'
        }
      };
    } catch (error) {
      throw new Error('Token validation failed in fallback mode');
    }
  }

  async queueAuthRequest(req, res, serviceName) {
    // Queue authentication request for later processing
    const queueId = `auth_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // In a real implementation, this would use a proper queue system
    logger.info('Authentication request queued', {
      queue: {
        id: queueId,
        path: req.path,
        body: req.body
      }
    });

    return {
      success: true,
      data: {
        queueId,
        status: 'queued',
        message: 'Your authentication request has been queued and will be processed shortly',
        estimatedWaitTime: 30000 // 30 seconds
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'],
        service: 'gateway',
        fallback: 'queued_request'
      }
    };
  }

  async partialCommentProcessing(req, res, serviceName) {
    // Provide partial comment processing with basic categorization
    const comments = req.body.comments || [];
    
    const basicCategories = [
      'General Feedback',
      'Technical Issues',
      'Service Quality',
      'Feature Request',
      'Complaint'
    ];

    const processedComments = comments.map((comment, index) => ({
      id: index + 1,
      comment,
      category: basicCategories[Math.floor(Math.random() * basicCategories.length)],
      sentiment: Math.random() * 2 - 1, // Random sentiment between -1 and 1
      confidence: 0.3, // Low confidence for fallback processing
      processingMethod: 'fallback_basic'
    }));

    return {
      success: true,
      data: {
        jobId: `fallback_${Date.now()}`,
        status: 'completed',
        results: {
          categorizedComments: processedComments,
          processingMetadata: {
            totalComments: comments.length,
            processedComments: processedComments.length,
            failedComments: 0,
            elapsedTimeMs: 100,
            processingMethod: 'fallback_basic'
          }
        },
        warning: 'Processed using fallback method with reduced accuracy'
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'],
        service: 'gateway',
        fallback: 'partial_processing'
      }
    };
  }

  async cachedJobStatus(req, res, serviceName) {
    const jobId = req.params.jobId || req.path.split('/').pop();
    
    return {
      success: true,
      data: {
        jobId,
        status: 'unknown',
        progress: 0,
        message: 'Job status unavailable - service is degraded',
        lastUpdate: new Date().toISOString()
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'],
        service: 'gateway',
        fallback: 'cached_status'
      }
    };
  }

  async staticIndustryList(req, res, serviceName) {
    const staticIndustries = [
      'SaaS/Technology',
      'E-commerce/Retail',
      'Healthcare',
      'Financial Services',
      'Hospitality',
      'Manufacturing',
      'Education'
    ];

    return {
      success: true,
      data: {
        industries: staticIndustries
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'],
        service: 'gateway',
        fallback: 'static_list'
      }
    };
  }

  async staticCategoryList(req, res, serviceName) {
    const industry = req.params.industry || 'default';
    const staticCategories = {
      'SaaS/Technology': [
        'Technical Issues: Bug Reports',
        'Technical Issues: Feature Requests',
        'Customer Success: Support Quality',
        'Product Feedback: UI/UX'
      ],
      'default': [
        'General Feedback',
        'Service Quality',
        'Product Issues',
        'Feature Requests'
      ]
    };

    return {
      success: true,
      data: {
        categories: staticCategories[industry] || staticCategories.default
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'],
        service: 'gateway',
        fallback: 'static_categories'
      }
    };
  }

  async cachedNPSDashboard(req, res, serviceName) {
    const userId = req.params.userId || 'unknown';
    
    return {
      success: true,
      data: {
        npsScore: null,
        totalResponses: 0,
        promoters: { count: 0, percentage: 0 },
        passives: { count: 0, percentage: 0 },
        detractors: { count: 0, percentage: 0 },
        message: 'Dashboard data unavailable - using cached fallback'
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'],
        service: 'gateway',
        fallback: 'cached_dashboard'
      }
    };
  }

  async queueNPSUpload(req, res, serviceName) {
    const uploadId = `nps_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    return {
      success: true,
      data: {
        uploadId,
        status: 'queued',
        message: 'NPS data upload queued for processing when service recovers'
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'],
        service: 'gateway',
        fallback: 'queued_upload'
      }
    };
  }

  // Helper methods
  extractServiceName(path) {
    const pathParts = path.split('/');
    if (pathParts.length >= 3 && pathParts[1] === 'api') {
      const serviceMap = {
        'auth': 'auth',
        'comments': 'comment',
        'industries': 'industry',
        'nps': 'nps'
      };
      return serviceMap[pathParts[2]] || null;
    }
    return null;
  }

  getDegradationStrategy(serviceName, path) {
    if (!serviceName || !this.degradationStrategies.has(serviceName)) {
      return null;
    }

    const strategies = this.degradationStrategies.get(serviceName);
    
    // Direct path match
    if (strategies[path]) {
      return strategies[path];
    }

    // Pattern matching
    for (const [pattern, strategy] of Object.entries(strategies)) {
      if (this.matchesPattern(path, pattern)) {
        return strategy;
      }
    }

    return null;
  }

  matchesPattern(path, pattern) {
    const regexPattern = pattern
      .replace(/\*/g, '[^/]+')
      .replace(/\//g, '\\/');
    
    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(path);
  }

  isServiceHealthy(serviceName) {
    const health = this.serviceHealth.get(serviceName);
    if (!health) return true; // Assume healthy if no data

    const now = Date.now();
    const recentFailures = health.failures.filter(f => now - f < 300000); // 5 minutes
    
    return recentFailures.length < this.failureThresholds.consecutiveFailures;
  }

  recordServiceFailure(serviceName, reason) {
    if (!this.serviceHealth.has(serviceName)) {
      this.serviceHealth.set(serviceName, {
        failures: [],
        successes: [],
        lastFailure: null,
        lastSuccess: null
      });
    }

    const health = this.serviceHealth.get(serviceName);
    const now = Date.now();
    
    health.failures.push(now);
    health.lastFailure = now;
    
    // Keep only recent failures (last hour)
    health.failures = health.failures.filter(f => now - f < 3600000);
    
    logger.warn('Service failure recorded', {
      degradation: {
        serviceName,
        reason,
        recentFailures: health.failures.length
      }
    });
  }

  recordServiceSuccess(serviceName) {
    if (!this.serviceHealth.has(serviceName)) {
      this.serviceHealth.set(serviceName, {
        failures: [],
        successes: [],
        lastFailure: null,
        lastSuccess: null
      });
    }

    const health = this.serviceHealth.get(serviceName);
    const now = Date.now();
    
    health.successes.push(now);
    health.lastSuccess = now;
    
    // Keep only recent successes (last hour)
    health.successes = health.successes.filter(s => now - s < 3600000);
  }

  // Get degradation statistics
  getStats() {
    const serviceStats = {};
    
    for (const [serviceName, health] of this.serviceHealth.entries()) {
      const now = Date.now();
      const recentFailures = health.failures.filter(f => now - f < 300000); // 5 minutes
      const recentSuccesses = health.successes.filter(s => now - s < 300000);
      const total = recentFailures.length + recentSuccesses.length;
      
      serviceStats[serviceName] = {
        healthy: this.isServiceHealthy(serviceName),
        recentFailures: recentFailures.length,
        recentSuccesses: recentSuccesses.length,
        errorRate: total > 0 ? recentFailures.length / total : 0,
        lastFailure: health.lastFailure ? new Date(health.lastFailure).toISOString() : null,
        lastSuccess: health.lastSuccess ? new Date(health.lastSuccess).toISOString() : null
      };
    }

    return {
      enabled: this.enabled,
      failureThresholds: this.failureThresholds,
      registeredStrategies: this.degradationStrategies.size,
      services: serviceStats
    };
  }

  // Express routes for degradation management
  getDegradationRoutes() {
    const router = require('express').Router();

    router.get('/stats', (req, res) => {
      const stats = this.getStats();
      res.json({
        success: true,
        data: stats,
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'],
          service: 'gateway'
        }
      });
    });

    return router;
  }
}

module.exports = GracefulDegradationManager;