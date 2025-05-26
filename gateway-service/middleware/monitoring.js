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
      const originalAuth = req.user;
      
      // Monitor auth state changes
      Object.defineProperty(req, 'user', {
        get: () => originalAuth,
        set: (value) => {
          if (value && !originalAuth) {
            // User just authenticated
            logger.authentication('token_validation', req, true, null, {
              userId: value.id,
              email: value.email
            });
            
            metrics.recordAuthRequest('token_validation', true);
          }
          originalAuth = value;
        }
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