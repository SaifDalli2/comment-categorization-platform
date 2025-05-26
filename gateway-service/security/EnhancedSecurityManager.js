// gateway-service/security/EnhancedSecurityManager.js
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const ApiKeyManager = require('./ApiKeyManager');
const SignatureValidator = require('./SignatureValidator');
const logger = require('../utils/logger');
const configIntegration = require('../utils/configIntegration');

class EnhancedSecurityManager {
  constructor() {
    this.securityConfig = configIntegration.getSecurityConfig();
    this.apiKeyManager = new ApiKeyManager();
    this.signatureValidator = new SignatureValidator();
    
    // Security tracking
    this.securityEvents = new Map();
    this.threatDetection = new Map();
    this.blockedIPs = new Set();
    this.suspiciousPatterns = new Map();
    
    // Rate limiters for different endpoint types
    this.rateLimiters = new Map();
    
    this.initializeRateLimiters();
    this.initializeThreatDetection();
    this.setupSecurityMonitoring();
  }

  initializeRateLimiters() {
    const rateLimitConfig = this.securityConfig.rateLimiting;

    // General API rate limiter
    this.rateLimiters.set('general', rateLimit({
      windowMs: rateLimitConfig.windowMs,
      max: rateLimitConfig.maxRequests,
      message: this.createRateLimitResponse('RATE_LIMIT_EXCEEDED', 'Too many requests'),
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => this.getRateLimitKey(req, 'general'),
      handler: this.handleRateLimit.bind(this, 'general'),
      skip: this.shouldSkipRateLimit.bind(this)
    }));

    // Authentication endpoint rate limiter (stricter)
    this.rateLimiters.set('auth', rateLimit({
      windowMs: rateLimitConfig.authWindowMs,
      max: rateLimitConfig.authMaxRequests,
      message: this.createRateLimitResponse('AUTH_RATE_LIMIT_EXCEEDED', 'Too many authentication attempts'),
      keyGenerator: (req) => this.getRateLimitKey(req, 'auth'),
      handler: this.handleRateLimit.bind(this, 'auth'),
      skipSuccessfulRequests: true
    }));

    // API key based rate limiter
    this.rateLimiters.set('api_key', rateLimit({
      windowMs: 60 * 1000, // 1 minute
      max: (req) => this.getApiKeyRateLimit(req),
      message: this.createRateLimitResponse('API_KEY_RATE_LIMIT_EXCEEDED', 'API key rate limit exceeded'),
      keyGenerator: (req) => this.getApiKeyFromRequest(req),
      handler: this.handleRateLimit.bind(this, 'api_key'),
      skip: (req) => !this.hasApiKey(req)
    }));

    // User-based rate limiter (for authenticated requests)
    this.rateLimiters.set('user', rateLimit({
      windowMs: 60 * 1000, // 1 minute
      max: (req) => this.getUserRateLimit(req),
      message: this.createRateLimitResponse('USER_RATE_LIMIT_EXCEEDED', 'User rate limit exceeded'),
      keyGenerator: (req) => req.userContext?.userId || req.ip,
      handler: this.handleRateLimit.bind(this, 'user'),
      skip: (req) => !req.userContext?.userId
    }));

    // Endpoint-specific rate limiters
    this.setupEndpointRateLimiters();
  }

  setupEndpointRateLimiters() {
    // Comment processing rate limiter
    this.rateLimiters.set('comments', rateLimit({
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 50,
      message: this.createRateLimitResponse('COMMENT_PROCESSING_LIMIT', 'Comment processing rate limit exceeded'),
      keyGenerator: (req) => req.userContext?.userId || req.ip,
      handler: this.handleRateLimit.bind(this, 'comments')
    }));

    // File upload rate limiter
    this.rateLimiters.set('upload', rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 10,
      message: this.createRateLimitResponse('UPLOAD_RATE_LIMIT', 'File upload rate limit exceeded'),
      keyGenerator: (req) => req.userContext?.userId || req.ip,
      handler: this.handleRateLimit.bind(this, 'upload')
    }));

    // Admin endpoint rate limiter
    this.rateLimiters.set('admin', rateLimit({
      windowMs: 5 * 60 * 1000, // 5 minutes
      max: 20,
      message: this.createRateLimitResponse('ADMIN_RATE_LIMIT', 'Admin endpoint rate limit exceeded'),
      keyGenerator: (req) => req.userContext?.userId || req.ip,
      handler: this.handleRateLimit.bind(this, 'admin')
    }));
  }

  initializeThreatDetection() {
    // SQL injection patterns
    this.threatPatterns = {
      sqlInjection: [
        /(\s|^)(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+/gi,
        /'(\s*or\s*|\s*and\s*).+[=<>]/gi,
        /(\s|^)(or|and)\s+\d+\s*[=<>]\s*\d+/gi
      ],
      xss: [
        /<script[^>]*>.*?<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<iframe[^>]*>.*?<\/iframe>/gi
      ],
      pathTraversal: [
        /\.\.[\/\\]/g,
        /[\/\\]\.\.[\/\\]/g,
        /%2e%2e[\/\\]/gi
      ],
      commandInjection: [
        /[;&|`$(){}[\]]/g,
        /(^|\s)(cat|ls|pwd|whoami|id|uname|netstat|ps|kill|rm|mv|cp|chmod|chown)\s/gi
      ],
      lfi: [
        /\/etc\/passwd/gi,
        /\/etc\/shadow/gi,
        /\/proc\/self\/environ/gi,
        /\.\.\/\.\.\/\.\.\//g
      ]
    };

    // Suspicious user agent patterns
    this.suspiciousUserAgents = [
      /sqlmap/gi,
      /nikto/gi,
      /nessus/gi,
      /burp/gi,
      /w3af/gi,
      /acunetix/gi,
      /masscan/gi,
      /nmap/gi
    ];
  }

  setupSecurityMonitoring() {
    // Cleanup security events every 5 minutes
    setInterval(() => {
      this.cleanupSecurityEvents();
      this.analyzeSecurityPatterns();
    }, 5 * 60 * 1000);

    // Update threat intelligence every hour
    setInterval(() => {
      this.updateThreatIntelligence();
    }, 60 * 60 * 1000);
  }

  // Enhanced security headers middleware
  securityHeaders() {
    const helmetConfig = this.securityConfig.helmet;
    
    return helmet({
      contentSecurityPolicy: helmetConfig.contentSecurityPolicy.enabled ? {
        directives: helmetConfig.contentSecurityPolicy.directives,
        reportOnly: process.env.NODE_ENV === 'development'
      } : false,
      hsts: helmetConfig.hsts.enabled ? {
        maxAge: helmetConfig.hsts.maxAge,
        includeSubDomains: helmetConfig.hsts.includeSubDomains,
        preload: true
      } : false,
      noSniff: true,
      frameguard: { action: 'deny' },
      xssFilter: true,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      permittedCrossDomainPolicies: false,
      expectCt: {
        maxAge: 86400,
        enforce: process.env.NODE_ENV === 'production'
      }
    });
  }

  // Enhanced threat detection middleware
  threatDetection() {
    return (req, res, next) => {
      const threats = this.detectThreats(req);
      
      if (threats.length > 0) {
        this.recordSecurityEvent('THREAT_DETECTED', req, { threats });
        
        // Auto-block if critical threat detected
        const criticalThreats = threats.filter(t => t.severity === 'critical');
        if (criticalThreats.length > 0) {
          this.blockIP(req.ip, 'Critical threat detected');
          
          return res.status(403).json({
            success: false,
            error: {
              code: 'SECURITY_THREAT_DETECTED',
              message: 'Request blocked due to security policy violation',
              suggestion: 'Please ensure your request does not contain malicious content'
            },
            metadata: {
              timestamp: new Date().toISOString(),
              requestId: req.headers['x-request-id'],
              service: 'gateway'
            }
          });
        }

        // Log non-critical threats but allow request
        logger.warn('Security threat detected in request', {
          security: {
            threats,
            ip: req.ip,
            path: req.path,
            userAgent: req.get('User-Agent')
          }
        });
      }

      next();
    };
  }

  // Detect threats in request
  detectThreats(req) {
    const threats = [];
    const requestData = this.extractRequestData(req);

    // Check each threat type
    for (const [threatType, patterns] of Object.entries(this.threatPatterns)) {
      for (const pattern of patterns) {
        if (this.checkPattern(requestData, pattern)) {
          threats.push({
            type: threatType,
            severity: this.getThreatSeverity(threatType),
            pattern: pattern.toString(),
            location: this.findPatternLocation(requestData, pattern)
          });
        }
      }
    }

    // Check suspicious user agents
    const userAgent = req.get('User-Agent') || '';
    for (const pattern of this.suspiciousUserAgents) {
      if (pattern.test(userAgent)) {
        threats.push({
          type: 'suspicious_user_agent',
          severity: 'medium',
          pattern: pattern.toString(),
          location: 'user-agent'
        });
      }
    }

    // Check for rapid requests (possible DoS)
    if (this.detectRapidRequests(req.ip)) {
      threats.push({
        type: 'rapid_requests',
        severity: 'high',
        pattern: 'multiple_rapid_requests',
        location: 'request_pattern'
      });
    }

    return threats;
  }

  extractRequestData(req) {
    return {
      url: req.originalUrl || req.url,
      path: req.path,
      query: JSON.stringify(req.query || {}),
      body: JSON.stringify(req.body || {}),
      headers: JSON.stringify(req.headers || {}),
      userAgent: req.get('User-Agent') || ''
    };
  }

  checkPattern(requestData, pattern) {
    return Object.values(requestData).some(data => 
      typeof data === 'string' && pattern.test(data)
    );
  }

  findPatternLocation(requestData, pattern) {
    for (const [location, data] of Object.entries(requestData)) {
      if (typeof data === 'string' && pattern.test(data)) {
        return location;
      }
    }
    return 'unknown';
  }

  getThreatSeverity(threatType) {
    const severityMap = {
      sqlInjection: 'critical',
      xss: 'high',
      pathTraversal: 'high',
      commandInjection: 'critical',
      lfi: 'high',
      suspicious_user_agent: 'medium',
      rapid_requests: 'high'
    };
    
    return severityMap[threatType] || 'medium';
  }

  detectRapidRequests(ip) {
    const now = Date.now();
    const window = 60 * 1000; // 1 minute
    const threshold = 100; // requests per minute
    
    if (!this.threatDetection.has(ip)) {
      this.threatDetection.set(ip, { requests: [], blocked: false });
    }

    const ipData = this.threatDetection.get(ip);
    
    // Clean old requests
    ipData.requests = ipData.requests.filter(time => now - time < window);
    
    // Add current request
    ipData.requests.push(now);
    
    return ipData.requests.length > threshold;
  }

  // Enhanced API key validation middleware
  validateApiKey(options = {}) {
    const { requiredScopes = [], optional = false } = options;

    return async (req, res, next) => {
      const apiKeyHeader = req.headers[process.env.API_KEY_HEADER || 'x-api-key'];
      
      if (!apiKeyHeader) {
        if (optional) {
          return next();
        }
        
        this.recordSecurityEvent('API_KEY_MISSING', req);
        return res.status(401).json({
          success: false,
          error: {
            code: 'API_KEY_REQUIRED',
            message: 'API key is required for this endpoint',
            suggestion: `Include your API key in the ${process.env.API_KEY_HEADER || 'x-api-key'} header`
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      }

      try {
        const validation = await this.apiKeyManager.validateApiKey(apiKeyHeader, req);
        
        if (!validation.valid) {
          this.recordSecurityEvent('API_KEY_VALIDATION_FAILED', req, { reason: validation.reason });
          
          const errorMessages = {
            INVALID_FORMAT: 'API key format is invalid',
            KEY_NOT_FOUND: 'API key not found',
            KEY_DISABLED: 'API key has been disabled',
            KEY_EXPIRED: 'API key has expired',
            KEY_COMPROMISED: 'API key has been compromised',
            IP_NOT_WHITELISTED: 'IP address not authorized for this API key',
            INVALID_SECRET: 'API key is invalid',
            SUSPICIOUS_ACTIVITY: 'API key blocked due to suspicious activity',
            RATE_LIMIT_EXCEEDED: 'API key rate limit exceeded'
          };

          const message = errorMessages[validation.reason] || 'API key validation failed';
          const statusCode = validation.reason === 'RATE_LIMIT_EXCEEDED' ? 429 : 401;

          const response = {
            success: false,
            error: {
              code: 'API_KEY_VALIDATION_FAILED',
              message,
              suggestion: 'Please check your API key and try again'
            },
            metadata: {
              timestamp: new Date().toISOString(),
              requestId: req.headers['x-request-id'],
              service: 'gateway'
            }
          };

          if (validation.retryAfter) {
            res.setHeader('Retry-After', validation.retryAfter);
            response.error.retryAfter = validation.retryAfter;
          }

          return res.status(statusCode).json(response);
        }

        // Check required scopes
        for (const scope of requiredScopes) {
          if (!this.apiKeyManager.hasScope(validation.apiKey, scope)) {
            this.recordSecurityEvent('API_KEY_INSUFFICIENT_SCOPE', req, { 
              requiredScope: scope,
              availableScopes: validation.apiKey.scopes 
            });
            
            return res.status(403).json({
              success: false,
              error: {
                code: 'INSUFFICIENT_API_KEY_SCOPE',
                message: `API key does not have required scope: ${scope}`,
                suggestion: 'Contact support to upgrade your API key permissions'
              },
              metadata: {
                timestamp: new Date().toISOString(),
                requestId: req.headers['x-request-id'],
                service: 'gateway'
              }
            });
          }
        }

        // Attach API key info to request
        req.apiKeyAuth = validation.apiKey;
        req.authType = 'api_key';

        this.recordSecurityEvent('API_KEY_VALIDATED', req, { 
          keyId: validation.apiKey.id,
          scopes: validation.apiKey.scopes 
        });

        next();
      } catch (error) {
        logger.error('API key validation error', { error: error.message }, error);
        
        return res.status(500).json({
          success: false,
          error: {
            code: 'API_KEY_VALIDATION_ERROR',
            message: 'Unable to validate API key',
            suggestion: 'Please try again or contact support'
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

  // Request signature validation middleware
  validateSignature(options = {}) {
    return this.signatureValidator.validateSignature(options);
  }

  // Enhanced rate limiting with multiple strategies
  dynamicRateLimit() {
    return (req, res, next) => {
      // Skip for health checks
      if (req.path === '/health' || req.path.startsWith('/health/')) {
        return next();
      }

      // Check if IP is blocked
      if (this.blockedIPs.has(req.ip)) {
        this.recordSecurityEvent('BLOCKED_IP_ACCESS_ATTEMPT', req);
        return res.status(403).json({
          success: false,
          error: {
            code: 'IP_BLOCKED',
            message: 'Your IP address has been temporarily blocked',
            suggestion: 'Contact support if you believe this is an error'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      }

      // Get appropriate rate limiter
      const rateLimiter = this.getRateLimiter(req);
      
      if (rateLimiter) {
        return rateLimiter(req, res, next);
      }
      
      next();
    };
  }

  getRateLimiter(req) {
    // Admin endpoints
    if (req.path.startsWith('/admin')) {
      return this.rateLimiters.get('admin');
    }

    // Authentication endpoints
    if (req.path.startsWith('/api/auth')) {
      return this.rateLimiters.get('auth');
    }

    // Comment processing endpoints
    if (req.path.startsWith('/api/comments')) {
      return this.rateLimiters.get('comments');
    }

    // Upload endpoints
    if (req.path.includes('/upload')) {
      return this.rateLimiters.get('upload');
    }

    // API key rate limiting
    if (this.hasApiKey(req)) {
      return this.rateLimiters.get('api_key');
    }

    // User rate limiting for authenticated requests
    if (req.userContext?.userId) {
      return this.rateLimiters.get('user');
    }

    // General rate limiting
    return this.rateLimiters.get('general');
  }

  // Helper methods
  getRateLimitKey(req, type) {
    if (type === 'auth') {
      return `${req.ip}:${req.get('User-Agent') || 'unknown'}`;
    }
    
    if (req.userContext?.userId) {
      return `user:${req.userContext.userId}`;
    }
    
    if (this.hasApiKey(req)) {
      return `apikey:${this.getApiKeyFromRequest(req)}`;
    }
    
    return req.ip;
  }

  hasApiKey(req) {
    return !!(req.headers[process.env.API_KEY_HEADER || 'x-api-key']);
  }

  getApiKeyFromRequest(req) {
    const apiKey = req.headers[process.env.API_KEY_HEADER || 'x-api-key'];
    return apiKey ? apiKey.split('.')[0] : null; // Return key ID only
  }

  getApiKeyRateLimit(req) {
    if (req.apiKeyAuth) {
      const tierLimits = {
        development: 1000,
        basic: 100,
        premium: 500,
        enterprise: 2000,
        unlimited: 999999
      };
      return tierLimits[req.apiKeyAuth.rateLimitTier] || 100;
    }
    return 100;
  }

  getUserRateLimit(req) {
    if (req.userContext?.roles?.includes('admin')) {
      return 1000;
    }
    if (req.userContext?.roles?.includes('premium')) {
      return 500;
    }
    return 200;
  }

  shouldSkipRateLimit(req) {
    // Skip for internal health checks
    if (req.get('X-Health-Check') === 'true') {
      return true;
    }
    
    // Skip for super admin users
    if (req.userContext?.roles?.includes('super_admin')) {
      return true;
    }
    
    return false;
  }

  handleRateLimit(type, req, res) {
    this.recordSecurityEvent('RATE_LIMIT_EXCEEDED', req, { type });
    
    logger.warn('Rate limit exceeded', {
      security: {
        type,
        ip: req.ip,
        path: req.path,
        userAgent: req.get('User-Agent'),
        userId: req.userContext?.userId,
        apiKeyId: req.apiKeyAuth?.id
      }
    });

    // Auto-block aggressive IPs
    if (type === 'general') {
      this.recordRapidRequests(req.ip);
    }
  }

  createRateLimitResponse(code, message) {
    return {
      success: false,
      error: {
        code,
        message,
        suggestion: 'Please reduce your request rate and try again later'
      },
      metadata: {
        timestamp: new Date().toISOString(),
        service: 'gateway'
      }
    };
  }

  recordRapidRequests(ip) {
    const now = Date.now();
    const key = `rapid_${ip}`;
    
    if (!this.securityEvents.has(key)) {
      this.securityEvents.set(key, []);
    }
    
    const events = this.securityEvents.get(key);
    events.push(now);
    
    // Auto-block if too many rate limit violations
    if (events.length >= 5) {
      this.blockIP(ip, 'Multiple rate limit violations');
    }
  }

  // IP blocking functionality
  blockIP(ip, reason, duration = 24 * 60 * 60 * 1000) { // 24 hours default
    this.blockedIPs.add(ip);
    
    logger.warn('IP address blocked', {
      security: {
        ip,
        reason,
        duration: duration / 1000 / 60, // minutes
        blockedAt: new Date().toISOString()
      }
    });
    
    // Auto-unblock after duration
    setTimeout(() => {
      this.blockedIPs.delete(ip);
      logger.info('IP address unblocked', {
        security: {
          ip,
          unblockedAt: new Date().toISOString()
        }
      });
    }, duration);

    this.recordSecurityEvent('IP_BLOCKED', null, { ip, reason, duration });
  }

  // Security event recording
  recordSecurityEvent(eventType, req, metadata = {}) {
    const event = {
      type: eventType,
      timestamp: new Date().toISOString(),
      ip: req?.ip,
      path: req?.path,
      method: req?.method,
      userAgent: req?.get('User-Agent'),
      userId: req?.userContext?.userId,
      apiKeyId: req?.apiKeyAuth?.id,
      requestId: req?.headers['x-request-id'],
      metadata
    };

    // Store event
    const eventKey = `${eventType}_${Date.now()}_${Math.random()}`;
    this.securityEvents.set(eventKey, event);

    // Log based on severity
    const criticalEvents = [
      'THREAT_DETECTED',
      'IP_BLOCKED',
      'API_KEY_COMPROMISED',
      'BRUTE_FORCE_DETECTED'
    ];

    const logLevel = criticalEvents.includes(eventType) ? 'error' : 'warn';
    
    logger[logLevel]('Security event recorded', {
      security: event
    });

    // Trigger alerts for critical events
    if (criticalEvents.includes(eventType)) {
      this.triggerSecurityAlert(event);
    }
  }

  triggerSecurityAlert(event) {
    // In production, this would integrate with alerting systems
    logger.error('SECURITY ALERT', {
      alert: {
        type: 'CRITICAL_SECURITY_EVENT',
        event: event.type,
        ip: event.ip,
        timestamp: event.timestamp,
        metadata: event.metadata
      }
    });

    // TODO: Integrate with external alerting (Slack, email, PagerDuty, etc.)
  }

  // Security pattern analysis
  analyzeSecurityPatterns() {
    const now = Date.now();
    const window = 60 * 60 * 1000; // 1 hour
    
    // Analyze recent events
    const recentEvents = Array.from(this.securityEvents.values())
      .filter(event => now - new Date(event.timestamp).getTime() < window);

    // Detect brute force attempts
    this.detectBruteForce(recentEvents);
    
    // Detect distributed attacks
    this.detectDistributedAttacks(recentEvents);
    
    // Detect API key abuse
    this.detectApiKeyAbuse(recentEvents);
  }

  detectBruteForce(events) {
    const authFailures = events.filter(e => 
      e.type === 'API_KEY_VALIDATION_FAILED' || 
      e.type === 'AUTHENTICATION_FAILED'
    );

    // Group by IP
    const failuresByIP = new Map();
    for (const event of authFailures) {
      if (!failuresByIP.has(event.ip)) {
        failuresByIP.set(event.ip, []);
      }
      failuresByIP.get(event.ip).push(event);
    }

    // Check for brute force patterns
    for (const [ip, failures] of failuresByIP.entries()) {
      if (failures.length >= 10) { // 10 failures in 1 hour
        this.blockIP(ip, 'Brute force attack detected');
        this.recordSecurityEvent('BRUTE_FORCE_DETECTED', null, {
          ip,
          failureCount: failures.length,
          timespan: '1hour'
        });
      }
    }
  }

  detectDistributedAttacks(events) {
    const threatEvents = events.filter(e => e.type === 'THREAT_DETECTED');
    const uniqueIPs = new Set(threatEvents.map(e => e.ip));
    
    // If many IPs showing similar threat patterns, it might be a distributed attack
    if (uniqueIPs.size >= 5 && threatEvents.length >= 20) {
      logger.error('Distributed attack detected', {
        security: {
          type: 'DISTRIBUTED_ATTACK',
          uniqueIPs: uniqueIPs.size,
          totalEvents: threatEvents.length,
          timespan: '1hour'
        }
      });

      // Auto-block all involved IPs
      for (const ip of uniqueIPs) {
        this.blockIP(ip, 'Part of distributed attack');
      }
    }
  }

  detectApiKeyAbuse(events) {
    const apiKeyEvents = events.filter(e => e.apiKeyId);
    const eventsByKey = new Map();
    
    for (const event of apiKeyEvents) {
      if (!eventsByKey.has(event.apiKeyId)) {
        eventsByKey.set(event.apiKeyId, []);
      }
      eventsByKey.get(event.apiKeyId).push(event);
    }

    for (const [keyId, keyEvents] of eventsByKey.entries()) {
      const violations = keyEvents.filter(e => 
        e.type === 'RATE_LIMIT_EXCEEDED' || 
        e.type === 'THREAT_DETECTED'
      );

      if (violations.length >= 5) {
        this.apiKeyManager.revokeApiKey(keyId, 'Suspicious activity detected');
        this.recordSecurityEvent('API_KEY_ABUSE_DETECTED', null, {
          keyId,
          violationCount: violations.length
        });
      }
    }
  }

  // Update threat intelligence
  updateThreatIntelligence() {
    // In production, this would fetch from threat intelligence feeds
    logger.debug('Updating threat intelligence data');
    
    // Update suspicious IP lists, known attack patterns, etc.
    // This is where you'd integrate with services like:
    // - VirusTotal
    // - AbuseIPDB
    // - MISP
    // - Commercial threat feeds
  }

  // Cleanup old security events
  cleanupSecurityEvents() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    let cleaned = 0;
    
    for (const [key, event] of this.securityEvents.entries()) {
      const eventTime = new Date(event.timestamp).getTime();
      if (now - eventTime > maxAge) {
        this.securityEvents.delete(key);
        cleaned++;
      }
    }
    
    // Cleanup threat detection data
    for (const [ip, data] of this.threatDetection.entries()) {
      if (data.requests.length === 0) {
        this.threatDetection.delete(ip);
      }
    }

    if (cleaned > 0) {
      logger.debug('Security events cleanup completed', {
        security: {
          eventsRemoved: cleaned,
          remainingEvents: this.securityEvents.size
        }
      });
    }
  }

  // Configuration update handler
  updateConfiguration(newConfig) {
    this.securityConfig = newConfig;
    
    // Reinitialize rate limiters with new config
    this.rateLimiters.clear();
    this.initializeRateLimiters();
    
    logger.info('Security configuration updated', {
      security: {
        rateLimiting: newConfig.rateLimiting,
        cors: newConfig.cors,
        helmet: newConfig.helmet
      }
    });
  }

  // Get comprehensive security statistics
  getSecurityStats() {
    const now = Date.now();
    const lastHour = now - (60 * 60 * 1000);
    const lastDay = now - (24 * 60 * 60 * 1000);

    const recentEvents = Array.from(this.securityEvents.values())
      .filter(event => new Date(event.timestamp).getTime() > lastDay);

    const hourlyEvents = recentEvents.filter(event => 
      new Date(event.timestamp).getTime() > lastHour
    );

    const eventsByType = new Map();
    for (const event of recentEvents) {
      eventsByType.set(event.type, (eventsByType.get(event.type) || 0) + 1);
    }

    return {
      blockedIPs: this.blockedIPs.size,
      securityEvents: {
        total: this.securityEvents.size,
        lastHour: hourlyEvents.length,
        lastDay: recentEvents.length,
        byType: Object.fromEntries(eventsByType)
      },
      threatDetection: {
        monitoredIPs: this.threatDetection.size,
        suspiciousPatterns: this.suspiciousPatterns.size
      },
      rateLimiters: {
        active: this.rateLimiters.size,
        types: Array.from(this.rateLimiters.keys())
      },
      apiKeys: this.apiKeyManager.getSecurityStats(),
      signatures: this.signatureValidator.getSignatureStats()
    };
  }

  // Get recent security events
  getRecentSecurityEvents(limit = 100, eventType = null) {
    const events = Array.from(this.securityEvents.values())
      .filter(event => !eventType || event.type === eventType)
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);

    return events.map(event => ({
      ...event,
      // Remove sensitive information
      metadata: event.metadata ? { ...event.metadata } : {}
    }));
  }

  // Security health check
  getSecurityHealth() {
    const stats = this.getSecurityStats();
    
    const issues = [];
    
    // Check for high number of blocked IPs
    if (stats.blockedIPs > 100) {
      issues.push('High number of blocked IPs detected');
    }
    
    // Check for recent security events
    if (stats.securityEvents.lastHour > 50) {
      issues.push('High number of security events in the last hour');
    }
    
    // Check API key health
    if (stats.apiKeys.compromisedKeys > 0) {
      issues.push('Compromised API keys detected');
    }

    return {
      status: issues.length === 0 ? 'healthy' : 'degraded',
      issues,
      stats,
      timestamp: new Date().toISOString()
    };
  }

  // Get API key manager instance
  getApiKeyManager() {
    return this.apiKeyManager;
  }

  // Get signature validator instance
  getSignatureValidator() {
    return this.signatureValidator;
  }

  // Cleanup method
  cleanup() {
    this.securityEvents.clear();
    this.threatDetection.clear();
    this.blockedIPs.clear();
    this.suspiciousPatterns.clear();
    this.rateLimiters.clear();
    
    this.apiKeyManager.cleanup();
    this.signatureValidator.cleanup();
    
    logger.info('Enhanced security manager cleaned up');
  }
}

module.exports = EnhancedSecurityManager;