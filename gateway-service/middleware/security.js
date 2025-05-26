// gateway-service/middleware/security.js
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');

class SecurityManager {
  constructor() {
    this.rateLimiters = new Map();
    this.authenticatedUsers = new Map();
    this.blockedIPs = new Set();
    
    // Initialize security configurations
    this.initializeRateLimiters();
  }

  initializeRateLimiters() {
    // General API rate limiter
    this.rateLimiters.set('general', rateLimit({
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
      message: {
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 1000)
      },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        console.warn(`🚨 Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
        res.status(429).json({
          error: 'Too Many Requests',
          message: 'Rate limit exceeded. Please try again later.',
          retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 1000),
          timestamp: new Date().toISOString()
        });
      }
    }));

    // Authentication endpoint rate limiter (stricter)
    this.rateLimiters.set('auth', rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 10, // Limit auth attempts
      message: {
        error: 'Too many authentication attempts',
        message: 'Please wait before trying to authenticate again.',
        retryAfter: 900
      },
      skipSuccessfulRequests: true,
      handler: (req, res) => {
        console.warn(`🚨 Auth rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
          error: 'Too Many Authentication Attempts',
          message: 'Please wait before trying to authenticate again.',
          retryAfter: 900,
          timestamp: new Date().toISOString()
        });
      }
    }));

    // Comment processing rate limiter (more lenient for legitimate use)
    this.rateLimiters.set('comments', rateLimit({
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 50, // 50 processing requests per hour
      message: {
        error: 'Comment processing rate limit exceeded',
        message: 'You have exceeded the hourly limit for comment processing.',
        retryAfter: 3600
      },
      handler: (req, res) => {
        console.warn(`🚨 Comment processing rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
          error: 'Processing Rate Limit Exceeded',
          message: 'You have exceeded the hourly limit for comment processing.',
          retryAfter: 3600,
          timestamp: new Date().toISOString()
        });
      }
    }));

    // Admin endpoints rate limiter (very strict)
    this.rateLimiters.set('admin', rateLimit({
      windowMs: 5 * 60 * 1000, // 5 minutes
      max: 5, // Only 5 admin requests per 5 minutes
      message: {
        error: 'Admin rate limit exceeded',
        message: 'Admin endpoints are heavily rate limited.',
        retryAfter: 300
      }
    }));
  }

  // Get appropriate rate limiter for a route
  getRateLimiter(path) {
    if (path.startsWith('/api/auth')) {
      return this.rateLimiters.get('auth');
    }
    if (path.startsWith('/api/categorize') || path.startsWith('/api/comments')) {
      return this.rateLimiters.get('comments');
    }
    if (path.startsWith('/admin')) {
      return this.rateLimiters.get('admin');
    }
    return this.rateLimiters.get('general');
  }

  // Dynamic rate limiting middleware
  dynamicRateLimit() {
    return (req, res, next) => {
      // Skip rate limiting for health checks
      if (req.path === '/health' || req.path === '/health/services') {
        return next();
      }

      // Check if IP is blocked
      if (this.blockedIPs.has(req.ip)) {
        return res.status(403).json({
          error: 'IP Blocked',
          message: 'Your IP address has been temporarily blocked.',
          timestamp: new Date().toISOString()
        });
      }

      // Get appropriate rate limiter
      const rateLimiter = this.getRateLimiter(req.path);
      
      if (rateLimiter) {
        return rateLimiter(req, res, next);
      }
      
      next();
    };
  }

  // Security headers middleware
  securityHeaders() {
    return helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
        },
      },
      crossOriginEmbedderPolicy: false, // Allow embedding for dashboard
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    });
  }

  // JWT authentication middleware
  authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        error: 'Access Token Required',
        message: 'Please provide a valid authentication token.',
        timestamp: new Date().toISOString()
      });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      
      // Track authenticated user
      this.authenticatedUsers.set(decoded.userId, {
        lastSeen: new Date(),
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      next();
    } catch (error) {
      console.warn(`🚨 Invalid token from IP: ${req.ip}`);
      return res.status(403).json({
        error: 'Invalid Token',
        message: 'The provided authentication token is invalid or expired.',
        timestamp: new Date().toISOString()
      });
    }
  }

  // Optional authentication middleware
  optionalAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        
        // Track authenticated user
        this.authenticatedUsers.set(decoded.userId, {
          lastSeen: new Date(),
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
      } catch (error) {
        // Token is invalid, but we don't fail the request
        console.warn(`⚠️ Invalid optional token from IP: ${req.ip}`);
      }
    }
    
    next();
  }

  // API key validation middleware
  validateApiKey(req, res, next) {
    const apiKey = req.headers[process.env.API_KEY_HEADER || 'x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({
        error: 'API Key Required',
        message: 'Please provide a valid API key in the request headers.',
        timestamp: new Date().toISOString()
      });
    }

    // Validate API key format (basic validation)
    if (apiKey.length < 10 || !apiKey.startsWith('sk-')) {
      return res.status(401).json({
        error: 'Invalid API Key Format',
        message: 'The provided API key format is invalid.',
        timestamp: new Date().toISOString()
      });
    }

    // Store API key for service forwarding
    req.apiKey = apiKey;
    next();
  }

  // Request sanitization middleware
  sanitizeRequest() {
    return (req, res, next) => {
      // Basic input sanitization
      if (req.body) {
        // Remove potentially dangerous properties
        delete req.body.__proto__;
        delete req.body.constructor;
        delete req.body.prototype;
        
        // Sanitize string inputs
        this.sanitizeObject(req.body);
      }
      
      if (req.query) {
        this.sanitizeObject(req.query);
      }
      
      next();
    };
  }

  sanitizeObject(obj) {
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        // Basic XSS prevention
        obj[key] = obj[key]
          .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
          .replace(/javascript:/gi, '')
          .replace(/on\w+=/gi, '');
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        this.sanitizeObject(obj[key]);
      }
    }
  }

  // IP blocking functionality
  blockIP(ip, duration = 24 * 60 * 60 * 1000) { // 24 hours default
    this.blockedIPs.add(ip);
    console.warn(`🚫 IP ${ip} has been blocked`);
    
    // Auto-unblock after duration
    setTimeout(() => {
      this.blockedIPs.delete(ip);
      console.log(`✅ IP ${ip} has been unblocked`);
    }, duration);
  }

  // Suspicious activity detection
  detectSuspiciousActivity() {
    return (req, res, next) => {
      const suspiciousPatterns = [
        /\.\.\//g, // Path traversal
        /<script/gi, // XSS attempts
        /union.*select/gi, // SQL injection
        /exec\(/gi, // Code injection
        /eval\(/gi, // Code injection
      ];

      const requestString = JSON.stringify({
        url: req.url,
        body: req.body,
        query: req.query,
        headers: req.headers
      });

      for (const pattern of suspiciousPatterns) {
        if (pattern.test(requestString)) {
          console.error(`🚨 Suspicious activity detected from IP: ${req.ip}`);
          console.error(`Pattern: ${pattern}, Request: ${req.method} ${req.url}`);
          
          // Auto-block suspicious IPs
          this.blockIP(req.ip, 60 * 60 * 1000); // 1 hour block
          
          return res.status(403).json({
            error: 'Suspicious Activity Detected',
            message: 'Your request has been blocked due to suspicious patterns.',
            timestamp: new Date().toISOString()
          });
        }
      }
      
      next();
    };
  }

  // Get security statistics
  getSecurityStats() {
    return {
      blockedIPs: Array.from(this.blockedIPs),
      authenticatedUsers: this.authenticatedUsers.size,
      rateLimiters: Array.from(this.rateLimiters.keys()),
      timestamp: new Date().toISOString()
    };
  }

  // Cleanup expired data
  cleanup() {
    const now = new Date();
    const expireTime = 24 * 60 * 60 * 1000; // 24 hours

    // Clean up old authenticated user data
    for (const [userId, userData] of this.authenticatedUsers.entries()) {
      if (now - userData.lastSeen > expireTime) {
        this.authenticatedUsers.delete(userId);
      }
    }
  }
}

module.exports = SecurityManager;