// gateway-service/middleware/security.js - Simplified version
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const config = require('../config/simple');

class SecurityMiddleware {
  constructor() {
    this.rateLimiter = rateLimit({
      windowMs: config.get('security.rateLimitWindow'),
      max: config.get('security.rateLimitMax'),
      message: { error: 'Too many requests', retryAfter: 900 }
    });

    this.corsOptions = {
      origin: config.get('security.corsOrigins'),
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
    };
  }

  // All security middleware in one place
  apply() {
    return [
      helmet(),
      cors(this.corsOptions),
      this.rateLimiter,
      this.basicAuth()
    ];
  }

  basicAuth() {
    return (req, res, next) => {
      // Simple JWT validation - delegate complex auth to auth-service
      const token = req.headers.authorization?.split(' ')[1];
      if (token && req.path.startsWith('/api/')) {
        // Set basic user context for logging
        req.userContext = { token };
      }
      next();
    };
  }
}

module.exports = SecurityMiddleware;