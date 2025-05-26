// gateway-service/config/simple.js
class SimpleConfig {
  constructor() {
    this.config = {
      server: {
        port: parseInt(process.env.PORT) || 3000,
        timeout: parseInt(process.env.SERVICE_TIMEOUT) || 30000
      },
      services: {
        auth: process.env.AUTH_SERVICE_URL || 'http://localhost:3001',
        comment: process.env.COMMENT_SERVICE_URL || 'http://localhost:3002',
        industry: process.env.INDUSTRY_SERVICE_URL || 'http://localhost:3003',
        nps: process.env.NPS_SERVICE_URL || 'http://localhost:3004'
      },
      security: {
        jwtSecret: process.env.JWT_SECRET || 'default-dev-secret-change-in-production',
        rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
        rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
        corsOrigins: (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',')
      }
    };
  }

  get(path) {
    return path.split('.').reduce((obj, key) => obj?.[key], this.config);
  }
}

module.exports = new SimpleConfig();