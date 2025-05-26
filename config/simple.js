// gateway-service/config/simple.js
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const config = {
  port: parseInt(process.env.PORT) || 3000,
  
  services: {
    auth: process.env.AUTH_SERVICE_URL || 'http://localhost:3001',
    comment: process.env.COMMENT_SERVICE_URL || 'http://localhost:3002',
    industry: process.env.INDUSTRY_SERVICE_URL || 'http://localhost:3003',
    nps: process.env.NPS_SERVICE_URL || 'http://localhost:3004'
  },
  
  security: {
    jwtSecret: process.env.JWT_SECRET,
    corsOrigins: process.env.ALLOWED_ORIGINS ? 
      process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : 
      ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:5173']
  },
  
  monitoring: {
    logLevel: process.env.LOG_LEVEL || 'info',
    healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000
  }
};

// Validation
const requiredEnvVars = ['JWT_SECRET'];
const missing = requiredEnvVars.filter(varName => !process.env[varName]);

if (missing.length > 0) {
  console.error(`Missing required environment variables: ${missing.join(', ')}`);
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  } else {
    console.warn('Using default values for development');
    if (!config.security.jwtSecret) {
      config.security.jwtSecret = 'dev-secret-change-in-production-32-chars-min';
    }
  }
}

// Validate JWT secret length
if (config.security.jwtSecret && config.security.jwtSecret.length < 32) {
  console.error('JWT_SECRET must be at least 32 characters long');
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
}

module.exports = config;