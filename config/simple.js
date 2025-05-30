// gateway-service/config/simple.js - FIXED VERSION
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const config = {
  port: parseInt(process.env.PORT) || 3000,
  
  services: {
    // FIXED: Corrected comment service URL typo
    auth: process.env.AUTH_SERVICE_URL || 'https://auth-service-voice-0add8d339257.herokuapp.com',
    comment: process.env.COMMENT_SERVICE_URL || 'https://comment-serivce-1d430c50b7ad.herokuapp.com', // Fixed typo
    industry: process.env.INDUSTRY_SERVICE_URL || 'https://industry-service-voice-f7d40a18c50e.herokuapp.com',
    // REMOVED: NPS service until it's deployed
    // nps: process.env.NPS_SERVICE_URL || 'https://your-nps-service.herokuapp.com'
  },
  
  security: {
    // IMPORTANT: This must match ALL services exactly
    jwtSecret: process.env.JWT_SECRET,
    corsOrigins: process.env.ALLOWED_ORIGINS ? 
      process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : 
      [
        'https://gateway-service-b25f91548194.herokuapp.com',
        'https://your-frontend-app.netlify.app',
        'https://your-frontend-app.vercel.app',
        ...(process.env.NODE_ENV === 'development' ? ['http://localhost:3000', 'http://localhost:5173'] : [])
      ]
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

// Log configuration for debugging (without secrets)
console.log('Gateway Configuration:');
console.log(`- Port: ${config.port}`);
console.log(`- Environment: ${process.env.NODE_ENV || 'development'}`);
console.log(`- Services: ${Object.keys(config.services).join(', ')}`);
console.log(`- CORS Origins: ${config.security.corsOrigins.length} configured`);

module.exports = config;