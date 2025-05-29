// gateway-service/config/enhanced.js - Enhanced configuration with sync settings
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const config = {
  port: parseInt(process.env.PORT) || 3000,
  environment: process.env.NODE_ENV || 'development',
  
  services: {
    auth: process.env.AUTH_SERVICE_URL || 'https://auth-service-voice-0add8d339257.herokuapp.com',
    comment: process.env.COMMENT_SERVICE_URL || 'https://your-comment-service.herokuapp.com',
    industry: process.env.INDUSTRY_SERVICE_URL || 'https://your-industry-service.herokuapp.com',
    nps: process.env.NPS_SERVICE_URL || 'https://your-nps-service.herokuapp.com'
  },
  
  security: {
    jwtSecret: process.env.JWT_SECRET,
    corsOrigins: process.env.ALLOWED_ORIGINS ? 
      process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : 
      [
        'https://gateway-service-b25f91548194.herokuapp.com',
        'https://auth-service-voice-0add8d339257.herokuapp.com',
        'https://your-frontend-app.netlify.app',
        'https://your-frontend-app.vercel.app',
        ...(process.env.NODE_ENV === 'development' ? [
          'http://localhost:3000', 
          'http://localhost:3001',
          'http://localhost:5173',
          'http://localhost:8080'
        ] : [])
      ],
    // Rate limiting configuration
    rateLimits: {
      global: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100 // requests per window
      },
      auth: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 20 // auth requests per window
      },
      comments: {
        windowMs: 60 * 60 * 1000, // 1 hour
        max: 10 // comment jobs per hour per user
      },
      nps: {
        windowMs: 60 * 60 * 1000, // 1 hour
        max: 20 // NPS requests per hour per user
      },
      industries: {
        windowMs: 60 * 1000, // 1 minute
        max: 30 // industry requests per minute
      }
    }
  },
  
  monitoring: {
    logLevel: process.env.LOG_LEVEL || 'info',
    healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000,
    syncCheckInterval: parseInt(process.env.SYNC_CHECK_INTERVAL) || 5 * 60 * 1000, // 5 minutes
    enableMetrics: process.env.ENABLE_METRICS !== 'false',
    enableTracing: process.env.ENABLE_TRACING !== 'false'
  },
  
  // Shared Knowledge Synchronization Configuration
  sync: {
    enabled: process.env.SYNC_ENABLED !== 'false',
    expectedVersion: process.env.SHARED_KNOWLEDGE_VERSION || '1.0.0',
    checkInterval: parseInt(process.env.SYNC_CHECK_INTERVAL) || 5 * 60 * 1000, // 5 minutes
    warningThreshold: parseInt(process.env.SYNC_WARNING_THRESHOLD) || 30 * 60 * 1000, // 30 minutes
    criticalThreshold: parseInt(process.env.SYNC_CRITICAL_THRESHOLD) || 60 * 60 * 1000, // 1 hour
    autoUpdate: process.env.SYNC_AUTO_UPDATE === 'true', // Disabled by default for safety
    notificationEndpoint: process.env.SYNC_NOTIFICATION_ENDPOINT || null
  },
  
  // Orchestration Configuration
  orchestration: {
    enabled: process.env.ORCHESTRATION_ENABLED !== 'false',
    timeout: parseInt(process.env.ORCHESTRATION_TIMEOUT) || 10000, // 10 seconds
    retryAttempts: parseInt(process.env.ORCHESTRATION_RETRY_ATTEMPTS) || 3,
    retryDelay: parseInt(process.env.ORCHESTRATION_RETRY_DELAY) || 1000, // 1 second
    cacheEnabled: process.env.ORCHESTRATION_CACHE_ENABLED !== 'false',
    cacheExpiry: parseInt(process.env.ORCHESTRATION_CACHE_EXPIRY) || 5 * 60 * 1000, // 5 minutes
    cacheTtl: {
      user: parseInt(process.env.CACHE_TTL_USER) || 10 * 60 * 1000, // 10 minutes
      dashboard: parseInt(process.env.CACHE_TTL_DASHBOARD) || 2 * 60 * 1000, // 2 minutes
      industries: parseInt(process.env.CACHE_TTL_INDUSTRIES) || 15 * 60 * 1000, // 15 minutes
      jobs: parseInt(process.env.CACHE_TTL_JOBS) || 2 * 60 * 1000 // 2 minutes
    }
  },
  
  // Circuit Breaker Configuration
  circuitBreaker: {
    enabled: process.env.CIRCUIT_BREAKER_ENABLED !== 'false',
    failureThreshold: parseInt(process.env.CIRCUIT_BREAKER_FAILURE_THRESHOLD) || 5,
    resetTimeout: parseInt(process.env.CIRCUIT_BREAKER_RESET_TIMEOUT) || 60000, // 1 minute
    monitoringPeriod: parseInt(process.env.CIRCUIT_BREAKER_MONITORING_PERIOD) || 60000 // 1 minute
  },
  
  // Feature Flags
  features: {
    enhancedLogging: process.env.FEATURE_ENHANCED_LOGGING !== 'false',
    requestTracing: process.env.FEATURE_REQUEST_TRACING !== 'false',
    syncMonitoring: process.env.FEATURE_SYNC_MONITORING !== 'false',
    orchestration: process.env.FEATURE_ORCHESTRATION !== 'false',
    advancedMetrics: process.env.FEATURE_ADVANCED_METRICS !== 'false',
    developmentEndpoints: process.env.NODE_ENV === 'development'
  }
};

// Configuration validation
const validateConfig = () => {
  const errors = [];
  
  // Required environment variables
  const requiredEnvVars = ['JWT_SECRET'];
  const missing = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missing.length > 0) {
    errors.push(`Missing required environment variables: ${missing.join(', ')}`);
  }
  
  // Validate JWT secret length
  if (config.security.jwtSecret && config.security.jwtSecret.length < 32) {
    errors.push('JWT_SECRET must be at least 32 characters long');
  }
  
  // Validate service URLs
  Object.entries(config.services).forEach(([serviceName, url]) => {
    if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
      errors.push(`Invalid ${serviceName.toUpperCase()}_SERVICE_URL: ${url}`);
    }
  });
  
  // Validate numeric configurations
  if (config.monitoring.healthCheckInterval < 5000) {
    errors.push('Health check interval must be at least 5 seconds');
  }
  
  if (config.sync.checkInterval < 60000) {
    errors.push('Sync check interval must be at least 1 minute');
  }
  
  if (config.orchestration.timeout < 1000) {
    errors.push('Orchestration timeout must be at least 1 second');
  }
  
  return errors;
};

// Validate configuration
const validationErrors = validateConfig();

if (validationErrors.length > 0) {
  console.error('Configuration validation failed:');
  validationErrors.forEach(error => console.error(`  - ${error}`));
  
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  } else {
    console.warn('Using default values for development');
    // Set safe defaults for development
    if (!config.security.jwtSecret) {
      config.security.jwtSecret = 'dev-secret-change-in-production-must-be-at-least-32-characters-long';
    }
  }
}

// Helper functions for configuration
const getServiceUrl = (serviceName) => {
  return config.services[serviceName];
};

const isFeatureEnabled = (featureName) => {
  return config.features[featureName] === true;
};

const getRateLimitConfig = (endpoint) => {
  return config.security.rateLimits[endpoint] || config.security.rateLimits.global;
};

const getCacheTtl = (type) => {
  return config.orchestration.cacheTtl[type] || config.orchestration.cacheExpiry;
};

// Log configuration summary (without secrets)
const logConfiguration = () => {
  console.log('=== Gateway Configuration Summary ===');
  console.log(`Environment: ${config.environment}`);
  console.log(`Port: ${config.port}`);
  console.log(`Services: ${Object.keys(config.services).join(', ')}`);
  console.log(`CORS Origins: ${config.security.corsOrigins.length} configured`);
  console.log(`Features enabled: ${Object.entries(config.features).filter(([, enabled]) => enabled).map(([name]) => name).join(', ')}`);
  console.log(`Sync monitoring: ${config.sync.enabled ? 'enabled' : 'disabled'}`);
  console.log(`Orchestration: ${config.orchestration.enabled ? 'enabled' : 'disabled'}`);
  console.log(`Circuit breaker: ${config.circuitBreaker.enabled ? 'enabled' : 'disabled'}`);
  console.log('=====================================');
};

// Log configuration on startup
if (process.env.NODE_ENV !== 'test') {
  logConfiguration();
}

// Export configuration with helper functions
module.exports = {
  ...config,
  helpers: {
    getServiceUrl,
    isFeatureEnabled,
    getRateLimitConfig,
    getCacheTtl,
    validateConfig,
    logConfiguration
  }
};