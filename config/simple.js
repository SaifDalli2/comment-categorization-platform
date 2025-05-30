// gateway-service/config/simple.js - Enhanced with Debug and Service Discovery
const dotenv = require('dotenv');
const axios = require('axios');

// Load environment variables
dotenv.config();

// Service URL validation and discovery
const validateServiceUrl = (serviceName, url) => {
  if (!url || url === `https://your-${serviceName}-service.herokuapp.com`) {
    console.warn(`⚠️  Service ${serviceName} URL not configured, using placeholder`);
    return false;
  }
  return true;
};

// Build service configuration with validation
const buildServiceConfig = () => {
  const services = {
    auth: process.env.AUTH_SERVICE_URL || 'https://your-auth-service.herokuapp.com',
    comment: process.env.COMMENT_SERVICE_URL || 'https://your-comment-service.herokuapp.com',
    industry: process.env.INDUSTRY_SERVICE_URL || 'https://your-industry-service.herokuapp.com',
    nps: process.env.NPS_SERVICE_URL || 'https://your-nps-service.herokuapp.com'
  };

  // Validate service URLs
  Object.entries(services).forEach(([name, url]) => {
    const isValid = validateServiceUrl(name, url);
    console.log(`${isValid ? '✅' : '❌'} ${name.toUpperCase()} Service: ${url}`);
  });

  return services;
};

// CORS origins configuration
const buildCorsOrigins = () => {
  const origins = [];
  
  // Add configured origins
  if (process.env.ALLOWED_ORIGINS) {
    const configuredOrigins = process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim());
    origins.push(...configuredOrigins);
  }
  
  // Add common production patterns
  origins.push(
    'https://gateway-service-b25f91548194.herokuapp.com',
    'https://*.herokuapp.com',
    'https://*.netlify.app',
    'https://*.vercel.app'
  );
  
  // Add development origins
  if (process.env.NODE_ENV === 'development') {
    origins.push(
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173',
      'http://localhost:8080',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173'
    );
  }
  
  return [...new Set(origins)]; // Remove duplicates
};

const config = {
  port: parseInt(process.env.PORT) || 3000,
  
  services: buildServiceConfig(),
  
  security: {
    jwtSecret: process.env.JWT_SECRET,
    corsOrigins: buildCorsOrigins(),
    apiKeyPrefix: process.env.API_KEY_PREFIX || 'sk-'
  },
  
  monitoring: {
    logLevel: process.env.LOG_LEVEL || 'info',
    healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000,
    enableMetrics: process.env.ENABLE_METRICS !== 'false'
  },
  
  proxy: {
    timeout: parseInt(process.env.PROXY_TIMEOUT) || 30000,
    retries: parseInt(process.env.PROXY_RETRIES) || 3,
    retryDelay: parseInt(process.env.RETRY_DELAY) || 1000
  },
  
  rateLimit: {
    global: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
      max: parseInt(process.env.RATE_LIMIT_MAX) || 100
    },
    auth: {
      windowMs: 15 * 60 * 1000,
      max: parseInt(process.env.AUTH_RATE_LIMIT) || 20
    },
    comments: {
      windowMs: 15 * 60 * 1000,
      max: parseInt(process.env.COMMENTS_RATE_LIMIT) || 50
    }
  }
};

// Configuration validation
const validateConfig = () => {
  const errors = [];
  const warnings = [];
  
  // Required environment variables
  const requiredEnvVars = ['JWT_SECRET'];
  const missing = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missing.length > 0) {
    errors.push(`Missing required environment variables: ${missing.join(', ')}`);
  }
  
  // JWT secret validation
  if (config.security.jwtSecret) {
    if (config.security.jwtSecret.length < 32) {
      errors.push('JWT_SECRET must be at least 32 characters long');
    }
    if (config.security.jwtSecret === 'dev-secret-change-in-production-32-chars-min') {
      warnings.push('Using default JWT_SECRET - change in production');
    }
  }
  
  // Service URL validation
  const hasConfiguredServices = Object.values(config.services).some(url => 
    !url.includes('your-') && !url.includes('localhost')
  );
  
  if (!hasConfiguredServices && process.env.NODE_ENV === 'production') {
    warnings.push('No backend services configured for production');
  }
  
  // Port validation
  if (config.port < 1 || config.port > 65535) {
    errors.push(`Invalid port number: ${config.port}`);
  }
  
  return { errors, warnings };
};

// Service discovery function
const discoverServices = async () => {
  const discoveries = {};
  
  for (const [serviceName, serviceUrl] of Object.entries(config.services)) {
    try {
      // Skip placeholder URLs
      if (serviceUrl.includes('your-') || serviceUrl.includes('localhost')) {
        discoveries[serviceName] = { status: 'not_configured', url: serviceUrl };
        continue;
      }
      
      const response = await axios.get(`${serviceUrl}/health`, { 
        timeout: 5000,
        validateStatus: () => true // Accept any status code
      });
      
      discoveries[serviceName] = {
        status: response.status === 200 ? 'healthy' : 'unhealthy',
        url: serviceUrl,
        responseTime: response.responseTime || 0,
        version: response.data?.version || 'unknown'
      };
    } catch (error) {
      discoveries[serviceName] = {
        status: 'unreachable',
        url: serviceUrl,
        error: error.message
      };
    }
  }
  
  return discoveries;
};

// Initialize configuration
const initializeConfig = () => {
  const { errors, warnings } = validateConfig();
  
  // Handle errors
  if (errors.length > 0) {
    console.error('❌ Configuration Errors:');
    errors.forEach(error => console.error(`  - ${error}`));
    
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    } else {
      console.warn('⚠️  Continuing with invalid configuration in development mode');
      // Set fallback values for development
      if (!config.security.jwtSecret) {
        config.security.jwtSecret = 'dev-secret-change-in-production-32-chars-min';
        console.warn('  - Using fallback JWT_SECRET for development');
      }
    }
  }
  
  // Handle warnings
  if (warnings.length > 0) {
    console.warn('⚠️  Configuration Warnings:');
    warnings.forEach(warning => console.warn(`  - ${warning}`));
  }
  
  // Log successful configuration
  console.log('\n🚀 Gateway Configuration:');
  console.log(`  - Port: ${config.port}`);
  console.log(`  - Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`  - Log Level: ${config.monitoring.logLevel}`);
  console.log(`  - CORS Origins: ${config.security.corsOrigins.length} configured`);
  console.log(`  - Health Check Interval: ${config.monitoring.healthCheckInterval}ms`);
  console.log(`  - Proxy Timeout: ${config.proxy.timeout}ms`);
  
  // Service configuration summary
  console.log('\n📡 Service Configuration:');
  Object.entries(config.services).forEach(([name, url]) => {
    const status = url.includes('your-') ? '❌ Not Configured' : '✅ Configured';
    console.log(`  - ${name.toUpperCase()}: ${status}`);
  });
  
  console.log('\n🔒 Security Configuration:');
  console.log(`  - JWT Secret: ${config.security.jwtSecret ? '✅ Set' : '❌ Missing'}`);
  console.log(`  - CORS Origins: ${config.security.corsOrigins.length} origins`);
  
  console.log('\n📊 Monitoring Configuration:');
  console.log(`  - Metrics Enabled: ${config.monitoring.enableMetrics ? '✅' : '❌'}`);
  console.log(`  - Health Checks: Every ${config.monitoring.healthCheckInterval / 1000}s`);
  
  console.log('\n🛡️  Rate Limiting:');
  console.log(`  - Global: ${config.rateLimit.global.max} requests per ${config.rateLimit.global.windowMs / 60000} minutes`);
  console.log(`  - Auth: ${config.rateLimit.auth.max} requests per ${config.rateLimit.auth.windowMs / 60000} minutes`);
  console.log(`  - Comments: ${config.rateLimit.comments.max} requests per ${config.rateLimit.comments.windowMs / 60000} minutes`);
};

// Helper functions
const getServiceConfig = (serviceName) => {
  return {
    url: config.services[serviceName],
    timeout: config.proxy.timeout,
    retries: config.proxy.retries,
    retryDelay: config.proxy.retryDelay
  };
};

const isServiceConfigured = (serviceName) => {
  const url = config.services[serviceName];
  return url && !url.includes('your-') && !url.includes('localhost');
};

const getEnvironmentInfo = () => {
  return {
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || 'development',
    platform: process.platform,
    uptime: Math.floor(process.uptime()),
    memory: process.memoryUsage(),
    port: config.port,
    services: Object.keys(config.services),
    configuredServices: Object.keys(config.services).filter(isServiceConfigured)
  };
};

// Initialize configuration on load
initializeConfig();

// Export configuration and utilities
module.exports = {
  ...config,
  discoverServices,
  getServiceConfig,
  isServiceConfigured,
  getEnvironmentInfo,
  validateConfig
};
