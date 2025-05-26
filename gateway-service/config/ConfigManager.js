// gateway-service/config/ConfigManager.js
const fs = require('fs');
const path = require('path');
const Joi = require('joi');
const logger = require('../utils/logger');

class ConfigManager {
  constructor(environment = process.env.NODE_ENV || 'development') {
    this.environment = environment;
    this.config = {};
    this.watchers = new Map();
    this.validators = new Map();
    this.changeListeners = new Set();
    
    this.setupValidators();
    this.loadConfigurations();
    this.validateConfiguration();
    
    // Watch for configuration changes in development
    if (environment === 'development' && process.env.ENABLE_CONFIG_WATCH !== 'false') {
      this.setupConfigWatch();
    }
  }

  setupValidators() {
    // Server configuration validator
    this.validators.set('server', Joi.object({
      port: Joi.number().port().default(3000),
      host: Joi.string().hostname().default('0.0.0.0'),
      timeout: Joi.number().positive().default(30000),
      keepAliveTimeout: Joi.number().positive().default(5000),
      headersTimeout: Joi.number().positive().default(60000),
      maxHeaderSize: Joi.number().positive().default(16384),
      bodySizeLimit: Joi.string().default('10mb'),
      enableCompression: Joi.boolean().default(true),
      enableRequestLogging: Joi.boolean().default(true)
    }));

    // Security configuration validator
    this.validators.set('security', Joi.object({
      jwtSecret: Joi.string().min(32).required(),
      jwtExpiresIn: Joi.string().default('7d'),
      jwtIssuer: Joi.string().default('claude-analysis-gateway'),
      sessionSecret: Joi.string().min(32).required(),
      bcryptRounds: Joi.number().min(10).max(15).default(12),
      rateLimiting: Joi.object({
        enabled: Joi.boolean().default(true),
        windowMs: Joi.number().positive().default(900000), // 15 minutes
        maxRequests: Joi.number().positive().default(100),
        skipSuccessfulRequests: Joi.boolean().default(false),
        skipFailedRequests: Joi.boolean().default(false),
        authWindowMs: Joi.number().positive().default(900000), // 15 minutes
        authMaxRequests: Joi.number().positive().default(5),
        enableSlowDown: Joi.boolean().default(true),
        slowDownDelay: Joi.number().positive().default(500)
      }).default(),
      cors: Joi.object({
        enabled: Joi.boolean().default(true),
        allowedOrigins: Joi.array().items(Joi.string().uri()).default(['http://localhost:3000']),
        allowedMethods: Joi.array().items(Joi.string()).default(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']),
        allowedHeaders: Joi.array().items(Joi.string()).default(['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key']),
        credentials: Joi.boolean().default(true),
        maxAge: Joi.number().positive().default(86400),
        optionsSuccessStatus: Joi.number().default(204)
      }).default(),
      helmet: Joi.object({
        enabled: Joi.boolean().default(true),
        contentSecurityPolicy: Joi.object({
          enabled: Joi.boolean().default(true),
          directives: Joi.object().default({
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"]
          })
        }).default(),
        hsts: Joi.object({
          enabled: Joi.boolean().default(true),
          maxAge: Joi.number().positive().default(31536000),
          includeSubDomains: Joi.boolean().default(true)
        }).default()
      }).default()
    }));

    // Service discovery configuration validator
    this.validators.set('services', Joi.object({
      discovery: Joi.object({
        healthCheckInterval: Joi.number().positive().default(30000),
        healthCheckTimeout: Joi.number().positive().default(5000),
        unhealthyThreshold: Joi.number().positive().default(3),
        healthyThreshold: Joi.number().positive().default(2),
        enableCircuitBreaker: Joi.boolean().default(true),
        circuitBreakerThreshold: Joi.number().positive().default(5),
        circuitBreakerTimeout: Joi.number().positive().default(60000),
        retryAttempts: Joi.number().min(0).max(10).default(3),
        retryDelay: Joi.number().positive().default(1000),
        enableServiceMesh: Joi.boolean().default(false)
      }).default(),
      registry: Joi.object().pattern(
        Joi.string(), // service name
        Joi.object({
          urls: Joi.array().items(Joi.string().uri()).min(1).required(),
          healthPath: Joi.string().default('/health'),
          readyPath: Joi.string().default('/ready'),
          timeout: Joi.number().positive().default(30000),
          retries: Joi.number().min(0).max(5).default(3),
          metadata: Joi.object().default({}),
          authentication: Joi.object({
            type: Joi.string().valid('none', 'jwt', 'api-key').default('none'),
            credentials: Joi.object().when('type', {
              is: 'jwt',
              then: Joi.object({
                secret: Joi.string().required(),
                algorithm: Joi.string().default('HS256')
              }),
              otherwise: Joi.object({
                apiKey: Joi.string()
              })
            })
          }).default({ type: 'none' })
        })
      ).default({})
    }));

    // Error handling configuration validator
    this.validators.set('errorHandling', Joi.object({
      enabled: Joi.boolean().default(true),
      logLevel: Joi.string().valid('debug', 'info', 'warn', 'error').default('warn'),
      enableStackTrace: Joi.boolean().default(false),
      errorRateThresholds: Joi.object({
        warning: Joi.number().min(0).max(1).default(0.05),
        critical: Joi.number().min(0).max(1).default(0.15)
      }).default(),
      cleanup: Joi.object({
        interval: Joi.number().positive().default(300000), // 5 minutes
        maxAge: Joi.number().positive().default(1800000) // 30 minutes
      }).default(),
      notification: Joi.object({
        enabled: Joi.boolean().default(false),
        webhookUrl: Joi.string().uri().allow(''),
        slackChannel: Joi.string().allow(''),
        emailRecipients: Joi.array().items(Joi.string().email()).default([])
      }).default()
    }));

    // Monitoring configuration validator
    this.validators.set('monitoring', Joi.object({
      enabled: Joi.boolean().default(true),
      prometheus: Joi.object({
        enabled: Joi.boolean().default(true),
        endpoint: Joi.string().default('/metrics'),
        collectDefaultMetrics: Joi.boolean().default(true),
        prefix: Joi.string().default('gateway_')
      }).default(),
      logging: Joi.object({
        level: Joi.string().valid('debug', 'info', 'warn', 'error').default('info'),
        format: Joi.string().valid('json', 'text').default('json'),
        enableColors: Joi.boolean().default(false),
        enableTimestamp: Joi.boolean().default(true),
        maxFileSize: Joi.string().default('10MB'),
        maxFiles: Joi.number().positive().default(5),
        enableRotation: Joi.boolean().default(true)
      }).default(),
      tracing: Joi.object({
        enabled: Joi.boolean().default(false),
        jaegerEndpoint: Joi.string().uri().allow(''),
        serviceName: Joi.string().default('claude-analysis-gateway'),
        sampleRate: Joi.number().min(0).max(1).default(0.1)
      }).default(),
      healthChecks: Joi.object({
        endpoint: Joi.string().default('/health'),
        detailedEndpoint: Joi.string().default('/health/detailed'),
        includeServices: Joi.boolean().default(true),
        timeout: Joi.number().positive().default(5000)
      }).default()
    }));

    // Development configuration validator
    this.validators.set('development', Joi.object({
      enableHotReload: Joi.boolean().default(true),
      enableConfigWatch: Joi.boolean().default(true),
      enableTestEndpoints: Joi.boolean().default(true),
      enableSwaggerUI: Joi.boolean().default(true),
      enableDebugLogs: Joi.boolean().default(true),
      mockServices: Joi.object().pattern(
        Joi.string(),
        Joi.object({
          enabled: Joi.boolean().default(false),
          responses: Joi.object().default({}),
          delay: Joi.number().min(0).default(0)
        })
      ).default({})
    }));

    // Production configuration validator
    this.validators.set('production', Joi.object({
      enableMetrics: Joi.boolean().default(true),
      enableHealthChecks: Joi.boolean().default(true),
      enableGracefulShutdown: Joi.boolean().default(true),
      shutdownTimeout: Joi.number().positive().default(30000),
      staticFilesCache: Joi.object({
        enabled: Joi.boolean().default(true),
        maxAge: Joi.string().default('1d'),
        etag: Joi.boolean().default(true)
      }).default(),
      clustering: Joi.object({
        enabled: Joi.boolean().default(false),
        workers: Joi.number().positive().default(require('os').cpus().length)
      }).default()
    }));
  }

  loadConfigurations() {
    // Load base configuration
    this.config = this.loadConfigFile('base');
    
    // Load environment-specific configuration
    const envConfig = this.loadConfigFile(this.environment);
    if (envConfig) {
      this.config = this.mergeConfigs(this.config, envConfig);
    }

    // Load local overrides if they exist
    const localConfig = this.loadConfigFile('local');
    if (localConfig) {
      this.config = this.mergeConfigs(this.config, localConfig);
    }

    // Override with environment variables
    this.applyEnvironmentVariables();

    logger.info('Configuration loaded successfully', {
      config: {
        environment: this.environment,
        sources: this.getConfigSources(),
        validation: 'pending'
      }
    });
  }

  loadConfigFile(name) {
    const configPath = path.join(__dirname, `${name}.json`);
    
    try {
      if (fs.existsSync(configPath)) {
        const content = fs.readFileSync(configPath, 'utf8');
        return JSON.parse(content);
      }
    } catch (error) {
      logger.warn('Failed to load configuration file', {
        config: {
          file: configPath,
          error: error.message
        }
      });
    }
    
    return null;
  }

  mergeConfigs(base, override) {
    const result = { ...base };
    
    for (const [key, value] of Object.entries(override)) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        result[key] = this.mergeConfigs(result[key] || {}, value);
      } else {
        result[key] = value;
      }
    }
    
    return result;
  }

  applyEnvironmentVariables() {
    // Map environment variables to configuration paths
    const envMappings = {
      // Server configuration
      'PORT': 'server.port',
      'HOST': 'server.host',
      'SERVER_TIMEOUT': 'server.timeout',
      'BODY_SIZE_LIMIT': 'server.bodySizeLimit',
      'ENABLE_COMPRESSION': 'server.enableCompression',
      
      // Security configuration
      'JWT_SECRET': 'security.jwtSecret',
      'JWT_EXPIRES_IN': 'security.jwtExpiresIn',
      'SESSION_SECRET': 'security.sessionSecret',
      'BCRYPT_ROUNDS': 'security.bcryptRounds',
      
      // Rate limiting
      'RATE_LIMIT_WINDOW_MS': 'security.rateLimiting.windowMs',
      'RATE_LIMIT_MAX_REQUESTS': 'security.rateLimiting.maxRequests',
      'AUTH_RATE_LIMIT_MAX': 'security.rateLimiting.authMaxRequests',
      
      // CORS configuration
      'CORS_ALLOWED_ORIGINS': 'security.cors.allowedOrigins',
      'CORS_CREDENTIALS': 'security.cors.credentials',
      
      // Service discovery
      'HEALTH_CHECK_INTERVAL': 'services.discovery.healthCheckInterval',
      'HEALTH_CHECK_TIMEOUT': 'services.discovery.healthCheckTimeout',
      'CIRCUIT_BREAKER_ENABLED': 'services.discovery.enableCircuitBreaker',
      'RETRY_ATTEMPTS': 'services.discovery.retryAttempts',
      
      // Service URLs
      'AUTH_SERVICE_URL': 'services.registry.auth.urls',
      'COMMENT_SERVICE_URL': 'services.registry.comment.urls',
      'INDUSTRY_SERVICE_URL': 'services.registry.industry.urls',
      'NPS_SERVICE_URL': 'services.registry.nps.urls',
      
      // Error handling
      'ERROR_LOG_LEVEL': 'errorHandling.logLevel',
      'ENABLE_STACK_TRACE': 'errorHandling.enableStackTrace',
      'ERROR_RATE_WARNING_THRESHOLD': 'errorHandling.errorRateThresholds.warning',
      'ERROR_RATE_CRITICAL_THRESHOLD': 'errorHandling.errorRateThresholds.critical',
      
      // Monitoring
      'MONITORING_ENABLED': 'monitoring.enabled',
      'PROMETHEUS_ENABLED': 'monitoring.prometheus.enabled',
      'LOG_LEVEL': 'monitoring.logging.level',
      'JAEGER_ENDPOINT': 'monitoring.tracing.jaegerEndpoint',
      
      // Development
      'ENABLE_HOT_RELOAD': 'development.enableHotReload',
      'ENABLE_TEST_ENDPOINTS': 'development.enableTestEndpoints',
      'ENABLE_SWAGGER_UI': 'development.enableSwaggerUI',
      
      // Production
      'CLUSTERING_ENABLED': 'production.clustering.enabled',
      'CLUSTERING_WORKERS': 'production.clustering.workers',
      'SHUTDOWN_TIMEOUT': 'production.shutdownTimeout'
    };

    for (const [envVar, configPath] of Object.entries(envMappings)) {
      const value = process.env[envVar];
      if (value !== undefined) {
        this.setConfigValue(configPath, this.parseEnvValue(value));
      }
    }

    // Handle array environment variables
    this.handleArrayEnvVars();
  }

  handleArrayEnvVars() {
    // Handle comma-separated array values
    const arrayEnvVars = {
      'CORS_ALLOWED_ORIGINS': 'security.cors.allowedOrigins',
      'CORS_ALLOWED_METHODS': 'security.cors.allowedMethods',
      'CORS_ALLOWED_HEADERS': 'security.cors.allowedHeaders',
      'ERROR_EMAIL_RECIPIENTS': 'errorHandling.notification.emailRecipients'
    };

    for (const [envVar, configPath] of Object.entries(arrayEnvVars)) {
      const value = process.env[envVar];
      if (value) {
        const arrayValue = value.split(',').map(item => item.trim()).filter(Boolean);
        this.setConfigValue(configPath, arrayValue);
      }
    }

    // Handle service URL arrays
    const serviceUrlEnvVars = ['AUTH_SERVICE_URL', 'COMMENT_SERVICE_URL', 'INDUSTRY_SERVICE_URL', 'NPS_SERVICE_URL'];
    
    for (const envVar of serviceUrlEnvVars) {
      const value = process.env[envVar];
      if (value) {
        const serviceName = envVar.replace('_SERVICE_URL', '').toLowerCase();
        const urls = value.includes(',') ? value.split(',').map(url => url.trim()) : [value];
        this.setConfigValue(`services.registry.${serviceName}.urls`, urls);
      }
    }
  }

  parseEnvValue(value) {
    // Try to parse as JSON first
    if (value.startsWith('{') || value.startsWith('[')) {
      try {
        return JSON.parse(value);
      } catch (error) {
        // Fall through to other parsing
      }
    }

    // Parse boolean values
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;

    // Parse numeric values
    if (/^\d+$/.test(value)) return parseInt(value, 10);
    if (/^\d*\.\d+$/.test(value)) return parseFloat(value);

    // Return as string
    return value;
  }

  setConfigValue(path, value) {
    const keys = path.split('.');
    let current = this.config;

    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (!(key in current) || typeof current[key] !== 'object') {
        current[key] = {};
      }
      current = current[key];
    }

    current[keys[keys.length - 1]] = value;
  }

  validateConfiguration() {
    const errors = [];
    
    for (const [section, validator] of this.validators.entries()) {
      const sectionConfig = this.config[section] || {};
      const { error, value } = validator.validate(sectionConfig, { 
        abortEarly: false,
        allowUnknown: false,
        stripUnknown: true
      });

      if (error) {
        errors.push(`${section}: ${error.details.map(d => d.message).join(', ')}`);
      } else {
        this.config[section] = value;
      }
    }

    if (errors.length > 0) {
      const errorMessage = `Configuration validation failed:\n${errors.join('\n')}`;
      logger.error('Configuration validation failed', {
        config: {
          environment: this.environment,
          errors: errors
        }
      });
      throw new Error(errorMessage);
    }

    // Additional cross-section validation
    this.performCrossValidation();

    logger.info('Configuration validation completed successfully', {
      config: {
        environment: this.environment,
        sections: Object.keys(this.config),
        validated: true
      }
    });
  }

  performCrossValidation() {
    const errors = [];

    // Validate JWT secret length
    if (this.config.security?.jwtSecret && this.config.security.jwtSecret.length < 32) {
      errors.push('JWT secret must be at least 32 characters long');
    }

    // Validate session secret length
    if (this.config.security?.sessionSecret && this.config.security.sessionSecret.length < 32) {
      errors.push('Session secret must be at least 32 characters long');
    }

    // Validate error rate thresholds
    const errorThresholds = this.config.errorHandling?.errorRateThresholds;
    if (errorThresholds && errorThresholds.warning >= errorThresholds.critical) {
      errors.push('Error rate warning threshold must be less than critical threshold');
    }

    // Validate service URLs
    for (const [serviceName, serviceConfig] of Object.entries(this.config.services?.registry || {})) {
      if (!serviceConfig.urls || serviceConfig.urls.length === 0) {
        errors.push(`Service ${serviceName} must have at least one URL configured`);
      }
    }

    // Validate CORS origins in production
    if (this.environment === 'production') {
      const corsOrigins = this.config.security?.cors?.allowedOrigins || [];
      if (corsOrigins.includes('*') || corsOrigins.some(origin => origin.includes('localhost'))) {
        errors.push('CORS configuration is too permissive for production environment');
      }
    }

    if (errors.length > 0) {
      const errorMessage = `Cross-section validation failed:\n${errors.join('\n')}`;
      throw new Error(errorMessage);
    }
  }

  setupConfigWatch() {
    const configDir = __dirname;
    const watchFiles = ['base.json', `${this.environment}.json`, 'local.json'];

    for (const file of watchFiles) {
      const filePath = path.join(configDir, file);
      if (fs.existsSync(filePath)) {
        const watcher = fs.watchFile(filePath, { interval: 1000 }, () => {
          logger.info('Configuration file changed, reloading', {
            config: {
              file: file,
              path: filePath
            }
          });
          
          try {
            this.reloadConfiguration();
          } catch (error) {
            logger.error('Failed to reload configuration', {
              config: {
                file: file,
                error: error.message
              }
            }, error);
          }
        });
        
        this.watchers.set(file, watcher);
      }
    }

    logger.info('Configuration file watching enabled', {
      config: {
        watchedFiles: Array.from(this.watchers.keys()),
        directory: configDir
      }
    });
  }

  reloadConfiguration() {
    const oldConfig = JSON.parse(JSON.stringify(this.config));
    
    try {
      this.loadConfigurations();
      this.validateConfiguration();
      
      // Notify change listeners
      this.notifyConfigChange(oldConfig, this.config);
      
      logger.info('Configuration reloaded successfully', {
        config: {
          environment: this.environment,
          hasChanges: JSON.stringify(oldConfig) !== JSON.stringify(this.config)
        }
      });
    } catch (error) {
      // Restore old configuration on error
      this.config = oldConfig;
      throw error;
    }
  }

  notifyConfigChange(oldConfig, newConfig) {
    const changes = this.getConfigChanges(oldConfig, newConfig);
    
    for (const listener of this.changeListeners) {
      try {
        listener(changes, newConfig);
      } catch (error) {
        logger.error('Config change listener failed', {
          config: {
            listener: listener.name || 'anonymous',
            error: error.message
          }
        }, error);
      }
    }
  }

  getConfigChanges(oldConfig, newConfig) {
    const changes = [];
    
    const compareObjects = (old, new_, path = '') => {
      for (const key of new Set([...Object.keys(old || {}), ...Object.keys(new_ || {})])) {
        const currentPath = path ? `${path}.${key}` : key;
        const oldValue = old?.[key];
        const newValue = new_?.[key];
        
        if (oldValue !== newValue) {
          if (typeof oldValue === 'object' && typeof newValue === 'object' && !Array.isArray(oldValue) && !Array.isArray(newValue)) {
            compareObjects(oldValue, newValue, currentPath);
          } else {
            changes.push({
              path: currentPath,
              oldValue,
              newValue,
              type: oldValue === undefined ? 'added' : newValue === undefined ? 'removed' : 'modified'
            });
          }
        }
      }
    };
    
    compareObjects(oldConfig, newConfig);
    return changes;
  }

  // Public API methods
  get(path, defaultValue = undefined) {
    const keys = path.split('.');
    let current = this.config;
    
    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = current[key];
      } else {
        return defaultValue;
      }
    }
    
    return current;
  }

  set(path, value) {
    this.setConfigValue(path, value);
    
    // Validate the changed configuration
    try {
      this.validateConfiguration();
    } catch (error) {
      // Revert the change if validation fails
      const keys = path.split('.');
      let current = this.config;
      for (let i = 0; i < keys.length - 1; i++) {
        current = current[keys[i]];
      }
      delete current[keys[keys.length - 1]];
      throw error;
    }
  }

  has(path) {
    return this.get(path) !== undefined;
  }

  getSection(section) {
    return this.config[section] || {};
  }

  getAllConfig() {
    return JSON.parse(JSON.stringify(this.config));
  }

  getConfigSources() {
    const sources = ['base.json'];
    
    if (fs.existsSync(path.join(__dirname, `${this.environment}.json`))) {
      sources.push(`${this.environment}.json`);
    }
    
    if (fs.existsSync(path.join(__dirname, 'local.json'))) {
      sources.push('local.json');
    }
    
    sources.push('environment-variables');
    
    return sources;
  }

  onConfigChange(listener) {
    this.changeListeners.add(listener);
    
    return () => {
      this.changeListeners.delete(listener);
    };
  }

  cleanup() {
    // Stop file watchers
    for (const [file, watcher] of this.watchers.entries()) {
      fs.unwatchFile(path.join(__dirname, file));
    }
    this.watchers.clear();
    
    // Clear change listeners
    this.changeListeners.clear();
    
    logger.info('Configuration manager cleaned up');
  }

  // Development helpers
  exportSchema() {
    const schema = {};
    for (const [section, validator] of this.validators.entries()) {
      schema[section] = validator.describe();
    }
    return schema;
  }

  validateValue(section, value) {
    const validator = this.validators.get(section);
    if (!validator) {
      throw new Error(`Unknown configuration section: ${section}`);
    }
    
    return validator.validate(value);
  }
}

module.exports = ConfigManager;