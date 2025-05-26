// gateway-service/utils/configIntegration.js
const ConfigManager = require('../config/ConfigManager');
const logger = require('./logger');

class ConfigIntegration {
  constructor() {
    this.configManager = new ConfigManager();
    this.integrations = new Map();
    this.setupIntegrations();
    this.setupConfigChangeHandlers();
  }

  setupIntegrations() {
    // Register configuration integration points
    this.integrations.set('cors', this.updateCorsConfig.bind(this));
    this.integrations.set('security', this.updateSecurityConfig.bind(this));
    this.integrations.set('services', this.updateServicesConfig.bind(this));
    this.integrations.set('errorHandling', this.updateErrorHandlingConfig.bind(this));
    this.integrations.set('monitoring', this.updateMonitoringConfig.bind(this));
  }

  setupConfigChangeHandlers() {
    this.configManager.onConfigChange((changes, newConfig) => {
      logger.info('Configuration changes detected', {
        config: {
          changesCount: changes.length,
          sections: [...new Set(changes.map(c => c.path.split('.')[0]))]
        }
      });

      // Apply changes to relevant systems
      for (const change of changes) {
        const section = change.path.split('.')[0];
        const integration = this.integrations.get(section);
        
        if (integration) {
          try {
            integration(newConfig[section], change);
          } catch (error) {
            logger.error('Failed to apply configuration change', {
              config: {
                section,
                path: change.path,
                error: error.message
              }
            }, error);
          }
        }
      }
    });
  }

  updateCorsConfig(corsConfig, change) {
    if (global.corsManager) {
      global.corsManager.updateConfiguration(corsConfig);
      logger.info('CORS configuration updated', {
        config: {
          path: change.path,
          newValue: change.newValue
        }
      });
    }
  }

  updateSecurityConfig(securityConfig, change) {
    if (global.securityManager) {
      global.securityManager.updateConfiguration(securityConfig);
      logger.info('Security configuration updated', {
        config: {
          path: change.path,
          newValue: change.newValue
        }
      });
    }
  }

  updateServicesConfig(servicesConfig, change) {
    if (global.serviceRegistry) {
      global.serviceRegistry.updateConfiguration(servicesConfig);
      logger.info('Services configuration updated', {
        config: {
          path: change.path,
          newValue: change.newValue
        }
      });
    }
  }

  updateErrorHandlingConfig(errorConfig, change) {
    if (global.errorHandler) {
      global.errorHandler.updateConfiguration(errorConfig);
      logger.info('Error handling configuration updated', {
        config: {
          path: change.path,
          newValue: change.newValue
        }
      });
    }
  }

  updateMonitoringConfig(monitoringConfig, change) {
    if (global.monitoringMiddleware) {
      global.monitoringMiddleware.updateConfiguration(monitoringConfig);
      logger.info('Monitoring configuration updated', {
        config: {
          path: change.path,
          newValue: change.newValue
        }
      });
    }
  }

  // Utility methods for accessing configuration
  getServerConfig() {
    return this.configManager.getSection('server');
  }

  getSecurityConfig() {
    return this.configManager.getSection('security');
  }

  getServicesConfig() {
    return this.configManager.getSection('services');
  }

  getErrorHandlingConfig() {
    return this.configManager.getSection('errorHandling');
  }

  getMonitoringConfig() {
    return this.configManager.getSection('monitoring');
  }

  getDevelopmentConfig() {
    return this.configManager.getSection('development');
  }

  getProductionConfig() {
    return this.configManager.getSection('production');
  }

  // Environment-specific getters
  isProduction() {
    return process.env.NODE_ENV === 'production';
  }

  isDevelopment() {
    return process.env.NODE_ENV === 'development';
  }

  isTestEnvironment() {
    return process.env.NODE_ENV === 'test';
  }

  // Configuration validation helpers
  validateServiceUrl(serviceName) {
    const serviceConfig = this.configManager.get(`services.registry.${serviceName}`);
    
    if (!serviceConfig) {
      throw new Error(`Service ${serviceName} not configured`);
    }

    if (!serviceConfig.urls || serviceConfig.urls.length === 0) {
      throw new Error(`Service ${serviceName} has no URLs configured`);
    }

    return serviceConfig;
  }

  validateSecrets() {
    const secrets = [
      'security.jwtSecret',
      'security.sessionSecret'
    ];

    const errors = [];

    for (const secretPath of secrets) {
      const secret = this.configManager.get(secretPath);
      
      if (!secret) {
        errors.push(`Missing required secret: ${secretPath}`);
      } else if (secret.length < 32) {
        errors.push(`Secret too short: ${secretPath} (minimum 32 characters)`);
      } else if (secret.includes('change-this') || secret.includes('your-secret')) {
        errors.push(`Default secret detected: ${secretPath} (must be changed for production)`);
      }
    }

    if (errors.length > 0) {
      throw new Error(`Secret validation failed:\n${errors.join('\n')}`);
    }

    return true;
  }

  validateProductionConfig() {
    if (!this.isProduction()) {
      return true;
    }

    const errors = [];

    // Validate CORS origins
    const corsOrigins = this.configManager.get('security.cors.allowedOrigins', []);
    if (corsOrigins.includes('*') || corsOrigins.some(origin => origin.includes('localhost'))) {
      errors.push('CORS origins contain wildcard or localhost in production');
    }

    // Validate service URLs (should be HTTPS in production)
    const services = this.configManager.get('services.registry', {});
    for (const [serviceName, serviceConfig] of Object.entries(services)) {
      if (serviceConfig.urls && serviceConfig.urls.some(url => url.startsWith('http://'))) {
        errors.push(`Service ${serviceName} uses insecure HTTP in production`);
      }
    }

    // Validate logging configuration
    const logLevel = this.configManager.get('monitoring.logging.level');
    if (logLevel === 'debug') {
      errors.push('Debug logging enabled in production');
    }

    // Validate development features are disabled
    const devConfig = this.configManager.getSection('development');
    const enabledDevFeatures = Object.entries(devConfig)
      .filter(([key, value]) => key.startsWith('enable') && value === true)
      .map(([key]) => key);

    if (enabledDevFeatures.length > 0) {
      errors.push(`Development features enabled in production: ${enabledDevFeatures.join(', ')}`);
    }

    if (errors.length > 0) {
      throw new Error(`Production configuration validation failed:\n${errors.join('\n')}`);
    }

    return true;
  }

  // Dynamic configuration updates
  updateServiceUrls(serviceName, urls) {
    if (!Array.isArray(urls) || urls.length === 0) {
      throw new Error('URLs must be a non-empty array');
    }

    // Validate URLs
    for (const url of urls) {
      try {
        new URL(url);
      } catch (error) {
        throw new Error(`Invalid URL: ${url}`);
      }
    }

    this.configManager.set(`services.registry.${serviceName}.urls`, urls);
    
    logger.info('Service URLs updated', {
      config: {
        serviceName,
        urls,
        updateTime: new Date().toISOString()
      }
    });
  }

  updateRateLimits(newLimits) {
    const currentLimits = this.configManager.get('security.rateLimiting');
    const updatedLimits = { ...currentLimits, ...newLimits };
    
    this.configManager.set('security.rateLimiting', updatedLimits);
    
    logger.info('Rate limits updated', {
      config: {
        previous: currentLimits,
        updated: updatedLimits,
        updateTime: new Date().toISOString()
      }
    });
  }

  updateCorsOrigins(origins) {
    if (!Array.isArray(origins)) {
      throw new Error('Origins must be an array');
    }

    // Validate origins
    for (const origin of origins) {
      if (origin !== '*') {
        try {
          new URL(origin);
        } catch (error) {
          throw new Error(`Invalid origin: ${origin}`);
        }
      }
    }

    // Production validation
    if (this.isProduction() && (origins.includes('*') || origins.some(o => o.includes('localhost')))) {
      throw new Error('CORS origins too permissive for production');
    }

    this.configManager.set('security.cors.allowedOrigins', origins);
    
    logger.info('CORS origins updated', {
      config: {
        origins,
        updateTime: new Date().toISOString()
      }
    });
  }

  // Configuration export/import for backups
  exportConfiguration() {
    return {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV,
      version: this.configManager.get('server.version', '1.0.0'),
      configuration: this.configManager.getAllConfig()
    };
  }

  importConfiguration(configData) {
    if (!configData.configuration) {
      throw new Error('Invalid configuration data format');
    }

    // Backup current configuration
    const backup = this.exportConfiguration();
    
    try {
      // Validate imported configuration
      const tempConfigManager = new ConfigManager();
      tempConfigManager.config = configData.configuration;
      tempConfigManager.validateConfiguration();
      
      // Apply new configuration
      this.configManager.config = configData.configuration;
      this.configManager.validateConfiguration();
      
      logger.info('Configuration imported successfully', {
        config: {
          importedFrom: configData.timestamp,
          importedEnvironment: configData.environment,
          currentEnvironment: process.env.NODE_ENV
        }
      });
      
      return { success: true, backup };
    } catch (error) {
      logger.error('Configuration import failed', {
        config: {
          error: error.message,
          backupAvailable: true
        }
      }, error);
      
      throw error;
    }
  }

  // Get configuration manager instance
  getConfigManager() {
    return this.configManager;
  }

  // Cleanup
  cleanup() {
    this.configManager.cleanup();
    this.integrations.clear();
    
    logger.info('Configuration integration cleaned up');
  }
}

// Create singleton instance
const configIntegration = new ConfigIntegration();

module.exports = configIntegration;