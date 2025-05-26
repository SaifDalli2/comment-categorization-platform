// gateway-service/routes/configManagement.js
const express = require('express');
const configIntegration = require('../utils/configIntegration');
const logger = require('../utils/logger');

class ConfigManagementRoutes {
  constructor() {
    this.router = express.Router();
    this.configManager = configIntegration.getConfigManager();
    this.setupRoutes();
  }

  setupRoutes() {
    // Get current configuration (filtered for security)
    this.router.get('/api/config', (req, res) => {
      try {
        const { section, includeSecrets = false } = req.query;
        
        // Only admins can view secrets
        const canViewSecrets = includeSecrets === 'true' && req.userContext?.roles?.includes('admin');
        
        let config;
        if (section) {
          config = this.configManager.getSection(section);
        } else {
          config = this.configManager.getAllConfig();
        }
        
        // Filter sensitive information unless explicitly requested by admin
        const filteredConfig = canViewSecrets ? config : this.filterSecrets(config);
        
        res.json({
          success: true,
          data: {
            configuration: filteredConfig,
            environment: process.env.NODE_ENV,
            sources: this.configManager.getConfigSources(),
            lastLoaded: new Date().toISOString()
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Failed to retrieve configuration', { error: error.message }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve configuration');
      }
    });

    // Get configuration schema
    this.router.get('/api/config/schema', (req, res) => {
      try {
        const schema = this.configManager.exportSchema();
        
        res.json({
          success: true,
          data: {
            schema,
            sections: Object.keys(schema),
            environment: process.env.NODE_ENV
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Failed to retrieve configuration schema', { error: error.message }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve configuration schema');
      }
    });

    // Validate configuration section
    this.router.post('/api/config/validate', (req, res) => {
      try {
        const { section, configuration } = req.body;
        
        if (!section || !configuration) {
          return res.error.validation('Section and configuration are required');
        }
        
        const validation = this.configManager.validateValue(section, configuration);
        
        if (validation.error) {
          return res.json({
            success: true,
            data: {
              valid: false,
              errors: validation.error.details.map(d => ({
                path: d.path.join('.'),
                message: d.message,
                value: d.context?.value
              }))
            },
            metadata: {
              timestamp: new Date().toISOString(),
              requestId: req.headers['x-request-id'],
              service: 'gateway'
            }
          });
        }
        
        res.json({
          success: true,
          data: {
            valid: true,
            normalizedValue: validation.value
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Configuration validation failed', { 
          section: req.body.section, 
          error: error.message 
        }, error);
        return res.error.send('VALIDATION_ERROR', error.message);
      }
    });

    // Update configuration (admin only)
    this.router.put('/api/config/:section', this.requireAdmin(), (req, res) => {
      try {
        const { section } = req.params;
        const { configuration, reason } = req.body;
        
        if (!configuration) {
          return res.error.validation('Configuration is required');
        }
        
        // Backup current configuration
        const backup = configIntegration.exportConfiguration();
        
        // Validate new configuration
        const validation = this.configManager.validateValue(section, configuration);
        if (validation.error) {
          return res.error.validation(`Configuration validation failed: ${validation.error.message}`);
        }
        
        // Apply configuration update
        const oldConfig = this.configManager.getSection(section);
        this.configManager.set(section, validation.value);
        
        logger.info('Configuration updated via API', {
          config: {
            section,
            updatedBy: req.userContext?.email,
            reason: reason || 'No reason provided',
            changes: this.getConfigDiff(oldConfig, validation.value)
          }
        });
        
        res.json({
          success: true,
          data: {
            section,
            updated: true,
            backup: {
              timestamp: backup.timestamp,
              available: true
            },
            newConfiguration: this.filterSecrets(validation.value)
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Configuration update failed', { 
          section: req.params.section, 
          error: error.message,
          updatedBy: req.userContext?.email
        }, error);
        return res.error.send('CONFIGURATION_ERROR', error.message);
      }
    });

    // Service URL management
    this.router.put('/api/config/services/:serviceName/urls', this.requireAdmin(), (req, res) => {
      try {
        const { serviceName } = req.params;
        const { urls, reason } = req.body;
        
        if (!Array.isArray(urls) || urls.length === 0) {
          return res.error.validation('URLs must be a non-empty array');
        }
        
        configIntegration.updateServiceUrls(serviceName, urls);
        
        logger.info('Service URLs updated via API', {
          config: {
            serviceName,
            urls,
            updatedBy: req.userContext?.email,
            reason: reason || 'No reason provided'
          }
        });
        
        res.json({
          success: true,
          data: {
            serviceName,
            urls,
            updated: true
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Service URL update failed', {
          serviceName: req.params.serviceName,
          error: error.message,
          updatedBy: req.userContext?.email
        }, error);
        return res.error.send('CONFIGURATION_ERROR', error.message);
      }
    });

    // CORS origins management
    this.router.put('/api/config/cors/origins', this.requireAdmin(), (req, res) => {
      try {
        const { origins, reason } = req.body;
        
        if (!Array.isArray(origins)) {
          return res.error.validation('Origins must be an array');
        }
        
        configIntegration.updateCorsOrigins(origins);
        
        logger.info('CORS origins updated via API', {
          config: {
            origins,
            updatedBy: req.userContext?.email,
            reason: reason || 'No reason provided'
          }
        });
        
        res.json({
          success: true,
          data: {
            origins,
            updated: true
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('CORS origins update failed', {
          error: error.message,
          updatedBy: req.userContext?.email
        }, error);
        return res.error.send('CONFIGURATION_ERROR', error.message);
      }
    });

    // Rate limiting configuration
    this.router.put('/api/config/rate-limits', this.requireAdmin(), (req, res) => {
      try {
        const { rateLimits, reason } = req.body;
        
        if (!rateLimits || typeof rateLimits !== 'object') {
          return res.error.validation('Rate limits configuration is required');
        }
        
        configIntegration.updateRateLimits(rateLimits);
        
        logger.info('Rate limits updated via API', {
          config: {
            rateLimits,
            updatedBy: req.userContext?.email,
            reason: reason || 'No reason provided'
          }
        });
        
        res.json({
          success: true,
          data: {
            rateLimits,
            updated: true
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Rate limits update failed', {
          error: error.message,
          updatedBy: req.userContext?.email
        }, error);
        return res.error.send('CONFIGURATION_ERROR', error.message);
      }
    });

    // Configuration export (admin only)
    this.router.get('/api/config/export', this.requireAdmin(), (req, res) => {
      try {
        const { includeSecrets = false } = req.query;
        const canIncludeSecrets = includeSecrets === 'true' && req.userContext?.roles?.includes('super_admin');
        
        const exportData = configIntegration.exportConfiguration();
        
        if (!canIncludeSecrets) {
          exportData.configuration = this.filterSecrets(exportData.configuration);
        }
        
        logger.info('Configuration exported', {
          config: {
            exportedBy: req.userContext?.email,
            includeSecrets: canIncludeSecrets,
            environment: exportData.environment
          }
        });
        
        res.setHeader('Content-Disposition', `attachment; filename="gateway-config-${exportData.environment}-${Date.now()}.json"`);
        res.setHeader('Content-Type', 'application/json');
        res.json(exportData);
      } catch (error) {
        logger.error('Configuration export failed', {
          error: error.message,
          exportedBy: req.userContext?.email
        }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to export configuration');
      }
    });

    // Configuration import (super admin only)
    this.router.post('/api/config/import', this.requireSuperAdmin(), (req, res) => {
      try {
        const { configurationData, reason, dryRun = false } = req.body;
        
        if (!configurationData) {
          return res.error.validation('Configuration data is required');
        }
        
        if (dryRun === true) {
          // Validate import without applying
          const tempConfigManager = new (require('../config/ConfigManager'))();
          tempConfigManager.config = configurationData.configuration;
          tempConfigManager.validateConfiguration();
          
          return res.json({
            success: true,
            data: {
              valid: true,
              dryRun: true,
              message: 'Configuration validation successful'
            },
            metadata: {
              timestamp: new Date().toISOString(),
              requestId: req.headers['x-request-id'],
              service: 'gateway'
            }
          });
        }
        
        const result = configIntegration.importConfiguration(configurationData);
        
        logger.warn('Configuration imported via API', {
          config: {
            importedBy: req.userContext?.email,
            reason: reason || 'No reason provided',
            importedFrom: configurationData.timestamp,
            backupAvailable: result.backup ? true : false
          }
        });
        
        res.json({
          success: true,
          data: {
            imported: true,
            backup: result.backup,
            message: 'Configuration imported successfully'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Configuration import failed', {
          error: error.message,
          importedBy: req.userContext?.email
        }, error);
        return res.error.send('CONFIGURATION_ERROR', error.message);
      }
    });

    // Configuration health check
    this.router.get('/api/config/health', (req, res) => {
      try {
        const health = {
          status: 'healthy',
          environment: process.env.NODE_ENV,
          configSources: this.configManager.getConfigSources(),
          validation: 'passed',
          lastValidated: new Date().toISOString()
        };

        // Check for configuration issues
        const issues = [];
        
        try {
          configIntegration.validateSecrets();
        } catch (error) {
          issues.push('Secret validation failed');
          health.status = 'degraded';
        }
        
        if (configIntegration.isProduction()) {
          try {
            configIntegration.validateProductionConfig();
          } catch (error) {
            issues.push('Production validation failed');
            health.status = 'degraded';
          }
        }
        
        if (issues.length > 0) {
          health.issues = issues;
        }
        
        res.status(health.status === 'healthy' ? 200 : 503).json({
          ...health,
          timestamp: new Date().toISOString(),
          service: 'gateway-config'
        });
      } catch (error) {
        logger.error('Configuration health check failed', { error: error.message }, error);
        res.status(503).json({
          status: 'unhealthy',
          error: error.message,
          timestamp: new Date().toISOString(),
          service: 'gateway-config'
        });
      }
    });

    // Development-only endpoints
    if (configIntegration.isDevelopment()) {
      this.setupDevelopmentRoutes();
    }
  }

  setupDevelopmentRoutes() {
    // Reload configuration (development only)
    this.router.post('/api/config/reload', (req, res) => {
      try {
        this.configManager.reloadConfiguration();
        
        logger.info('Configuration reloaded via API', {
          config: {
            reloadedBy: req.userContext?.email || 'anonymous',
            environment: process.env.NODE_ENV
          }
        });
        
        res.json({
          success: true,
          data: {
            reloaded: true,
            timestamp: new Date().toISOString()
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Configuration reload failed', { error: error.message }, error);
        return res.error.send('CONFIGURATION_ERROR', error.message);
      }
    });

    // Reset to defaults (development only)
    this.router.post('/api/config/reset', (req, res) => {
      try {
        const { section } = req.body;
        
        // Create fresh config manager to get defaults
        const freshConfigManager = new (require('../config/ConfigManager'))();
        
        if (section) {
          const defaultConfig = freshConfigManager.getSection(section);
          this.configManager.set(section, defaultConfig);
        } else {
          this.configManager.config = freshConfigManager.getAllConfig();
        }
        
        logger.warn('Configuration reset to defaults', {
          config: {
            section: section || 'all',
            resetBy: req.userContext?.email || 'anonymous'
          }
        });
        
        res.json({
          success: true,
          data: {
            reset: true,
            section: section || 'all'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Configuration reset failed', { error: error.message }, error);
        return res.error.send('CONFIGURATION_ERROR', error.message);
      }
    });
  }

  // Helper methods
  filterSecrets(config) {
    const filtered = JSON.parse(JSON.stringify(config));
    
    const secretPaths = [
      'security.jwtSecret',
      'security.sessionSecret'
    ];
    
    for (const path of secretPaths) {
      this.setNestedValue(filtered, path, '[REDACTED]');
    }
    
    return filtered;
  }

  setNestedValue(obj, path, value) {
    const keys = path.split('.');
    let current = obj;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (!(keys[i] in current)) return;
      current = current[keys[i]];
    }
    
    if (current && keys[keys.length - 1] in current) {
      current[keys[keys.length - 1]] = value;
    }
  }

  getConfigDiff(oldConfig, newConfig) {
    const changes = [];
    
    const compare = (old, new_, path = '') => {
      for (const key of new Set([...Object.keys(old || {}), ...Object.keys(new_ || {})])) {
        const currentPath = path ? `${path}.${key}` : key;
        const oldValue = old?.[key];
        const newValue = new_?.[key];
        
        if (oldValue !== newValue) {
          if (typeof oldValue === 'object' && typeof newValue === 'object' && !Array.isArray(oldValue) && !Array.isArray(newValue)) {
            compare(oldValue, newValue, currentPath);
          } else {
            changes.push({
              path: currentPath,
              from: oldValue,
              to: newValue
            });
          }
        }
      }
    };
    
    compare(oldConfig, newConfig);
    return changes;
  }

  requireAdmin() {
    return (req, res, next) => {
      if (!req.userContext?.roles?.includes('admin')) {
        return res.error.forbidden('Admin access required for configuration management');
      }
      next();
    };
  }

  requireSuperAdmin() {
    return (req, res, next) => {
      if (!req.userContext?.roles?.includes('super_admin')) {
        return res.error.forbidden('Super admin access required for this operation');
      }
      next();
    };
  }

  getRouter() {
    return this.router;
  }
}

module.exports = ConfigManagementRoutes;