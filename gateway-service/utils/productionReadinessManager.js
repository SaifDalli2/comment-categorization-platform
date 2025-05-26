// gateway-service/utils/productionReadinessManager.js
const fs = require('fs').promises;
const path = require('path');
const logger = require('./logger');
const metrics = require('./metrics');

class ProductionReadinessManager {
  constructor(options = {}) {
    this.gracefulShutdownTimeout = options.gracefulShutdownTimeout || 
      parseInt(process.env.GRACEFUL_SHUTDOWN_TIMEOUT) || 30000;
    this.healthCheckInterval = options.healthCheckInterval || 30000;
    this.livenessCheckInterval = options.livenessCheckInterval || 10000;
    
    this.isShuttingDown = false;
    this.isReady = false;
    this.dependencies = new Map();
    this.healthChecks = new Map();
    this.startTime = Date.now();
    
    this.setupSignalHandlers();
    this.initializeHealthChecks();
    this.startPeriodicChecks();
  }

  // Initialize default health checks
  initializeHealthChecks() {
    // Basic system health checks
    this.addHealthCheck('memory', this.checkMemoryUsage.bind(this));
    this.addHealthCheck('cpu', this.checkCPUUsage.bind(this));
    this.addHealthCheck('disk', this.checkDiskSpace.bind(this));
    this.addHealthCheck('connections', this.checkConnectionLimits.bind(this));
    
    // Application-specific health checks
    this.addHealthCheck('configuration', this.checkConfiguration.bind(this));
    this.addHealthCheck('environment', this.checkEnvironment.bind(this));
    this.addHealthCheck('secrets', this.checkSecrets.bind(this));
  }

  // Add a dependency that must be healthy for the service to be ready
  addDependency(name, healthCheckFn, options = {}) {
    this.dependencies.set(name, {
      name,
      healthCheck: healthCheckFn,
      required: options.required !== false,
      timeout: options.timeout || 5000,
      lastCheck: null,
      status: 'unknown',
      error: null
    });
  }

  // Add a health check
  addHealthCheck(name, checkFn, options = {}) {
    this.healthChecks.set(name, {
      name,
      check: checkFn,
      critical: options.critical === true,
      timeout: options.timeout || 5000,
      lastCheck: null,
      status: 'unknown',
      error: null,
      lastDuration: 0
    });
  }

  // Setup graceful shutdown signal handlers
  setupSignalHandlers() {
    const signals = ['SIGTERM', 'SIGINT', 'SIGUSR2'];
    
    signals.forEach(signal => {
      process.on(signal, () => {
        logger.info(`Received ${signal}, initiating graceful shutdown`, {
          shutdown: {
            signal,
            startTime: new Date().toISOString(),
            timeout: this.gracefulShutdownTimeout
          }
        });
        
        this.gracefulShutdown(signal);
      });
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.fatal('Uncaught exception detected', {
        shutdown: {
          reason: 'uncaught_exception',
          error: error.message,
          stack: error.stack
        }
      }, error);
      
      this.emergencyShutdown('uncaught_exception');
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.fatal('Unhandled promise rejection detected', {
        shutdown: {
          reason: 'unhandled_rejection',
          error: reason?.message || reason
        }
      });
      
      this.emergencyShutdown('unhandled_rejection');
    });
  }

  // Graceful shutdown procedure
  async gracefulShutdown(signal) {
    if (this.isShuttingDown) {
      logger.warn('Shutdown already in progress');
      return;
    }

    this.isShuttingDown = true;
    this.isReady = false;

    const shutdownSteps = [
      { name: 'Stop accepting new connections', fn: this.stopAcceptingConnections },
      { name: 'Drain existing connections', fn: this.drainConnections },
      { name: 'Close connection pools', fn: this.closeConnectionPools },
      { name: 'Flush logs and metrics', fn: this.flushLogsAndMetrics },
      { name: 'Close database connections', fn: this.closeDatabaseConnections },
      { name: 'Cleanup resources', fn: this.cleanupResources }
    ];

    const shutdownPromise = this.executeShutdownSteps(shutdownSteps);
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Shutdown timeout')), this.gracefulShutdownTimeout);
    });

    try {
      await Promise.race([shutdownPromise, timeoutPromise]);
      logger.info('Graceful shutdown completed successfully');
      process.exit(0);
    } catch (error) {
      logger.error('Graceful shutdown failed, forcing exit', {
        shutdown: {
          error: error.message,
          timeout: this.gracefulShutdownTimeout
        }
      }, error);
      process.exit(1);
    }
  }

  async executeShutdownSteps(steps) {
    for (const step of steps) {
      try {
        logger.info(`Shutdown step: ${step.name}`);
        await step.fn.call(this);
        logger.info(`Shutdown step completed: ${step.name}`);
      } catch (error) {
        logger.error(`Shutdown step failed: ${step.name}`, {
          shutdown: {
            step: step.name,
            error: error.message
          }
        }, error);
        // Continue with other steps even if one fails
      }
    }
  }

  // Emergency shutdown for critical failures
  emergencyShutdown(reason) {
    logger.fatal(`Emergency shutdown initiated: ${reason}`);
    
    // Try to flush critical logs
    setTimeout(() => {
      process.exit(1);
    }, 1000);
  }

  // Shutdown step implementations
  async stopAcceptingConnections() {
    // Signal to load balancer that this instance is shutting down
    this.isReady = false;
    
    // If we have an Express server reference, stop accepting new connections
    if (global.server) {
      global.server.close();
    }
  }

  async drainConnections() {
    // Wait for existing requests to complete
    const maxWait = 10000; // 10 seconds
    const checkInterval = 100;
    let waited = 0;

    while (waited < maxWait) {
      const activeConnections = global.activeConnections || 0;
      if (activeConnections === 0) {
        break;
      }
      
      await new Promise(resolve => setTimeout(resolve, checkInterval));
      waited += checkInterval;
    }
  }

  async closeConnectionPools() {
    // Close HTTP connection pools
    if (global.connectionPoolManager) {
      await global.connectionPoolManager.closeAllPools();
    }
  }

  async flushLogsAndMetrics() {
    // Flush any pending logs and metrics
    if (global.logger && typeof global.logger.flush === 'function') {
      await global.logger.flush();
    }
    
    if (global.metrics && typeof global.metrics.flush === 'function') {
      await global.metrics.flush();
    }
  }

  async closeDatabaseConnections() {
    // Close Redis connections
    if (global.redis && global.redis.isOpen) {
      await global.redis.quit();
    }
    
    // Close any other database connections
    if (global.dbConnections) {
      for (const connection of global.dbConnections) {
        if (typeof connection.close === 'function') {
          await connection.close();
        }
      }
    }
  }

  async cleanupResources() {
    // Cleanup any other resources
    if (global.cacheMiddleware) {
      await global.cacheMiddleware.cleanup();
    }
    
    if (global.compressionMiddleware) {
      await global.compressionMiddleware.cleanup();
    }
  }

  // Health check implementations
  async checkMemoryUsage() {
    const memUsage = process.memoryUsage();
    const totalMemory = require('os').totalmem();
    const usedPercentage = (memUsage.rss / totalMemory) * 100;
    
    const threshold = 85; // 85% memory usage threshold
    const isHealthy = usedPercentage < threshold;
    
    return {
      healthy: isHealthy,
      details: {
        usage: `${usedPercentage.toFixed(2)}%`,
        rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
        external: `${Math.round(memUsage.external / 1024 / 1024)}MB`,
        threshold: `${threshold}%`
      },
      message: isHealthy ? 'Memory usage is normal' : `Memory usage is high: ${usedPercentage.toFixed(2)}%`
    };
  }

  async checkCPUUsage() {
    const cpus = require('os').cpus();
    const loadAvg = require('os').loadavg();
    const avgLoad = loadAvg[0]; // 1-minute average
    const numCPUs = cpus.length;
    const cpuPercentage = (avgLoad / numCPUs) * 100;
    
    const threshold = 80; // 80% CPU usage threshold
    const isHealthy = cpuPercentage < threshold;
    
    return {
      healthy: isHealthy,
      details: {
        usage: `${cpuPercentage.toFixed(2)}%`,
        loadAverage: loadAvg,
        cores: numCPUs,
        threshold: `${threshold}%`
      },
      message: isHealthy ? 'CPU usage is normal' : `CPU usage is high: ${cpuPercentage.toFixed(2)}%`
    };
  }

  async checkDiskSpace() {
    try {
      const stats = await fs.statfs(process.cwd());
      const totalSpace = stats.bavail * stats.bsize;
      const freeSpace = stats.bfree * stats.bsize;
      const usedPercentage = ((totalSpace - freeSpace) / totalSpace) * 100;
      
      const threshold = 90; // 90% disk usage threshold
      const isHealthy = usedPercentage < threshold;
      
      return {
        healthy: isHealthy,
        details: {
          usage: `${usedPercentage.toFixed(2)}%`,
          free: `${Math.round(freeSpace / 1024 / 1024 / 1024)}GB`,
          total: `${Math.round(totalSpace / 1024 / 1024 / 1024)}GB`,
          threshold: `${threshold}%`
        },
        message: isHealthy ? 'Disk space is sufficient' : `Disk space is low: ${usedPercentage.toFixed(2)}%`
      };
    } catch (error) {
      return {
        healthy: false,
        details: { error: error.message },
        message: 'Unable to check disk space'
      };
    }
  }

  async checkConnectionLimits() {
    const activeConnections = global.activeConnections || 0;
    const maxConnections = parseInt(process.env.MAX_CONNECTIONS) || 1000;
    const usagePercentage = (activeConnections / maxConnections) * 100;
    
    const threshold = 85; // 85% connection limit threshold
    const isHealthy = usagePercentage < threshold;
    
    return {
      healthy: isHealthy,
      details: {
        active: activeConnections,
        max: maxConnections,
        usage: `${usagePercentage.toFixed(2)}%`,
        threshold: `${threshold}%`
      },
      message: isHealthy ? 'Connection usage is normal' : `Connection usage is high: ${usagePercentage.toFixed(2)}%`
    };
  }

  async checkConfiguration() {
    const requiredEnvVars = [
      'JWT_SECRET',
      'SESSION_SECRET',
      'AUTH_SERVICE_URL',
      'COMMENT_SERVICE_URL',
      'INDUSTRY_SERVICE_URL',
      'NPS_SERVICE_URL'
    ];
    
    const missing = requiredEnvVars.filter(varName => !process.env[varName]);
    const isHealthy = missing.length === 0;
    
    return {
      healthy: isHealthy,
      details: {
        required: requiredEnvVars.length,
        configured: requiredEnvVars.length - missing.length,
        missing: missing
      },
      message: isHealthy ? 'All required configuration is present' : `Missing configuration: ${missing.join(', ')}`
    };
  }

  async checkEnvironment() {
    const nodeVersion = process.version;
    const nodeEnv = process.env.NODE_ENV;
    const expectedNodeVersion = '16.0.0'; // Minimum required version
    
    const isValidNodeVersion = this.compareVersions(nodeVersion.slice(1), expectedNodeVersion) >= 0;
    const isValidEnv = ['development', 'test', 'production'].includes(nodeEnv);
    const isHealthy = isValidNodeVersion && isValidEnv;
    
    return {
      healthy: isHealthy,
      details: {
        nodeVersion,
        nodeEnv,
        platform: process.platform,
        arch: process.arch,
        uptime: Math.floor(process.uptime()),
        pid: process.pid
      },
      message: isHealthy ? 'Environment is valid' : 'Environment validation failed'
    };
  }

  async checkSecrets() {
    const secrets = ['JWT_SECRET', 'SESSION_SECRET'];
    const issues = [];
    
    for (const secret of secrets) {
      const value = process.env[secret];
      if (!value) {
        issues.push(`${secret} is not set`);
      } else if (value.length < 32) {
        issues.push(`${secret} is too short (minimum 32 characters)`);
      } else if (value.includes('change') || value.includes('default')) {
        issues.push(`${secret} appears to be using default value`);
      }
    }
    
    const isHealthy = issues.length === 0;
    
    return {
      healthy: isHealthy,
      details: {
        secretsChecked: secrets.length,
        issues: issues.length
      },
      message: isHealthy ? 'All secrets are properly configured' : `Secret issues: ${issues.join(', ')}`
    };
  }

  // Utility method to compare version strings
  compareVersions(a, b) {
    const aParts = a.split('.').map(Number);
    const bParts = b.split('.').map(Number);
    
    for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
      const aPart = aParts[i] || 0;
      const bPart = bParts[i] || 0;
      
      if (aPart > bPart) return 1;
      if (aPart < bPart) return -1;
    }
    
    return 0;
  }

  // Perform all health checks
  async performHealthChecks() {
    const results = {};
    let overallHealthy = true;
    
    for (const [name, check] of this.healthChecks.entries()) {
      const startTime = Date.now();
      
      try {
        const result = await Promise.race([
          check.check(),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Health check timeout')), check.timeout)
          )
        ]);
        
        check.lastCheck = new Date().toISOString();
        check.lastDuration = Date.now() - startTime;
        check.status = result.healthy ? 'healthy' : 'unhealthy';
        check.error = null;
        
        results[name] = {
          ...result,
          duration: check.lastDuration,
          lastCheck: check.lastCheck
        };
        
        if (!result.healthy && check.critical) {
          overallHealthy = false;
        }
        
      } catch (error) {
        check.lastCheck = new Date().toISOString();
        check.lastDuration = Date.now() - startTime;
        check.status = 'error';
        check.error = error.message;
        
        results[name] = {
          healthy: false,
          message: `Health check failed: ${error.message}`,
          duration: check.lastDuration,
          lastCheck: check.lastCheck
        };
        
        if (check.critical) {
          overallHealthy = false;
        }
      }
    }
    
    return { overall: overallHealthy, checks: results };
  }

  // Perform dependency checks
  async performDependencyChecks() {
    const results = {};
    let overallReady = true;
    
    for (const [name, dependency] of this.dependencies.entries()) {
      const startTime = Date.now();
      
      try {
        const result = await Promise.race([
          dependency.healthCheck(),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Dependency check timeout')), dependency.timeout)
          )
        ]);
        
        dependency.lastCheck = new Date().toISOString();
        dependency.status = result.healthy ? 'healthy' : 'unhealthy';
        dependency.error = null;
        
        results[name] = {
          ...result,
          required: dependency.required,
          lastCheck: dependency.lastCheck
        };
        
        if (!result.healthy && dependency.required) {
          overallReady = false;
        }
        
      } catch (error) {
        dependency.lastCheck = new Date().toISOString();
        dependency.status = 'error';
        dependency.error = error.message;
        
        results[name] = {
          healthy: false,
          required: dependency.required,
          message: `Dependency check failed: ${error.message}`,
          lastCheck: dependency.lastCheck
        };
        
        if (dependency.required) {
          overallReady = false;
        }
      }
    }
    
    this.isReady = overallReady;
    return { overall: overallReady, dependencies: results };
  }

  // Start periodic health checks
  startPeriodicChecks() {
    // Health checks
    setInterval(async () => {
      if (!this.isShuttingDown) {
        await this.performHealthChecks();
      }
    }, this.healthCheckInterval);

    // Readiness checks
    setInterval(async () => {
      if (!this.isShuttingDown) {
        await this.performDependencyChecks();
      }
    }, this.healthCheckInterval);
  }

  // Express routes for health and readiness
  getHealthRoutes() {
    const router = require('express').Router();

    // Liveness probe - basic health check
    router.get('/live', async (req, res) => {
      if (this.isShuttingDown) {
        return res.status(503).json({
          status: 'shutting_down',
          timestamp: new Date().toISOString()
        });
      }

      const uptime = Math.floor((Date.now() - this.startTime) / 1000);
      
      res.json({
        status: 'alive',
        uptime,
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0'
      });
    });

    // Readiness probe - dependency checks
    router.get('/ready', async (req, res) => {
      if (this.isShuttingDown) {
        return res.status(503).json({
          status: 'shutting_down',
          ready: false,
          timestamp: new Date().toISOString()
        });
      }

      const dependencyResults = await this.performDependencyChecks();
      
      res.status(dependencyResults.overall ? 200 : 503).json({
        status: dependencyResults.overall ? 'ready' : 'not_ready',
        ready: dependencyResults.overall,
        dependencies: dependencyResults.dependencies,
        timestamp: new Date().toISOString()
      });
    });

    // Detailed health check
    router.get('/health/detailed', async (req, res) => {
      const [healthResults, dependencyResults] = await Promise.all([
        this.performHealthChecks(),
        this.performDependencyChecks()
      ]);

      const overallStatus = healthResults.overall && dependencyResults.overall ? 'healthy' : 'unhealthy';
      
      res.status(overallStatus === 'healthy' ? 200 : 503).json({
        status: overallStatus,
        timestamp: new Date().toISOString(),
        uptime: Math.floor((Date.now() - this.startTime) / 1000),
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV,
        health: healthResults,
        readiness: dependencyResults,
        shutdown: {
          gracefulShutdownEnabled: true,
          isShuttingDown: this.isShuttingDown,
          timeout: this.gracefulShutdownTimeout
        }
      });
    });

    return router;
  }
}

module.exports = ProductionReadinessManager;