// gateway-service/services/ServiceRegistry.js
const axios = require('axios');
const EventEmitter = require('events');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

class ServiceRegistry extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.services = new Map();
    this.healthCheckInterval = options.healthCheckInterval || parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000;
    this.serviceTimeout = options.serviceTimeout || parseInt(process.env.SERVICE_TIMEOUT) || 5000;
    this.circuitBreakerEnabled = options.circuitBreakerEnabled || process.env.CIRCUIT_BREAKER_ENABLED === 'true';
    this.loadBalanceStrategy = options.loadBalanceStrategy || process.env.LOAD_BALANCE_STRATEGY || 'round_robin';
    
    // Circuit breaker settings
    this.circuitBreakerThreshold = options.circuitBreakerThreshold || 5; // failures before opening
    this.circuitBreakerTimeout = options.circuitBreakerTimeout || 60000; // 1 minute
    this.circuitBreakerResetTimeout = options.circuitBreakerResetTimeout || 30000; // 30 seconds
    
    this.healthCheckTimer = null;
    this.isShuttingDown = false;
    
    this.initializeServices();
    this.startHealthChecks();
  }

  // Initialize services from environment variables
  initializeServices() {
    const serviceConfigs = [
      {
        name: 'auth',
        urls: this.parseServiceUrls(process.env.AUTH_SERVICE_URL || 'http://localhost:3001'),
        healthPath: '/health',
        readyPath: '/ready'
      },
      {
        name: 'comment',
        urls: this.parseServiceUrls(process.env.COMMENT_SERVICE_URL || 'http://localhost:3002'),
        healthPath: '/health',
        readyPath: '/ready'
      },
      {
        name: 'industry',
        urls: this.parseServiceUrls(process.env.INDUSTRY_SERVICE_URL || 'http://localhost:3003'),
        healthPath: '/health',
        readyPath: '/ready'
      },
      {
        name: 'nps',
        urls: this.parseServiceUrls(process.env.NPS_SERVICE_URL || 'http://localhost:3004'),
        healthPath: '/health',
        readyPath: '/ready'
      }
    ];

    // Support for legacy monolith during migration
    if (process.env.MONOLITH_SERVICE_URL) {
      serviceConfigs.push({
        name: 'monolith',
        urls: this.parseServiceUrls(process.env.MONOLITH_SERVICE_URL),
        healthPath: '/health',
        readyPath: '/health' // Monolith might not have separate ready endpoint
      });
    }

    serviceConfigs.forEach(config => {
      this.registerService(config.name, config);
    });

    logger.info('Service registry initialized', {
      serviceRegistry: {
        registeredServices: Array.from(this.services.keys()),
        healthCheckInterval: this.healthCheckInterval,
        circuitBreakerEnabled: this.circuitBreakerEnabled,
        loadBalanceStrategy: this.loadBalanceStrategy
      }
    });
  }

  // Parse service URLs (supports multiple instances)
  parseServiceUrls(urlString) {
    if (!urlString) return [];
    
    return urlString.split(',').map(url => url.trim()).filter(url => url.length > 0);
  }

  // Register a service with multiple instances
  registerService(name, config) {
    const serviceInstances = config.urls.map((url, index) => ({
      id: `${name}-${index}`,
      name,
      url: url.replace(/\/$/, ''), // Remove trailing slash
      healthPath: config.healthPath || '/health',
      readyPath: config.readyPath || '/ready',
      status: 'unknown',
      lastHealthCheck: null,
      lastResponseTime: null,
      consecutiveFailures: 0,
      circuitBreakerState: 'closed', // closed, open, half-open
      circuitBreakerLastFailure: null,
      requestCount: 0,
      errorCount: 0,
      metadata: config.metadata || {}
    }));

    this.services.set(name, {
      name,
      instances: serviceInstances,
      lastUsedIndex: 0, // For round-robin load balancing
      config
    });

    logger.info('Service registered', {
      serviceRegistry: {
        serviceName: name,
        instanceCount: serviceInstances.length,
        urls: config.urls
      }
    });
  }

  // Get a healthy service instance using load balancing
  getService(serviceName) {
    const service = this.services.get(serviceName);
    if (!service) {
      return null;
    }

    const healthyInstances = service.instances.filter(instance => 
      instance.status === 'healthy' && instance.circuitBreakerState !== 'open'
    );

    if (healthyInstances.length === 0) {
      // Try half-open circuit breakers
      const halfOpenInstances = service.instances.filter(instance => 
        instance.circuitBreakerState === 'half-open'
      );
      
      if (halfOpenInstances.length > 0) {
        return halfOpenInstances[0]; // Try one half-open instance
      }
      
      return null; // No healthy instances available
    }

    // Apply load balancing strategy
    switch (this.loadBalanceStrategy) {
      case 'least_connections':
        return this.getLeastConnectionsInstance(healthyInstances);
      case 'least_response_time':
        return this.getLeastResponseTimeInstance(healthyInstances);
      case 'random':
        return healthyInstances[Math.floor(Math.random() * healthyInstances.length)];
      case 'round_robin':
      default:
        return this.getRoundRobinInstance(service, healthyInstances);
    }
  }

  // Round-robin load balancing
  getRoundRobinInstance(service, healthyInstances) {
    if (healthyInstances.length === 1) {
      return healthyInstances[0];
    }

    service.lastUsedIndex = (service.lastUsedIndex + 1) % healthyInstances.length;
    return healthyInstances[service.lastUsedIndex];
  }

  // Least connections load balancing
  getLeastConnectionsInstance(instances) {
    return instances.reduce((least, current) => 
      current.requestCount < least.requestCount ? current : least
    );
  }

  // Least response time load balancing
  getLeastResponseTimeInstance(instances) {
    const instancesWithResponseTime = instances.filter(i => i.lastResponseTime !== null);
    
    if (instancesWithResponseTime.length === 0) {
      return instances[0]; // Fallback to first instance
    }

    return instancesWithResponseTime.reduce((fastest, current) => 
      current.lastResponseTime < fastest.lastResponseTime ? current : fastest
    );
  }

  // Get all services with their status
  getAllServices() {
    const servicesStatus = {};
    
    for (const [name, service] of this.services) {
      servicesStatus[name] = {
        name,
        totalInstances: service.instances.length,
        healthyInstances: service.instances.filter(i => i.status === 'healthy').length,
        instances: service.instances.map(instance => ({
          id: instance.id,
          url: instance.url,
          status: instance.status,
          lastHealthCheck: instance.lastHealthCheck,
          lastResponseTime: instance.lastResponseTime,
          consecutiveFailures: instance.consecutiveFailures,
          circuitBreakerState: instance.circuitBreakerState,
          requestCount: instance.requestCount,
          errorCount: instance.errorCount
        }))
      };
    }
    
    return servicesStatus;
  }

  // Record service request
  recordRequest(serviceName, instanceId, success, responseTime) {
    const service = this.services.get(serviceName);
    if (!service) return;

    const instance = service.instances.find(i => i.id === instanceId);
    if (!instance) return;

    instance.requestCount++;
    instance.lastResponseTime = responseTime;

    if (success) {
      instance.consecutiveFailures = 0;
      if (instance.circuitBreakerState === 'half-open') {
        instance.circuitBreakerState = 'closed';
        logger.info('Circuit breaker closed after successful request', {
          serviceRegistry: {
            serviceName,
            instanceId,
            url: instance.url
          }
        });

        // Record circuit breaker state change
        metrics.recordCircuitBreakerState(serviceName, instanceId, 'closed');
      }
    } else {
      instance.errorCount++;
      instance.consecutiveFailures++;
      instance.circuitBreakerLastFailure = new Date();

      // Check if circuit breaker should open
      if (this.circuitBreakerEnabled && 
          instance.consecutiveFailures >= this.circuitBreakerThreshold &&
          instance.circuitBreakerState === 'closed') {
        
        instance.circuitBreakerState = 'open';
        
        logger.warn('Circuit breaker opened due to consecutive failures', {
          serviceRegistry: {
            serviceName,
            instanceId,
            url: instance.url,
            consecutiveFailures: instance.consecutiveFailures,
            threshold: this.circuitBreakerThreshold
          }
        });

        // Record circuit breaker metrics
        metrics.recordCircuitBreakerState(serviceName, instanceId, 'open');
        metrics.recordCircuitBreakerTrip(serviceName, instanceId);

        // Schedule circuit breaker to half-open
        setTimeout(() => {
          if (instance.circuitBreakerState === 'open') {
            instance.circuitBreakerState = 'half-open';
            logger.info('Circuit breaker moved to half-open state', {
              serviceRegistry: {
                serviceName,
                instanceId,
                url: instance.url
              }
            });

            // Record circuit breaker state change
            metrics.recordCircuitBreakerState(serviceName, instanceId, 'half-open');
          }
        }, this.circuitBreakerResetTimeout);
      }
    }
  }

  // Start health check monitoring
  startHealthChecks() {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
    }

    this.healthCheckTimer = setInterval(() => {
      if (!this.isShuttingDown) {
        this.performHealthChecks();
      }
    }, this.healthCheckInterval);

    // Perform initial health check
    this.performHealthChecks();
  }

  // Perform health checks on all service instances
  async performHealthChecks() {
    const healthCheckPromises = [];

    for (const [serviceName, service] of this.services) {
      for (const instance of service.instances) {
        healthCheckPromises.push(this.checkInstanceHealth(serviceName, instance));
      }
    }

    try {
      await Promise.allSettled(healthCheckPromises);
    } catch (error) {
      logger.error('Error during health checks', {}, error);
    }
  }

  // Check health of a single service instance
  async checkInstanceHealth(serviceName, instance) {
    const startTime = Date.now();
    
    try {
      const response = await axios.get(`${instance.url}${instance.healthPath}`, {
        timeout: this.serviceTimeout,
        headers: {
          'User-Agent': 'Gateway-Health-Check/1.0',
          'X-Health-Check': 'true'
        }
      });

      const responseTime = Date.now() - startTime;
      const wasUnhealthy = instance.status !== 'healthy';

      instance.status = response.status === 200 ? 'healthy' : 'unhealthy';
      instance.lastHealthCheck = new Date().toISOString();
      instance.lastResponseTime = responseTime;

      // Record health check metrics
      metrics.recordServiceHealth(serviceName, instance.id, instance.status === 'healthy', responseTime);

      if (wasUnhealthy && instance.status === 'healthy') {
        logger.info('Service instance recovered', {
          serviceRegistry: {
            serviceName,
            instanceId: instance.id,
            url: instance.url,
            responseTime
          }
        });

        this.emit('serviceRecovered', { serviceName, instance });
      }

    } catch (error) {
      const responseTime = Date.now() - startTime;
      const wasHealthy = instance.status === 'healthy';

      instance.status = 'unhealthy';
      instance.lastHealthCheck = new Date().toISOString();
      instance.lastResponseTime = responseTime;

      // Record health check metrics
      metrics.recordServiceHealth(serviceName, instance.id, false, responseTime);

      if (wasHealthy) {
        logger.warn('Service instance became unhealthy', {
          serviceRegistry: {
            serviceName,
            instanceId: instance.id,
            url: instance.url,
            responseTime
          }
        }, error);

        this.emit('serviceUnhealthy', { serviceName, instance, error });
      }
    }
  }

  // Get service registry statistics
  getStats() {
    const stats = {
      totalServices: this.services.size,
      totalInstances: 0,
      healthyInstances: 0,
      unhealthyInstances: 0,
      openCircuitBreakers: 0,
      halfOpenCircuitBreakers: 0,
      lastHealthCheck: new Date().toISOString(),
      services: {}
    };

    for (const [name, service] of this.services) {
      stats.totalInstances += service.instances.length;
      
      const serviceStats = {
        instances: service.instances.length,
        healthy: 0,
        unhealthy: 0,
        openCircuitBreakers: 0,
        halfOpenCircuitBreakers: 0,
        totalRequests: 0,
        totalErrors: 0,
        avgResponseTime: 0
      };

      let totalResponseTime = 0;
      let responseTimeCount = 0;

      service.instances.forEach(instance => {
        if (instance.status === 'healthy') {
          serviceStats.healthy++;
          stats.healthyInstances++;
        } else {
          serviceStats.unhealthy++;
          stats.unhealthyInstances++;
        }

        if (instance.circuitBreakerState === 'open') {
          serviceStats.openCircuitBreakers++;
          stats.openCircuitBreakers++;
        } else if (instance.circuitBreakerState === 'half-open') {
          serviceStats.halfOpenCircuitBreakers++;
          stats.halfOpenCircuitBreakers++;
        }

        serviceStats.totalRequests += instance.requestCount;
        serviceStats.totalErrors += instance.errorCount;

        if (instance.lastResponseTime !== null) {
          totalResponseTime += instance.lastResponseTime;
          responseTimeCount++;
        }
      });

      if (responseTimeCount > 0) {
        serviceStats.avgResponseTime = Math.round(totalResponseTime / responseTimeCount);
      }

      stats.services[name] = serviceStats;
    }

    return stats;
  }

  // Graceful shutdown
  async shutdown() {
    this.isShuttingDown = true;
    
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }

    logger.info('Service registry shutting down gracefully');
    this.emit('shutdown');
  }

  // Dynamic service registration (for development/testing)
  dynamicRegister(serviceName, config) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Dynamic service registration not allowed in production');
    }

    this.registerService(serviceName, config);
    return this.getService(serviceName);
  }

  // Remove service (for development/testing)
  unregisterService(serviceName) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Service unregistration not allowed in production');
    }

    const removed = this.services.delete(serviceName);
    
    if (removed) {
      logger.info('Service unregistered', {
        serviceRegistry: { serviceName }
      });
    }

    return removed;
  }
}

module.exports = ServiceRegistry;