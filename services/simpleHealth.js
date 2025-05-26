// gateway-service/services/simpleHealth.js
const axios = require('axios');
const config = require('../config/simple');
const logger = require('../utils/simpleLogger');

class SimpleHealth {
  constructor() {
    this.services = config.services;
    this.serviceStatus = new Map();
    this.checkInterval = config.monitoring.healthCheckInterval;
    
    // Initialize service status
    Object.keys(this.services).forEach(serviceName => {
      this.serviceStatus.set(serviceName, {
        name: serviceName,
        url: this.services[serviceName],
        status: 'unknown',
        lastCheck: null,
        lastSuccess: null,
        lastError: null,
        consecutiveFailures: 0,
        responseTime: null
      });
    });
    
    // Start periodic health checks
    this.startHealthChecks();
  }

  // Start periodic health checks
  startHealthChecks() {
    // Initial check
    this.checkAllServices();
    
    // Schedule periodic checks
    this.healthCheckTimer = setInterval(() => {
      this.checkAllServices();
    }, this.checkInterval);
    
    logger.info(`Health checks started with ${this.checkInterval}ms interval`);
  }

  // Check all services
  async checkAllServices() {
    const promises = Object.keys(this.services).map(serviceName =>
      this.checkService(serviceName)
    );
    
    await Promise.allSettled(promises);
  }

  // Check individual service
  async checkService(serviceName) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    const startTime = Date.now();
    
    try {
      const response = await axios.get(`${serviceInfo.url}/health`, {
        timeout: 5000,
        headers: {
          'User-Agent': 'Gateway-Health-Check/1.0'
        }
      });
      
      const responseTime = Date.now() - startTime;
      const isHealthy = response.status === 200;
      
      serviceInfo.status = isHealthy ? 'healthy' : 'unhealthy';
      serviceInfo.lastCheck = new Date().toISOString();
      serviceInfo.responseTime = responseTime;
      serviceInfo.lastError = null;
      
      if (isHealthy) {
        serviceInfo.lastSuccess = serviceInfo.lastCheck;
        serviceInfo.consecutiveFailures = 0;
      } else {
        serviceInfo.consecutiveFailures++;
      }
      
      logger.debug(`Health check ${serviceName}: ${serviceInfo.status} (${responseTime}ms)`);
      
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      serviceInfo.status = 'unhealthy';
      serviceInfo.lastCheck = new Date().toISOString();
      serviceInfo.responseTime = responseTime;
      serviceInfo.lastError = error.message;
      serviceInfo.consecutiveFailures++;
      
      logger.warn(`Health check ${serviceName} failed: ${error.message}`);
    }
  }

  // Record service response (called from proxy)
  recordServiceResponse(serviceName, success) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    if (!serviceInfo) return;
    
    if (success) {
      serviceInfo.consecutiveFailures = 0;
      if (serviceInfo.status === 'unhealthy') {
        logger.info(`Service ${serviceName} appears to be recovering`);
      }
    } else {
      serviceInfo.consecutiveFailures++;
    }
  }

  // Get service status for a specific service
  getServiceHealth(serviceName) {
    return this.serviceStatus.get(serviceName) || null;
  }

  // Get all service statuses
  getServiceStatus() {
    const status = {};
    
    for (const [name, info] of this.serviceStatus.entries()) {
      status[name] = {
        name: info.name,
        url: info.url,
        status: info.status,
        lastCheck: info.lastCheck,
        lastSuccess: info.lastSuccess,
        consecutiveFailures: info.consecutiveFailures,
        responseTime: info.responseTime,
        error: info.lastError
      };
    }
    
    return status;
  }

  // Check if a service is healthy
  isServiceHealthy(serviceName) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    return serviceInfo && serviceInfo.status === 'healthy';
  }

  // Get overall health status
  getOverallHealth() {
    const services = Array.from(this.serviceStatus.values());
    const healthyServices = services.filter(s => s.status === 'healthy');
    const totalServices = services.length;
    
    return {
      healthy: healthyServices.length === totalServices,
      totalServices,
      healthyServices: healthyServices.length,
      unhealthyServices: totalServices - healthyServices.length,
      services: this.getServiceStatus()
    };
  }

  // Express middleware for service health check
  checkServices() {
    return async (req, res) => {
      const overallHealth = this.getOverallHealth();
      const isHealthy = overallHealth.healthy;
      
      res.status(isHealthy ? 200 : 503).json({
        status: isHealthy ? 'healthy' : 'degraded',
        service: 'gateway',
        timestamp: new Date().toISOString(),
        dependencies: overallHealth.services,
        summary: {
          totalServices: overallHealth.totalServices,
          healthyServices: overallHealth.healthyServices,
          unhealthyServices: overallHealth.unhealthyServices
        }
      });
    };
  }

  // Force health check for all services
  async forceHealthCheck() {
    logger.info('Forcing health check for all services');
    await this.checkAllServices();
    return this.getOverallHealth();
  }

  // Get health statistics
  getStats() {
    const services = Array.from(this.serviceStatus.values());
    const now = Date.now();
    
    return {
      totalServices: services.length,
      healthyServices: services.filter(s => s.status === 'healthy').length,
      unhealthyServices: services.filter(s => s.status === 'unhealthy').length,
      unknownServices: services.filter(s => s.status === 'unknown').length,
      averageResponseTime: this.calculateAverageResponseTime(),
      checkInterval: this.checkInterval,
      lastCheckTime: services.reduce((latest, service) => {
        const serviceTime = service.lastCheck ? new Date(service.lastCheck).getTime() : 0;
        return Math.max(latest, serviceTime);
      }, 0),
      nextCheckIn: this.getNextCheckTime()
    };
  }

  calculateAverageResponseTime() {
    const services = Array.from(this.serviceStatus.values());
    const responseTimes = services
      .filter(s => s.responseTime !== null)
      .map(s => s.responseTime);
    
    if (responseTimes.length === 0) return null;
    
    return Math.round(responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length);
  }

  getNextCheckTime() {
    // This is approximate since we don't track the exact interval start
    return this.checkInterval;
  }

  // Cleanup method
  cleanup() {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
    
    logger.info('Health check service cleaned up');
  }

  // Add a new service dynamically (for development)
  addService(serviceName, serviceUrl) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Dynamic service addition not allowed in production');
    }
    
    this.services[serviceName] = serviceUrl;
    this.serviceStatus.set(serviceName, {
      name: serviceName,
      url: serviceUrl,
      status: 'unknown',
      lastCheck: null,
      lastSuccess: null,
      lastError: null,
      consecutiveFailures: 0,
      responseTime: null
    });
    
    // Immediate health check for new service
    this.checkService(serviceName);
    
    logger.info(`Added service: ${serviceName} at ${serviceUrl}`);
  }

  // Remove a service (for development)
  removeService(serviceName) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Dynamic service removal not allowed in production');
    }
    
    delete this.services[serviceName];
    this.serviceStatus.delete(serviceName);
    
    logger.info(`Removed service: ${serviceName}`);
  }
}

module.exports = SimpleHealth;