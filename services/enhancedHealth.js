// gateway-service/services/enhancedHealth.js
const axios = require('axios');
const config = require('../config/simple');
const logger = require('../utils/simpleLogger');

class EnhancedHealth {
  constructor() {
    this.services = config.services;
    this.serviceStatus = new Map();
    this.syncVersions = new Map();
    this.checkInterval = config.monitoring.healthCheckInterval;
    this.syncCheckInterval = 5 * 60 * 1000; // 5 minutes for sync checks
    this.expectedSharedKnowledgeVersion = '1.0.0'; // Should come from config
    this.totalRequests = 0;
    this.lastSyncCheck = null;
    
    // Initialize service status
    this.initializeServiceStatus();
  }

  initialize() {
    this.startHealthChecks();
    this.startSyncMonitoring();
    logger.info('Enhanced health monitoring initialized');
  }

  initializeServiceStatus() {
    Object.keys(this.services).forEach(serviceName => {
      this.serviceStatus.set(serviceName, {
        name: serviceName,
        url: this.services[serviceName],
        status: 'unknown',
        lastCheck: null,
        lastSuccess: null,
        lastError: null,
        consecutiveFailures: 0,
        responseTime: null,
        avgResponseTime: null,
        requestCount: 0,
        errorCount: 0,
        lastResponseTimes: [], // Keep last 10 response times
        // Sync-related fields
        sharedKnowledgeVersion: null,
        lastSyncCheck: null,
        syncStatus: 'unknown',
        syncDelay: null
      });
      
      // Initialize sync version tracking
      this.syncVersions.set(serviceName, {
        version: null,
        lastUpdated: null,
        expectedVersion: this.expectedSharedKnowledgeVersion
      });
    });
  }

  startHealthChecks() {
    // Initial check
    this.checkAllServices();
    
    // Schedule periodic checks
    this.healthCheckTimer = setInterval(() => {
      this.checkAllServices();
    }, this.checkInterval);
    
    logger.info(`Health checks started with ${this.checkInterval}ms interval`);
  }

  startSyncMonitoring() {
    // Initial sync check
    this.checkAllServiceSync();
    
    // Schedule periodic sync checks
    this.syncCheckTimer = setInterval(() => {
      this.checkAllServiceSync();
    }, this.syncCheckInterval);
    
    logger.info(`Sync monitoring started with ${this.syncCheckInterval}ms interval`);
  }

  async checkAllServices() {
    const promises = Object.keys(this.services).map(serviceName =>
      this.checkService(serviceName)
    );
    
    await Promise.allSettled(promises);
  }

  async checkService(serviceName) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    const startTime = Date.now();
    
    try {
      const response = await axios.get(`${serviceInfo.url}/health`, {
        timeout: 5000,
        headers: {
          'User-Agent': 'Gateway-Health-Check/1.0',
          'X-Gateway-Request': 'true'
        }
      });
      
      const responseTime = Date.now() - startTime;
      const isHealthy = response.status === 200;
      
      // Update basic health info
      serviceInfo.status = isHealthy ? 'healthy' : 'unhealthy';
      serviceInfo.lastCheck = new Date().toISOString();
      serviceInfo.responseTime = responseTime;
      serviceInfo.lastError = null;
      serviceInfo.requestCount++;
      
      // Track response times for average calculation
      serviceInfo.lastResponseTimes.push(responseTime);
      if (serviceInfo.lastResponseTimes.length > 10) {
        serviceInfo.lastResponseTimes.shift();
      }
      serviceInfo.avgResponseTime = Math.round(
        serviceInfo.lastResponseTimes.reduce((sum, time) => sum + time, 0) / 
        serviceInfo.lastResponseTimes.length
      );
      
      if (isHealthy) {
        serviceInfo.lastSuccess = serviceInfo.lastCheck;
        serviceInfo.consecutiveFailures = 0;
        
        // Extract sync information from health response
        if (response.data && response.data.sharedKnowledgeVersion) {
          this.updateServiceSyncInfo(serviceName, response.data.sharedKnowledgeVersion);
        }
      } else {
        serviceInfo.consecutiveFailures++;
        serviceInfo.errorCount++;
      }
      
      logger.debug(`Health check ${serviceName}: ${serviceInfo.status} (${responseTime}ms)`);
      
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      serviceInfo.status = 'unhealthy';
      serviceInfo.lastCheck = new Date().toISOString();
      serviceInfo.responseTime = responseTime;
      serviceInfo.lastError = error.message;
      serviceInfo.consecutiveFailures++;
      serviceInfo.errorCount++;
      
      logger.warn(`Health check ${serviceName} failed: ${error.message}`);
    }
  }

  async checkAllServiceSync() {
    this.lastSyncCheck = new Date().toISOString();
    
    const promises = Object.keys(this.services).map(serviceName =>
      this.checkServiceSync(serviceName)
    );
    
    await Promise.allSettled(promises);
    
    logger.debug('Sync status check completed for all services');
  }

  async checkServiceSync(serviceName) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    
    try {
      // Try to get sync status from a dedicated endpoint
      const response = await axios.get(`${serviceInfo.url}/api/shared-knowledge/status`, {
        timeout: 3000,
        headers: {
          'User-Agent': 'Gateway-Sync-Check/1.0',
          'X-Gateway-Request': 'true'
        }
      });
      
      if (response.status === 200 && response.data) {
        const syncData = response.data;
        this.updateServiceSyncInfo(serviceName, syncData.version, syncData);
      }
      
    } catch (error) {
      // If dedicated sync endpoint doesn't exist, mark as unknown
      serviceInfo.syncStatus = 'unknown';
      serviceInfo.lastSyncCheck = new Date().toISOString();
      
      logger.debug(`Sync check ${serviceName}: endpoint not available`);
    }
  }

  updateServiceSyncInfo(serviceName, version, additionalData = {}) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    const syncInfo = this.syncVersions.get(serviceName);
    
    if (serviceInfo && syncInfo) {
      const now = new Date().toISOString();
      
      // Update service info
      serviceInfo.sharedKnowledgeVersion = version;
      serviceInfo.lastSyncCheck = now;
      
      // Determine sync status
      const isInSync = version === this.expectedSharedKnowledgeVersion;
      serviceInfo.syncStatus = isInSync ? 'in-sync' : 'out-of-sync';
      
      if (!isInSync) {
        const versionDate = additionalData.lastUpdated ? new Date(additionalData.lastUpdated) : new Date();
        const delayMs = Date.now() - versionDate.getTime();
        serviceInfo.syncDelay = Math.floor(delayMs / (1000 * 60)); // minutes
      } else {
        serviceInfo.syncDelay = 0;
      }
      
      // Update sync version info
      syncInfo.version = version;
      syncInfo.lastUpdated = now;
      
      logger.debug(`Sync info updated for ${serviceName}: ${version} (${serviceInfo.syncStatus})`);
    }
  }

  recordServiceResponse(serviceName, success, responseTime = null) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    if (!serviceInfo) return;
    
    this.totalRequests++;
    serviceInfo.requestCount++;
    
    if (responseTime) {
      serviceInfo.responseTime = responseTime;
      serviceInfo.lastResponseTimes.push(responseTime);
      if (serviceInfo.lastResponseTimes.length > 10) {
        serviceInfo.lastResponseTimes.shift();
      }
      serviceInfo.avgResponseTime = Math.round(
        serviceInfo.lastResponseTimes.reduce((sum, time) => sum + time, 0) / 
        serviceInfo.lastResponseTimes.length
      );
    }
    
    if (success) {
      serviceInfo.consecutiveFailures = 0;
      if (serviceInfo.status === 'unhealthy') {
        logger.info(`Service ${serviceName} appears to be recovering`);
      }
    } else {
      serviceInfo.consecutiveFailures++;
      serviceInfo.errorCount++;
    }
  }

  recordServiceSyncVersion(serviceName, version) {
    if (version) {
      this.updateServiceSyncInfo(serviceName, version);
    }
  }

  // Express middleware for comprehensive health check
  checkServices() {
    return async (req, res) => {
      const overallHealth = this.getOverallHealth();
      const syncStatus = this.getSyncStatus();
      const isHealthy = overallHealth.healthy && syncStatus.allInSync;
      
      res.status(isHealthy ? 200 : 503).json({
        status: isHealthy ? 'healthy' : 'degraded',
        service: 'gateway',
        timestamp: new Date().toISOString(),
        dependencies: overallHealth.services,
        synchronization: {
          status: syncStatus.status,
          lastCheck: syncStatus.lastCheck,
          outOfSyncServices: syncStatus.outOfSyncCount
        },
        summary: {
          totalServices: overallHealth.totalServices,
          healthyServices: overallHealth.healthyServices,
          unhealthyServices: overallHealth.unhealthyServices,
          inSyncServices: syncStatus.inSyncCount,
          outOfSyncServices: syncStatus.outOfSyncCount
        }
      });
    };
  }

  // New endpoint for detailed sync status
  checkSyncStatus() {
    return (req, res) => {
      const syncStatus = this.getSyncStatus();
      
      res.json({
        success: true,
        data: {
          overallStatus: syncStatus.status,
          lastGlobalCheck: syncStatus.lastCheck,
          expectedVersion: this.expectedSharedKnowledgeVersion,
          services: syncStatus.services.map(service => ({
            name: service.name,
            currentVersion: service.version,
            expectedVersion: this.expectedSharedKnowledgeVersion,
            status: service.syncStatus,
            lastCheck: service.lastSyncCheck,
            delayMinutes: service.syncDelay,
            recommendation: this.getSyncRecommendation(service)
          }))
        },
        metadata: {
          timestamp: new Date().toISOString(),
          service: 'gateway'
        }
      });
    };
  }

  getSyncStatus() {
    const services = Array.from(this.serviceStatus.values());
    const inSyncServices = services.filter(s => s.syncStatus === 'in-sync');
    const outOfSyncServices = services.filter(s => s.syncStatus === 'out-of-sync');
    const unknownSyncServices = services.filter(s => s.syncStatus === 'unknown');
    
    let overallStatus = 'healthy';
    if (outOfSyncServices.length > 0) {
      overallStatus = 'degraded';
    } else if (unknownSyncServices.length > 0) {
      overallStatus = 'unknown';
    }
    
    return {
      status: overallStatus,
      allInSync: outOfSyncServices.length === 0 && unknownSyncServices.length === 0,
      lastCheck: this.lastSyncCheck,
      inSyncCount: inSyncServices.length,
      outOfSyncCount: outOfSyncServices.length,
      unknownCount: unknownSyncServices.length,
      services: services.map(s => ({
        name: s.name,
        version: s.sharedKnowledgeVersion,
        syncStatus: s.syncStatus,
        lastSyncCheck: s.lastSyncCheck,
        syncDelay: s.syncDelay
      }))
    };
  }

  getSyncRecommendation(service) {
    if (service.syncStatus === 'out-of-sync') {
      if (service.syncDelay > 60) { // More than 1 hour
        return 'URGENT: Service is significantly out of sync. Immediate update required.';
      } else if (service.syncDelay > 30) { // More than 30 minutes
        return 'WARNING: Service should be updated soon.';
      } else {
        return 'Service is slightly behind. Update when convenient.';
      }
    } else if (service.syncStatus === 'unknown') {
      return 'Cannot determine sync status. Check service health and sync endpoint.';
    } else {
      return 'Service is properly synchronized.';
    }
  }

  getSyncRecommendations() {
    const services = Array.from(this.serviceStatus.values());
    const recommendations = [];
    
    services.forEach(service => {
      if (service.syncStatus !== 'in-sync') {
        recommendations.push({
          service: service.name,
          status: service.syncStatus,
          recommendation: this.getSyncRecommendation(service),
          priority: service.syncDelay > 60 ? 'high' : 
                   service.syncDelay > 30 ? 'medium' : 'low'
        });
      }
    });
    
    return recommendations;
  }

  async forceSyncCheck() {
    logger.info('Force sync check initiated');
    
    await this.checkAllServiceSync();
    
    const syncStatus = this.getSyncStatus();
    const recommendations = this.getSyncRecommendations();
    
    return {
      syncStatus,
      recommendations,
      nextScheduledCheck: new Date(Date.now() + this.syncCheckInterval).toISOString()
    };
  }

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
        avgResponseTime: info.avgResponseTime,
        requestCount: info.requestCount,
        errorCount: info.errorCount,
        errorRate: info.requestCount > 0 ? 
          Math.round((info.errorCount / info.requestCount) * 100) : 0,
        error: info.lastError,
        // Sync information
        sharedKnowledgeVersion: info.sharedKnowledgeVersion,
        syncStatus: info.syncStatus,
        lastSyncCheck: info.lastSyncCheck,
        syncDelay: info.syncDelay
      };
    }
    
    return status;
  }

  getStats() {
    const services = Array.from(this.serviceStatus.values());
    const syncStatus = this.getSyncStatus();
    
    return {
      totalServices: services.length,
      healthyServices: services.filter(s => s.status === 'healthy').length,
      unhealthyServices: services.filter(s => s.status === 'unhealthy').length,
      unknownServices: services.filter(s => s.status === 'unknown').length,
      totalRequests: this.totalRequests,
      averageResponseTime: this.calculateAverageResponseTime(),
      checkInterval: this.checkInterval,
      syncCheckInterval: this.syncCheckInterval,
      lastHealthCheck: this.getLastCheckTime(),
      lastSyncCheck: this.lastSyncCheck,
      synchronization: {
        inSyncServices: syncStatus.inSyncCount,
        outOfSyncServices: syncStatus.outOfSyncCount,
        unknownSyncServices: syncStatus.unknownCount,
        overallSyncStatus: syncStatus.status
      }
    };
  }

  calculateAverageResponseTime() {
    const services = Array.from(this.serviceStatus.values());
    const avgTimes = services
      .filter(s => s.avgResponseTime !== null)
      .map(s => s.avgResponseTime);
    
    if (avgTimes.length === 0) return null;
    
    return Math.round(avgTimes.reduce((sum, time) => sum + time, 0) / avgTimes.length);
  }

  getLastCheckTime() {
    const services = Array.from(this.serviceStatus.values());
    return services.reduce((latest, service) => {
      const serviceTime = service.lastCheck ? new Date(service.lastCheck).getTime() : 0;
      return Math.max(latest, serviceTime);
    }, 0);
  }

  isServiceHealthy(serviceName) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    return serviceInfo && serviceInfo.status === 'healthy';
  }

  isServiceInSync(serviceName) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    return serviceInfo && serviceInfo.syncStatus === 'in-sync';
  }

  async cleanup() {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
    
    if (this.syncCheckTimer) {
      clearInterval(this.syncCheckTimer);
      this.syncCheckTimer = null;
    }
    
    logger.info('Enhanced health service cleaned up');
  }

  // Development-only methods
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
      responseTime: null,
      avgResponseTime: null,
      requestCount: 0,
      errorCount: 0,
      lastResponseTimes: [],
      sharedKnowledgeVersion: null,
      lastSyncCheck: null,
      syncStatus: 'unknown',
      syncDelay: null
    });
    
    this.syncVersions.set(serviceName, {
      version: null,
      lastUpdated: null,
      expectedVersion: this.expectedSharedKnowledgeVersion
    });
    
    // Immediate checks for new service
    this.checkService(serviceName);
    setTimeout(() => this.checkServiceSync(serviceName), 2000);
    
    logger.info(`Added service: ${serviceName} at ${serviceUrl}`);
  }

  removeService(serviceName) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Dynamic service removal not allowed in production');
    }
    
    delete this.services[serviceName];
    this.serviceStatus.delete(serviceName);
    this.syncVersions.delete(serviceName);
    
    logger.info(`Removed service: ${serviceName}`);
  }

  // Update expected shared knowledge version
  updateExpectedVersion(version) {
    this.expectedSharedKnowledgeVersion = version;
    
    // Update all sync version expectations
    for (const [serviceName, syncInfo] of this.syncVersions.entries()) {
      syncInfo.expectedVersion = version;
    }
    
    // Trigger immediate sync check
    this.checkAllServiceSync();
    
    logger.info(`Updated expected shared knowledge version to: ${version}`);
  }
}

module.exports = EnhancedHealth;