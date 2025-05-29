// gateway-service/services/serviceOrchestrator.js
const axios = require('axios');
const config = require('../config/simple');
const logger = require('../utils/simpleLogger');

class ServiceOrchestrator {
  constructor() {
    this.services = config.services;
    this.timeout = 10000; // 10 seconds for orchestrated calls
    this.cache = new Map();
    this.cacheExpiry = 5 * 60 * 1000; // 5 minutes
    this.stats = {
      orchestratedRequests: 0,
      cacheHits: 0,
      cacheMisses: 0,
      successfulOrchestrations: 0,
      failedOrchestrations: 0,
      avgOrchestrationTime: 0
    };
    
    // Cleanup cache periodically
    this.cacheCleanupTimer = setInterval(() => {
      this.cleanupCache();
    }, 60000); // Every minute
  }

  initialize() {
    logger.info('Service orchestrator initialized');
  }

  // Create authenticated HTTP client for service calls
  createServiceClient(serviceName, requestId) {
    return axios.create({
      baseURL: this.services[serviceName],
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Request': 'true',
        'X-Gateway-Version': '1.0.0',
        'X-Request-ID': requestId,
        'X-Service-Name': 'gateway',
        'User-Agent': 'Gateway-Orchestrator/1.0'
      }
    });
  }

  // Cache management
  getCacheKey(serviceName, endpoint, params = {}) {
    const paramString = Object.keys(params).length > 0 ? 
      JSON.stringify(params) : '';
    return `${serviceName}:${endpoint}:${paramString}`;
  }

  getFromCache(key) {
    const cached = this.cache.get(key);
    if (cached && cached.expiry > Date.now()) {
      this.stats.cacheHits++;
      return cached.data;
    }
    
    if (cached) {
      this.cache.delete(key); // Remove expired entry
    }
    
    this.stats.cacheMisses++;
    return null;
  }

  setCache(key, data, ttl = this.cacheExpiry) {
    this.cache.set(key, {
      data,
      expiry: Date.now() + ttl
    });
  }

  cleanupCache() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [key, value] of this.cache.entries()) {
      if (value.expiry <= now) {
        this.cache.delete(key);
        cleaned++;
      }
    }
    
    if (cleaned > 0) {
      logger.debug(`Cleaned ${cleaned} expired cache entries`);
    }
  }

  // Orchestrated endpoints
  async getUserDashboard(userId, requestId) {
    const startTime = Date.now();
    this.stats.orchestratedRequests++;
    
    try {
      logger.info(`Orchestrating user dashboard for ${userId}`, { requestId });
      
      // Check cache first
      const cacheKey = this.getCacheKey('dashboard', userId);
      const cached = this.getFromCache(cacheKey);
      if (cached) {
        logger.debug(`Dashboard cache hit for user ${userId}`);
        return cached;
      }
      
      // Parallel service calls for better performance
      const [userResult, industriesResult, recentJobsResult] = await Promise.allSettled([
        this.getUserProfile(userId, requestId),
        this.getUserIndustries(userId, requestId), 
        this.getUserRecentJobs(userId, requestId)
      ]);
      
      // Build dashboard response
      const dashboard = {
        user: userResult.status === 'fulfilled' ? userResult.value : null,
        industries: industriesResult.status === 'fulfilled' ? industriesResult.value : [],
        recentJobs: recentJobsResult.status === 'fulfilled' ? recentJobsResult.value : [],
        metadata: {
          generatedAt: new Date().toISOString(),
          requestId,
          cacheEnabled: true,
          services: {
            auth: userResult.status,
            industry: industriesResult.status,
            comment: recentJobsResult.status
          }
        }
      };
      
      // Only cache if we got at least user data
      if (dashboard.user) {
        this.setCache(cacheKey, dashboard, 2 * 60 * 1000); // 2 minute cache for dashboard
      }
      
      const orchestrationTime = Date.now() - startTime;
      this.updateOrchestrationStats(true, orchestrationTime);
      
      logger.info(`Dashboard orchestration completed for ${userId} in ${orchestrationTime}ms`);
      return dashboard;
      
    } catch (error) {
      const orchestrationTime = Date.now() - startTime;
      this.updateOrchestrationStats(false, orchestrationTime);
      
      logger.error(`Dashboard orchestration failed for ${userId}`, {
        requestId,
        error: error.message,
        duration: orchestrationTime
      }, error);
      
      throw error;
    }
  }

  async getUserProfile(userId, requestId) {
    const cacheKey = this.getCacheKey('auth', `user/${userId}`);
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;
    
    try {
      const client = this.createServiceClient('auth', requestId);
      const response = await client.get(`/api/auth/profile/${userId}`);
      
      if (response.status === 200 && response.data.success) {
        const userData = response.data.data;
        this.setCache(cacheKey, userData, 10 * 60 * 1000); // 10 minute cache for user data
        return userData;
      }
      
      throw new Error('Invalid user profile response');
      
    } catch (error) {
      logger.warn(`Failed to get user profile for ${userId}`, {
        requestId,
        error: error.message
      });
      
      // Return null to allow graceful degradation
      return null;
    }
  }

  async getUserIndustries(userId, requestId) {
    const cacheKey = this.getCacheKey('industry', `user/${userId}/industries`);
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;
    
    try {
      const client = this.createServiceClient('industry', requestId);
      const response = await client.get(`/api/industries/user/${userId}`);
      
      if (response.status === 200 && response.data.success) {
        const industries = response.data.data;
        this.setCache(cacheKey, industries, 15 * 60 * 1000); // 15 minute cache for industries
        return industries;
      }
      
      return [];
      
    } catch (error) {
      logger.warn(`Failed to get user industries for ${userId}`, {
        requestId,
        error: error.message
      });
      
      return [];
    }
  }

  async getUserRecentJobs(userId, requestId, limit = 5) {
    const cacheKey = this.getCacheKey('comment', `user/${userId}/jobs`, { limit });
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;
    
    try {
      const client = this.createServiceClient('comment', requestId);
      const response = await client.get(`/api/comments/user/${userId}/jobs`, {
        params: { limit, sort: 'desc' }
      });
      
      if (response.status === 200 && response.data.success) {
        const jobs = response.data.data;
        this.setCache(cacheKey, jobs, 2 * 60 * 1000); // 2 minute cache for recent jobs
        return jobs;
      }
      
      return [];
      
    } catch (error) {
      logger.warn(`Failed to get user recent jobs for ${userId}`, {
        requestId,
        error: error.message
      });
      
      return [];
    }
  }

  // Cross-service operations that require coordination
  async updateUserIndustries(userId, industryIds, requestId) {
    const startTime = Date.now();
    this.stats.orchestratedRequests++;
    
    try {
      logger.info(`Orchestrating industry update for user ${userId}`, {
        requestId,
        industries: industryIds
      });
      
      // Step 1: Validate industries exist
      const validIndustries = await this.validateIndustries(industryIds, requestId);
      if (validIndustries.length !== industryIds.length) {
        throw new Error('Some industries are invalid or do not exist');
      }
      
      // Step 2: Update user profile with new industries
      const updatedUser = await this.updateUserProfile(userId, {
        industries: industryIds
      }, requestId);
      
      // Step 3: Create/update industry classifications for user
      await this.createUserIndustryClassifications(userId, industryIds, requestId);
      
      // Step 4: Invalidate relevant caches
      this.invalidateUserCaches(userId);
      
      const orchestrationTime = Date.now() - startTime;
      this.updateOrchestrationStats(true, orchestrationTime);
      
      logger.info(`Industry update orchestration completed for ${userId} in ${orchestrationTime}ms`);
      
      return {
        user: updatedUser,
        industries: validIndustries,
        metadata: {
          updatedAt: new Date().toISOString(),
          requestId,
          orchestrationTime
        }
      };
      
    } catch (error) {
      const orchestrationTime = Date.now() - startTime;
      this.updateOrchestrationStats(false, orchestrationTime);
      
      logger.error(`Industry update orchestration failed for ${userId}`, {
        requestId,
        error: error.message,
        duration: orchestrationTime
      }, error);
      
      throw error;
    }
  }

  async validateIndustries(industryIds, requestId) {
    try {
      const client = this.createServiceClient('industry', requestId);
      const response = await client.post('/api/industries/validate', {
        ids: industryIds
      });
      
      if (response.status === 200 && response.data.success) {
        return response.data.data;
      }
      
      return [];
      
    } catch (error) {
      logger.error('Failed to validate industries', {
        requestId,
        industries: industryIds,
        error: error.message
      });
      throw error;
    }
  }

  async updateUserProfile(userId, updates, requestId) {
    try {
      const client = this.createServiceClient('auth', requestId);
      const response = await client.put(`/api/auth/profile/${userId}`, updates);
      
      if (response.status === 200 && response.data.success) {
        return response.data.data;
      }
      
      throw new Error('Failed to update user profile');
      
    } catch (error) {
      logger.error(`Failed to update user profile for ${userId}`, {
        requestId,
        updates,
        error: error.message
      });
      throw error;
    }
  }

  async createUserIndustryClassifications(userId, industryIds, requestId) {
    try {
      const client = this.createServiceClient('industry', requestId);
      const response = await client.post('/api/industries/user-classifications', {
        userId,
        industryIds
      });
      
      if (response.status === 200 || response.status === 201) {
        return response.data.data;
      }
      
      // Don't throw error here as this is not critical
      logger.warn('Failed to create user industry classifications', {
        requestId,
        userId,
        industryIds
      });
      
    } catch (error) {
      logger.warn('Failed to create user industry classifications', {
        requestId,
        userId,
        industryIds,
        error: error.message
      });
      // Don't throw - this is not critical for the main operation
    }
  }

  // Health check orchestration
  async performHealthOrchestration(requestId) {
    try {
      const healthChecks = await Promise.allSettled([
        this.checkServiceHealth('auth', requestId),
        this.checkServiceHealth('comment', requestId),
        this.checkServiceHealth('industry', requestId),
        this.checkServiceHealth('nps', requestId)
      ]);
      
      const results = {};
      const services = ['auth', 'comment', 'industry', 'nps'];
      
      healthChecks.forEach((result, index) => {
        const serviceName = services[index];
        results[serviceName] = {
          status: result.status === 'fulfilled' ? 'healthy' : 'unhealthy',
          ...(result.status === 'fulfilled' ? result.value : { error: result.reason.message })
        };
      });
      
      return results;
      
    } catch (error) {
      logger.error('Health orchestration failed', { requestId }, error);
      throw error;
    }
  }

  async checkServiceHealth(serviceName, requestId) {
    const client = this.createServiceClient(serviceName, requestId);
    const response = await client.get('/health');
    return response.data;
  }

  // Cache management helpers
  invalidateUserCaches(userId) {
    const keysToDelete = [];
    
    for (const [key] of this.cache.entries()) {
      if (key.includes(`user/${userId}`) || key.includes(`dashboard:${userId}`)) {
        keysToDelete.push(key);
      }
    }
    
    keysToDelete.forEach(key => this.cache.delete(key));
    
    logger.debug(`Invalidated ${keysToDelete.length} cache entries for user ${userId}`);
  }

  clearAllCache() {
    const size = this.cache.size;
    this.cache.clear();
    logger.info(`Cleared all orchestrator cache (${size} entries)`);
  }

  // Statistics and monitoring
  updateOrchestrationStats(success, duration) {
    if (success) {
      this.stats.successfulOrchestrations++;
    } else {
      this.stats.failedOrchestrations++;
    }
    
    // Update average orchestration time
    const totalOrchestrations = this.stats.successfulOrchestrations + this.stats.failedOrchestrations;
    this.stats.avgOrchestrationTime = Math.round(
      (this.stats.avgOrchestrationTime * (totalOrchestrations - 1) + duration) / totalOrchestrations
    );
  }

  getStats() {
    const cacheSize = this.cache.size;
    const cacheHitRate = this.stats.cacheHits + this.stats.cacheMisses > 0 ?
      Math.round((this.stats.cacheHits / (this.stats.cacheHits + this.stats.cacheMisses)) * 100) : 0;
    
    return {
      ...this.stats,
      cacheSize,
      cacheHitRate,
      services: Object.keys(this.services),
      timeout: this.timeout,
      cacheExpiry: this.cacheExpiry
    };
  }

  // Configuration methods
  setTimeout(timeout) {
    this.timeout = timeout;
    logger.info(`Orchestrator timeout updated to ${timeout}ms`);
  }

  setCacheExpiry(expiry) {
    this.cacheExpiry = expiry;
    logger.info(`Orchestrator cache expiry updated to ${expiry}ms`);
  }

  // Cleanup
  async cleanup() {
    if (this.cacheCleanupTimer) {
      clearInterval(this.cacheCleanupTimer);
      this.cacheCleanupTimer = null;
    }
    
    this.clearAllCache();
    
    logger.info('Service orchestrator cleaned up');
  }

  // Development helpers
  async testServiceCommunication(requestId) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Test methods not available in production');
    }
    
    const results = {};
    
    for (const [serviceName, serviceUrl] of Object.entries(this.services)) {
      try {
        const client = this.createServiceClient(serviceName, requestId);
        const start = Date.now();
        const response = await client.get('/health');
        const duration = Date.now() - start;
        
        results[serviceName] = {
          status: 'success',
          url: serviceUrl,
          responseTime: duration,
          version: response.data.version || 'unknown'
        };
        
      } catch (error) {
        results[serviceName] = {
          status: 'error',
          url: serviceUrl,
          error: error.message
        };
      }
    }
    
    return results;
  }
}

module.exports = ServiceOrchestrator;