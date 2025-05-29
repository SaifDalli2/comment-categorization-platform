// gateway-service/src/services/ServiceRegistry.js
const axios = require('axios');
const logger = require('../../utils/simpleLogger');

class BaseServiceClient {
  constructor(baseUrl, serviceName, options = {}) {
    this.baseUrl = baseUrl;
    this.serviceName = serviceName;
    this.timeout = options.timeout || 30000;
    this.retryAttempts = options.retryAttempts || 3;
    this.retryDelay = options.retryDelay || 1000;
    
    this.client = axios.create({
      baseURL: this.baseUrl,
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Gateway-Service-Client/1.0'
      }
    });

    this.setupInterceptors();
  }

  setupInterceptors() {
    this.client.interceptors.request.use(
      (config) => {
        config.headers['X-Request-ID'] = this.generateRequestId();
        config.headers['X-Service-Name'] = 'gateway';
        config.metadata = { startTime: Date.now() };
        return config;
      }
    );

    this.client.interceptors.response.use(
      (response) => {
        const duration = Date.now() - response.config.metadata.startTime;
        logger.debug(`${this.serviceName} response: ${response.status} (${duration}ms)`);
        return response;
      },
      async (error) => {
        if (this.shouldRetry(error) && !error.config._retry) {
          error.config._retry = true;
          error.config._retryCount = (error.config._retryCount || 0) + 1;

          if (error.config._retryCount <= this.retryAttempts) {
            await this.delay(this.retryDelay * error.config._retryCount);
            return this.client.request(error.config);
          }
        }
        return Promise.reject(this.normalizeError(error));
      }
    );
  }

  shouldRetry(error) {
    return (
      !error.response || 
      error.response.status >= 500 || 
      error.code === 'ECONNRESET' ||
      error.code === 'ETIMEDOUT'
    );
  }

  normalizeError(error) {
    if (error.response) {
      return {
        code: error.response.data?.error?.code || 'SERVICE_ERROR',
        message: error.response.data?.error?.message || error.message,
        status: error.response.status,
        service: this.serviceName
      };
    } else if (error.request) {
      return {
        code: 'SERVICE_UNAVAILABLE',
        message: `${this.serviceName} service is unavailable`,
        status: 503,
        service: this.serviceName
      };
    } else {
      return {
        code: 'REQUEST_ERROR',
        message: error.message,
        status: 500,
        service: this.serviceName
      };
    }
  }

  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async get(endpoint, params = {}, headers = {}) {
    const response = await this.client.get(endpoint, { params, headers });
    return response.data;
  }

  async post(endpoint, data = {}, headers = {}) {
    const response = await this.client.post(endpoint, data, { headers });
    return response.data;
  }

  async put(endpoint, data = {}, headers = {}) {
    const response = await this.client.put(endpoint, data, { headers });
    return response.data;
  }

  async delete(endpoint, headers = {}) {
    const response = await this.client.delete(endpoint, { headers });
    return response.data;
  }

  async healthCheck() {
    try {
      const response = await this.client.get('/health', { timeout: 5000 });
      return {
        healthy: response.status === 200,
        status: response.status,
        responseTime: Date.now() - response.config.metadata.startTime
      };
    } catch (error) {
      return {
        healthy: false,
        error: error.message,
        status: error.response?.status || 0
      };
    }
  }
}

class AuthServiceClient extends BaseServiceClient {
  constructor() {
    super(
      process.env.AUTH_SERVICE_URL || 'https://auth-service-voice-0add8d339257.herokuapp.com',
      'auth-service'
    );
  }

  async verifyToken(token) {
    return this.post('/api/auth/verify', {}, {
      'Authorization': `Bearer ${token}`
    });
  }

  async getUser(userId) {
    return this.get(`/api/users/${userId}`);
  }
}

class CommentServiceClient extends BaseServiceClient {
  constructor() {
    super(
      process.env.COMMENT_SERVICE_URL || 'https://your-comment-service.herokuapp.com',
      'comment-service'
    );
  }

  async categorizeComments(data, userHeaders = {}) {
    return this.post('/api/comments/categorize', data, userHeaders);
  }

  async getJobStatus(jobId, userHeaders = {}) {
    return this.get(`/api/comments/job/${jobId}/status`, {}, userHeaders);
  }
}

class IndustryServiceClient extends BaseServiceClient {
  constructor() {
    super(
      process.env.INDUSTRY_SERVICE_URL || 'https://your-industry-service.herokuapp.com',
      'industry-service'
    );
  }

  async getIndustries() {
    return this.get('/api/industries');
  }

  async getIndustryCategories(industry) {
    return this.get(`/api/industries/${encodeURIComponent(industry)}/categories`);
  }
}

class NPSServiceClient extends BaseServiceClient {
  constructor() {
    super(
      process.env.NPS_SERVICE_URL || 'https://your-nps-service.herokuapp.com',
      'nps-service'
    );
  }

  async getNPSDashboard(userId, params = {}) {
    return this.get(`/api/nps/dashboard/${userId}`, params);
  }
}

class ServiceRegistry {
  constructor() {
    this.services = new Map();
    this.initializeServices();
  }

  initializeServices() {
    this.services.set('auth', new AuthServiceClient());
    this.services.set('comment', new CommentServiceClient());
    this.services.set('industry', new IndustryServiceClient());
    this.services.set('nps', new NPSServiceClient());
    
    logger.info('Enhanced service registry initialized');
  }

  get(serviceName) {
    return this.services.get(serviceName);
  }

  async healthCheckAll() {
    const results = {};
    
    for (const [name, client] of this.services.entries()) {
      try {
        results[name] = await client.healthCheck();
      } catch (error) {
        results[name] = {
          healthy: false,
          error: error.message
        };
      }
    }
    
    return results;
  }

  getServiceNames() {
    return Array.from(this.services.keys());
  }
}

class EnhancedAuth {
  constructor(serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
    this.tokenCache = new Map();
    this.cacheExpiry = 5 * 60 * 1000; // 5 minutes
    
    // Import existing auth for fallback
    const SimpleAuth = require('../../middleware/simpleAuth');
    this.simpleAuth = new SimpleAuth();
  }

  optionalAuth() {
    if (process.env.USE_ENHANCED_AUTH === 'true') {
      return (req, res, next) => {
        // Enhanced optional auth logic would go here
        // For now, use existing implementation
        this.simpleAuth.optionalAuth()(req, res, next);
      };
    } else {
      return this.simpleAuth.optionalAuth();
    }
  }

  requireAuth() {
    if (process.env.USE_ENHANCED_AUTH === 'true') {
      return (req, res, next) => {
        // Enhanced auth logic would go here
        // For now, use existing implementation
        this.simpleAuth.requireAuth()(req, res, next);
      };
    } else {
      return this.simpleAuth.requireAuth();
    }
  }

  getStats() {
    return {
      cachedTokens: this.tokenCache.size,
      cacheExpiryMs: this.cacheExpiry,
      enhancedMode: process.env.USE_ENHANCED_AUTH === 'true'
    };
  }
}

module.exports = {
  BaseServiceClient,
  AuthServiceClient,
  CommentServiceClient,
  IndustryServiceClient,
  NPSServiceClient,
  ServiceRegistry,
  EnhancedAuth
};
