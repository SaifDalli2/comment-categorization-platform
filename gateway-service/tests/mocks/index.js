// gateway-service/tests/mocks/index.js
const jwt = require('jsonwebtoken');

// Mock service responses
const mockServiceResponses = {
  auth: {
    '/health': {
      status: 200,
      data: { status: 'healthy', service: 'auth' }
    },
    '/api/auth/login': {
      status: 200,
      data: {
        success: true,
        data: {
          token: 'mock-jwt-token',
          user: { id: 'test-user', email: 'test@example.com' }
        }
      }
    },
    '/api/auth/verify': {
      status: 200,
      data: {
        success: true,
        data: { valid: true, user: { id: 'test-user' } }
      }
    }
  },
  comment: {
    '/health': {
      status: 200,
      data: { status: 'healthy', service: 'comment' }
    },
    '/api/comments/categorize': {
      status: 200,
      data: {
        success: true,
        data: { jobId: 'job-123', status: 'queued' }
      }
    }
  },
  industry: {
    '/health': {
      status: 200,
      data: { status: 'healthy', service: 'industry' }
    },
    '/api/industries': {
      status: 200,
      data: {
        success: true,
        data: { industries: ['SaaS/Technology', 'Healthcare'] }
      }
    }
  },
  nps: {
    '/health': {
      status: 200,
      data: { status: 'healthy', service: 'nps' }
    },
    '/api/nps/dashboard/test-user': {
      status: 200,
      data: {
        success: true,
        data: { npsScore: 45, totalResponses: 1000 }
      }
    }
  }
};

// Mock axios for service requests
const mockAxios = {
  get: jest.fn((url, config) => {
    // Extract service name and path from URL
    const urlMatch = url.match(/http:\/\/localhost:(\d+)(\/.*)/);
    if (!urlMatch) {
      return Promise.reject(new Error('Invalid URL'));
    }

    const port = urlMatch[1];
    const path = urlMatch[2];
    
    // Map ports to services
    const serviceMap = {
      '3001': 'auth',
      '3002': 'comment', 
      '3003': 'industry',
      '3004': 'nps'
    };
    
    const serviceName = serviceMap[port];
    if (!serviceName) {
      return Promise.reject(new Error('Unknown service'));
    }
    
    const response = mockServiceResponses[serviceName][path];
    if (!response) {
      return Promise.reject(new Error('Not found'));
    }
    
    return Promise.resolve(response);
  }),

  post: jest.fn((url, data, config) => {
    const urlMatch = url.match(/http:\/\/localhost:(\d+)(\/.*)/);
    if (!urlMatch) {
      return Promise.reject(new Error('Invalid URL'));
    }

    const port = urlMatch[1];
    const path = urlMatch[2];
    const serviceMap = { '3001': 'auth', '3002': 'comment', '3003': 'industry', '3004': 'nps' };
    const serviceName = serviceMap[port];
    
    if (!serviceName) {
      return Promise.reject(new Error('Unknown service'));
    }
    
    const response = mockServiceResponses[serviceName][path];
    if (!response) {
      return Promise.reject(new Error('Not found'));
    }
    
    return Promise.resolve(response);
  })
};

// Mock service registry
const mockServiceRegistry = {
  services: new Map([
    ['auth', {
      name: 'auth',
      instances: [{
        id: 'auth-0',
        url: 'http://localhost:3001',
        status: 'healthy',
        circuitBreakerState: 'closed'
      }],
      lastUsedIndex: 0
    }],
    ['comment', {
      name: 'comment',
      instances: [{
        id: 'comment-0',
        url: 'http://localhost:3002',
        status: 'healthy',
        circuitBreakerState: 'closed'
      }],
      lastUsedIndex: 0
    }]
  ]),

  getService: jest.fn((serviceName) => {
    const service = mockServiceRegistry.services.get(serviceName);
    if (!service) return null;
    
    const healthyInstance = service.instances.find(
      i => i.status === 'healthy' && i.circuitBreakerState !== 'open'
    );
    
    return healthyInstance;
  }),

  getAllServices: jest.fn(() => {
    const result = {};
    for (const [name, service] of mockServiceRegistry.services.entries()) {
      result[name] = {
        name,
        totalInstances: service.instances.length,
        healthyInstances: service.instances.filter(i => i.status === 'healthy').length,
        instances: service.instances
      };
    }
    return result;
  }),

  getStats: jest.fn(() => ({
    totalServices: mockServiceRegistry.services.size,
    totalInstances: 4,
    healthyInstances: 4,
    unhealthyInstances: 0,
    openCircuitBreakers: 0,
    halfOpenCircuitBreakers: 0
  })),

  recordRequest: jest.fn(),
  performHealthChecks: jest.fn(),
  shutdown: jest.fn(),
  on: jest.fn(),
  emit: jest.fn()
};

// Mock logger
const mockLogger = {
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  log: jest.fn(),
  httpRequest: jest.fn(),
  serviceProxy: jest.fn(),
  healthCheck: jest.fn(),
  authentication: jest.fn(),
  security: jest.fn(),
  performance: jest.fn(),
  businessMetric: jest.fn(),
  startTimer: jest.fn(),
  endTimer: jest.fn(),
  middleware: jest.fn(() => (req, res, next) => next()),
  getConfig: jest.fn(() => ({
    serviceName: 'gateway',
    logLevel: 'info',
    uptime: 123
  })),
  cleanup: jest.fn()
};

// Mock metrics
const mockMetrics = {
  recordHttpRequest: jest.fn(),
  recordServiceRequest: jest.fn(),
  recordServiceHealth: jest.fn(),
  recordAuthRequest: jest.fn(),
  recordAuthCacheHit: jest.fn(),
  recordAuthCacheMiss: jest.fn(),
  recordRateLimit: jest.fn(),
  recordCorsRequest: jest.fn(),
  recordCorsPreflight: jest.fn(),
  recordCircuitBreakerState: jest.fn(),
  recordCircuitBreakerTrip: jest.fn(),
  updateActiveConnections: jest.fn(),
  updateServiceInstanceCount: jest.fn(),
  createCustomCounter: jest.fn(() => ({ inc: jest.fn() })),
  createCustomGauge: jest.fn(() => ({ set: jest.fn() })),
  createCustomHistogram: jest.fn(() => ({ observe: jest.fn() })),
  getCustomMetric: jest.fn(),
  getMetrics: jest.fn(() => Promise.resolve('# Mock metrics')),
  getMetricsJSON: jest.fn(() => Promise.resolve([])),
  isHealthy: jest.fn(() => true),
  reset: jest.fn(),
  cleanup: jest.fn(),
  middleware: jest.fn(() => (req, res, next) => next())
};

// Test data generators
const testDataGenerators = {
  generateUser: (overrides = {}) => ({
    id: 'test-user-id',
    email: 'test@example.com',
    firstName: 'Test',
    lastName: 'User',
    roles: ['user'],
    createdAt: new Date().toISOString(),
    ...overrides
  }),

  generateJWT: (payload = {}) => {
    return jwt.sign({
      userId: 'test-user-id',
      email: 'test@example.com',
      roles: ['user'],
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
      iat: Math.floor(Date.now() / 1000),
      ...payload
    }, process.env.JWT_SECRET || 'test-secret');
  },

  generateApiKey: () => 'sk-test-api-key-' + Math.random().toString(36).substr(2, 9),

  generateComments: (count = 5) => {
    const sampleComments = [
      'Great product, love the features!',
      'Customer service could be better',
      'Fast shipping and good quality',
      'The interface is confusing',
      'Excellent value for money'
    ];
    
    return Array(count).fill().map((_, i) => 
      sampleComments[i % sampleComments.length]
    );
  },

  generateNPSData: (count = 10) => {
    return Array(count).fill().map((_, i) => ({
      customerId: `customer-${i}`,
      npsScore: Math.floor(Math.random() * 11), // 0-10
      surveyDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
      comments: i % 3 === 0 ? 'Great service!' : undefined
    }));
  }
};

// Test environment setup helpers
const testHelpers = {
  async waitFor(condition, timeout = 1000) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      if (await condition()) {
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    return false;
  },

  createMockExpressApp: () => {
    const app = {
      use: jest.fn(),
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
      listen: jest.fn((port, callback) => {
        if (callback) callback();
        return { close: jest.fn() };
      })
    };
    return app;
  },

  setupServiceMocks: () => {
    // Reset all mocks
    Object.values(mockAxios).forEach(mock => mock.mockClear());
    Object.values(mockServiceRegistry).forEach(mock => {
      if (typeof mock === 'function') mock.mockClear();
    });
    Object.values(mockLogger).forEach(mock => mock.mockClear());
    Object.values(mockMetrics).forEach(mock => mock.mockClear());
  },

  simulateServiceFailure: (serviceName, failureType = 'timeout') => {
    const service = mockServiceRegistry.services.get(serviceName);
    if (service) {
      service.instances.forEach(instance => {
        instance.status = 'unhealthy';
        if (failureType === 'circuit-breaker') {
          instance.circuitBreakerState = 'open';
        }
      });
    }

    // Mock axios to reject requests for this service
    const portMap = { auth: '3001', comment: '3002', industry: '3003', nps: '3004' };
    const port = portMap[serviceName];
    
    if (port) {
      mockAxios.get.mockImplementation((url) => {
        if (url.includes(`:${port}`)) {
          if (failureType === 'timeout') {
            return new Promise(() => {}); // Never resolves
          } else {
            return Promise.reject(new Error('Service unavailable'));
          }
        }
        return mockServiceResponses[serviceName]['/health'];
      });
    }
  },

  restoreServiceHealth: (serviceName) => {
    const service = mockServiceRegistry.services.get(serviceName);
    if (service) {
      service.instances.forEach(instance => {
        instance.status = 'healthy';
        instance.circuitBreakerState = 'closed';
      });
    }
    
    // Restore normal axios behavior
    mockAxios.get.mockImplementation(mockAxios.get.getMockImplementation());
  }
};

module.exports = {
  mockServiceResponses,
  mockAxios,
  mockServiceRegistry,
  mockLogger,
  mockMetrics,
  testDataGenerators,
  testHelpers
};