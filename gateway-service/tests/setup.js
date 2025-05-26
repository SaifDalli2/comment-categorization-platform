// gateway-service/tests/setup.js
const { jest } = require('@jest/globals');

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.PORT = '3000';
process.env.JWT_SECRET = 'test-jwt-secret-for-testing-purposes-only-32-chars-minimum';
process.env.SESSION_SECRET = 'test-session-secret-for-testing-purposes-only-32-chars-minimum';
process.env.AUTH_SERVICE_URL = 'http://localhost:3001';
process.env.COMMENT_SERVICE_URL = 'http://localhost:3002';
process.env.INDUSTRY_SERVICE_URL = 'http://localhost:3003';
process.env.NPS_SERVICE_URL = 'http://localhost:3004';
process.env.RATE_LIMIT_WINDOW_MS = '900000';
process.env.RATE_LIMIT_MAX_REQUESTS = '100';
process.env.HEALTH_CHECK_INTERVAL = '30000';
process.env.CIRCUIT_BREAKER_ENABLED = 'true';
process.env.LOG_LEVEL = 'error'; // Reduce noise in tests

// Mock console methods for cleaner test output
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
};

// Global test utilities
global.testUtils = {
  createMockRequest: (overrides = {}) => ({
    method: 'GET',
    path: '/test',
    originalUrl: '/test',
    url: '/test',
    ip: '127.0.0.1',
    headers: {
      'user-agent': 'test-agent',
      'x-request-id': 'test-request-id'
    },
    get: function(header) {
      return this.headers[header.toLowerCase()];
    },
    query: {},
    body: {},
    ...overrides
  }),

  createMockResponse: () => {
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
      getHeader: jest.fn(),
      end: jest.fn().mockReturnThis(),
      headersSent: false,
      statusCode: 200
    };
    
    // Mock error response utilities
    res.error = {
      send: jest.fn().mockReturnThis(),
      unauthorized: jest.fn().mockReturnThis(),
      forbidden: jest.fn().mockReturnThis(),
      notFound: jest.fn().mockReturnThis(),
      validation: jest.fn().mockReturnThis(),
      rateLimit: jest.fn().mockReturnThis(),
      serviceError: jest.fn().mockReturnThis()
    };
    
    return res;
  },

  createMockNext: () => jest.fn(),

  sleep: (ms) => new Promise(resolve => setTimeout(resolve, ms)),

  generateJWT: (payload = {}) => {
    const jwt = require('jsonwebtoken');
    return jwt.sign({
      userId: 'test-user-id',
      email: 'test@example.com',
      roles: ['user'],
      ...payload
    }, process.env.JWT_SECRET, { expiresIn: '1h' });
  },

  createAuthenticatedRequest: (userPayload = {}) => {
    const token = global.testUtils.generateJWT(userPayload);
    return global.testUtils.createMockRequest({
      headers: {
        'authorization': `Bearer ${token}`,
        'user-agent': 'test-agent',
        'x-request-id': 'test-request-id'
      }
    });
  }
};

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});