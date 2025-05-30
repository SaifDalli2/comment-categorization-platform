// gateway-service/config/enhanced.js
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');

// Load environment variables
dotenv.config();

class GatewayConfig {
  constructor() {
    this.environment = process.env.NODE_ENV || 'development';
    this.isDevelopment = this.environment === 'development';
    this.isProduction = this.environment === 'production';
    this.isTesting = this.environment === 'test';
    
    this.loadConfiguration();
    this.validateConfiguration();
  }

  loadConfiguration() {
    this.config = {
      // Server configuration
      server: {
        port: parseInt(process.env.PORT) || 3000,
        host: process.env.HOST || '0.0.0.0',
        environment: this.environment
      },

      // Service URLs with fallbacks
      services: {
        auth: this.getServiceUrl('AUTH_SERVICE_URL', 'https://auth-service-voice-0add8d339257.herokuapp.com'),
        comment: this.getServiceUrl('COMMENT_SERVICE_URL', 'https://your-comment-service.herokuapp.com'),
        industry: this.getServiceUrl('INDUSTRY_SERVICE_URL', 'https://your-industry-service.herokuapp.com'),
        nps: this.getServiceUrl('NPS_SERVICE_URL', 'https://your-nps-service.herokuapp.com')
      },

      // Security configuration
      security: {
        jwtSecret: process.env.JWT_SECRET,
        corsOrigins: this.parseCorsOrigins(),
        rateLimiting: {
          general: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 100
          },
          auth: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 20
          },
          upload: {
            windowMs: 60 * 60 * 1000, // 1 hour
            max: 10
          },
          categorize: {
            windowMs: 60 * 60 * 1000, // 1 hour
            max: 50
          }
        },
        helmetConfig: {
          contentSecurityPolicy: {
            directives: {
              defaultSrc: ["'self'"],
              styleSrc: ["'self'", "'unsafe-inline'"],
              scriptSrc: ["'self'"],
              imgSrc: ["'self'", "data:", "https:"],
              connectSrc: ["'self'", "wss:", "https:"]
            }
          },
          crossOriginEmbedderPolicy: false
        }
      },

      // Client configuration for service communication
      clients: {
        timeout: parseInt(process.env.SERVICE_TIMEOUT) || 30000,
        retryAttempts: parseInt(process.env.SERVICE_RETRY_ATTEMPTS) || 3,
        retryDelay: parseInt(process.env.SERVICE_RETRY_DELAY) || 1000,
        healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000
      },

      // Monitoring and logging
      monitoring: {
        logLevel: process.env.LOG_LEVEL || (this.isProduction ? 'info' : 'debug'),
        enableColors: !this.isProduction && process.env.ENABLE_COLORS !== 'false',
        enableMetrics: process.env.ENABLE_METRICS !== 'false',
        healthCheckEndpoint: process.env.HEALTH_CHECK_ENDPOINT || '/health'
      },

      // Feature flags
      features: {
        serviceVerification: process.env.ENABLE_SERVICE_VERIFICATION === 'true',
        aggregatedEndpoints: process.env.ENABLE_AGGREGATED_ENDPOINTS !== 'false',
        circuitBreaker: process.env.ENABLE_CIRCUIT_BREAKER !== 'false',
        detailedErrorLogging: !this.isProduction || process.env.DETAILED_ERROR_LOGGING === 'true'
      }
    };
  }

  getServiceUrl(envVar, fallback) {
    const url = process.env[envVar];
    if (!url && this.isProduction) {
      console.warn(`Warning: ${envVar} not set in production environment`);
    }
    return url || fallback;
  }

  parseCorsOrigins() {
    const defaultOrigins = [
      'https://gateway-service-b25f91548194.herokuapp.com',
      'https://your-frontend-app.netlify.app',
      'https://your-frontend-app.vercel.app'
    ];

    // Add development origins
    if (this.isDevelopment) {
      defaultOrigins.push('http://localhost:3000', 'http://localhost:5173', 'http://localhost:3001');
    }

    // Parse custom origins from environment
    if (process.env.ALLOWED_ORIGINS) {
      const customOrigins = process.env.ALLOWED_ORIGINS
        .split(',')
        .map(origin => origin.trim())
        .filter(origin => origin.length > 0);
      
      return [...new Set([...defaultOrigins, ...customOrigins])];
    }

    return defaultOrigins;
  }

  validateConfiguration() {
    const errors = [];

    // Validate required environment variables
    const requiredVars = ['JWT_SECRET'];
    
    requiredVars.forEach(varName => {
      if (!process.env[varName]) {
        errors.push(`Missing required environment variable: ${varName}`);
      }
    });

    // Validate JWT secret length
    if (this.config.security.jwtSecret && this.config.security.jwtSecret.length < 32) {
      errors.push('JWT_SECRET must be at least 32 characters long');
    }

    // Validate service URLs in production
    if (this.isProduction) {
      Object.entries(this.config.services).forEach(([service, url]) => {
        if (!url || url.includes('your-')) {
          errors.push(`Service URL not configured for ${service}: ${url}`);
        }
      });
    }

    if (errors.length > 0) {
      console.error('Configuration validation errors:');
      errors.forEach(error => console.error(`  - ${error}`));
      
      if (this.isProduction) {
        process.exit(1);
      } else {
        console.warn('Continuing with default values for development...');
        this.applyDevelopmentDefaults();
      }
    }

    this.logConfiguration();
  }

  applyDevelopmentDefaults() {
    if (!this.config.security.jwtSecret) {
      this.config.security.jwtSecret = 'dev-secret-change-in-production-32-chars-minimum';
      console.warn('Using default JWT secret for development');
    }
  }

  logConfiguration() {
    console.log('Gateway Configuration Summary:');
    console.log(`  Environment: ${this.config.server.environment}`);
    console.log(`  Port: ${this.config.server.port}`);
    console.log(`  Services configured: ${Object.keys(this.config.services).join(', ')}`);
    console.log(`  CORS origins: ${this.config.security.corsOrigins.length} configured`);
    console.log(`  Log level: ${this.config.monitoring.logLevel}`);
    console.log(`  Features enabled: ${Object.entries(this.config.features).filter(([, enabled]) => enabled).map(([feature]) => feature).join(', ')}`);
  }

  // Getter methods for easy access
  get port() { return this.config.server.port; }
  get services() { return this.config.services; }
  get security() { return this.config.security; }
  get monitoring() { return this.config.monitoring; }
  get features() { return this.config.features; }
  get clients() { return this.config.clients; }

  // Method to get service-specific configuration
  getServiceConfig(serviceName) {
    return {
      url: this.config.services[serviceName],
      timeout: this.config.clients.timeout,
      retryAttempts: this.config.clients.retryAttempts,
      retryDelay: this.config.clients.retryDelay
    };
  }

  // Method to update configuration at runtime (development only)
  updateConfig(updates) {
    if (this.isProduction) {
      throw new Error('Configuration updates not allowed in production');
    }
    
    Object.assign(this.config, updates);
    console.log('Configuration updated:', updates);
  }
}

// Create singleton instance
const gatewayConfig = new GatewayConfig();

module.exports = gatewayConfig;

// gateway-service/tests/enhanced.test.js
const request = require('supertest');
const jwt = require('jsonwebtoken');
const nock = require('nock'); // For mocking HTTP requests

// Mock the enhanced config
jest.mock('../config/enhanced', () => ({
  port: 3000,
  services: {
    auth: 'http://localhost:3001',
    comment: 'http://localhost:3002',
    industry: 'http://localhost:3003',
    nps: 'http://localhost:3004'
  },
  security: {
    jwtSecret: 'test-jwt-secret-32-chars-minimum-length',
    corsOrigins: ['http://localhost:3000'],
    rateLimiting: {
      general: { windowMs: 15 * 60 * 1000, max: 100 },
      auth: { windowMs: 15 * 60 * 1000, max: 20 }
    }
  },
  monitoring: {
    logLevel: 'error',
    enableColors: false
  },
  features: {
    serviceVerification: false,
    aggregatedEndpoints: true
  },
  clients: {
    timeout: 5000,
    retryAttempts: 2,
    retryDelay: 500,
    healthCheckInterval: 30000
  }
}));

// Mock logger to reduce test noise
jest.mock('../utils/simpleLogger', () => ({
  info: jest.fn(),
  debug: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  log: jest.fn(),
  systemInfo: jest.fn()
}));

const app = require('../server');

describe('Enhanced Gateway Service', () => {
  let authServiceMock, commentServiceMock, industryServiceMock, npsServiceMock;

  beforeEach(() => {
    // Set up service mocks
    authServiceMock = nock('http://localhost:3001');
    commentServiceMock = nock('http://localhost:3002');
    industryServiceMock = nock('http://localhost:3003');
    npsServiceMock = nock('http://localhost:3004');
  });

  afterEach(() => {
    nock.cleanAll();
  });

  describe('Health Endpoints', () => {
    it('should respond to basic health check', async () => {
      const res = await request(app)
        .get('/health')
        .expect(200);

      expect(res.body).toMatchObject({
        status: 'healthy',
        service: 'gateway',
        timestamp: expect.any(String),
        uptime: expect.any(Number)
      });
    });

    it('should respond to enhanced service health check', async () => {
      // Mock service health endpoints
      authServiceMock.get('/health').reply(200, { status: 'healthy' });
      commentServiceMock.get('/health').reply(200, { status: 'healthy' });
      industryServiceMock.get('/health').reply(200, { status: 'healthy' });
      npsServiceMock.get('/health').reply(200, { status: 'healthy' });

      const res = await request(app)
        .get('/health/services')
        .expect(200);

      expect(res.body).toMatchObject({
        status: 'healthy',
        service: 'gateway',
        dependencies: expect.any(Object),
        summary: expect.objectContaining({
          totalServices: expect.any(Number),
          healthyServices: expect.any(Number)
        })
      });
    });

    it('should handle degraded service health', async () => {
      // Mock some services as unhealthy
      authServiceMock.get('/health').reply(200, { status: 'healthy' });
      commentServiceMock.get('/health').reply(503, { status: 'unhealthy' });
      industryServiceMock.get('/health').reply(200, { status: 'healthy' });
      npsServiceMock.get('/health').replyWithError('Connection refused');

      const res = await request(app)
        .get('/health/services')
        .expect(503);

      expect(res.body.status).toBe('degraded');
      expect(res.body.summary.unhealthyServices).toBeGreaterThan(0);
    });
  });

  describe('Enhanced Authentication', () => {
    const createValidToken = (payload = {}) => {
      return jwt.sign(
        {
          userId: 'test-user-123',
          email: 'test@example.com',
          roles: ['user'],
          industry: 'SaaS/Technology',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
          ...payload
        },
        'test-jwt-secret-32-chars-minimum-length'
      );
    };

    it('should handle optional authentication correctly', async () => {
      industryServiceMock.get('/api/industries').reply(200, { 
        success: true, 
        data: ['SaaS/Technology', 'Healthcare'] 
      });

      // Request without token should work
      await request(app)
        .get('/api/industries')
        .expect(200);

      // Request with valid token should also work
      const token = createValidToken();
      await request(app)
        .get('/api/industries')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
    });

    it('should require authentication for protected routes', async () => {
      await request(app)
        .post('/api/comments/categorize')
        .send({ comments: ['test comment'] })
        .expect(401);

      expect(await request(app).get('/api/comments/categorize').expect(404)); // Method not allowed, but auth passed
    });

    it('should forward user context to downstream services', async () => {
      const token = createValidToken({
        userId: 'user-456',
        email: 'user@test.com',
        industry: 'Healthcare'
      });

      commentServiceMock
        .post('/api/comments/categorize')
        .matchHeader('x-user-id', 'user-456')
        .matchHeader('x-user-email', 'user@test.com')
        .matchHeader('x-user-industry', 'Healthcare')
        .matchHeader('x-gateway-request', 'true')
        .reply(200, { success: true, jobId: 'job-123' });

      await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', `Bearer ${token}`)
        .send({ comments: ['test comment'], apiKey: 'sk-test' })
        .expect(200);
    });

    it('should handle token verification with auth service', async () => {
      const token = createValidToken();

      // Mock auth service verification for critical endpoints
      authServiceMock
        .post('/api/auth/verify')
        .matchHeader('authorization', `Bearer ${token}`)
        .reply(200, {
          success: true,
          data: {
            user: {
              userId: 'test-user-123',
              email: 'test@example.com',
              roles: ['user']
            }
          }
        });

      commentServiceMock
        .post('/api/comments/categorize')
        .reply(200, { success: true, jobId: 'job-123' });

      await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', `Bearer ${token}`)
        .send({ comments: ['test comment'] })
        .expect(200);
    });
  });

  describe('Service Integration', () => {
    it('should handle service unavailability gracefully', async () => {
      const token = createValidToken();

      // Mock service being down
      commentServiceMock
        .post('/api/comments/categorize')
        .replyWithError('ECONNREFUSED');

      const res = await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', `Bearer ${token}`)
        .send({ comments: ['test comment'] })
        .expect(503);

      expect(res.body).toMatchObject({
        success: false,
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: expect.stringContaining('service error')
        }
      });
    });

    it('should handle service timeouts', async () => {
      const token = createValidToken();

      // Mock service timeout
      commentServiceMock
        .post('/api/comments/categorize')
        .delayConnection(35000) // Longer than our timeout
        .reply(200, { success: true });

      const res = await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', `Bearer ${token}`)
        .send({ comments: ['test comment'] })
        .expect(504);

      expect(res.body.error.code).toBe('GATEWAY_TIMEOUT');
    });
  });

  describe('Aggregated Endpoints', () => {
    it('should provide user dashboard aggregation', async () => {
      const token = createValidToken({ userId: 'dashboard-user' });

      // Mock multiple service responses
      authServiceMock
        .get('/api/users/dashboard-user')
        .reply(200, {
          success: true,
          data: { id: 'dashboard-user', email: 'user@test.com' }
        });

      npsServiceMock
        .get('/api/nps/dashboard/dashboard-user')
        .reply(200, {
          success: true,
          data: { npsScore: 50, totalResponses: 100 }
        });

      commentServiceMock
        .get('/api/comments/jobs/history/dashboard-user')
        .query({ limit: 5 })
        .reply(200, {
          success: true,
          data: [{ id: 'job1', status: 'completed' }]
        });

      const res = await request(app)
        .get('/api/gateway/user/dashboard')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('profile');
      expect(res.body.data).toHaveProperty('nps');
      expect(res.body.data).toHaveProperty('recentJobs');
    });

    it('should handle partial service failures in aggregation', async () => {
      const token = createValidToken({ userId: 'partial-user' });

      // Mock successful auth service
      authServiceMock
        .get('/api/users/partial-user')
        .reply(200, {
          success: true,
          data: { id: 'partial-user', email: 'user@test.com' }
        });

      // Mock failed NPS service
      npsServiceMock
        .get('/api/nps/dashboard/partial-user')
        .reply(503, { error: 'Service unavailable' });

      // Mock successful comment service
      commentServiceMock
        .get('/api/comments/jobs/history/partial-user')
        .query({ limit: 5 })
        .reply(200, {
          success: true,
          data: []
        });

      const res = await request(app)
        .get('/api/gateway/user/dashboard')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.profile).toBeTruthy();
      expect(res.body.data.nps).toBeNull(); // Failed service should return null
      expect(res.body.data.recentJobs).toEqual([]);
    });
  });

  describe('Gateway Management', () => {
    it('should provide service information endpoint', async () => {
      // Mock health checks
      authServiceMock.get('/health').reply(200, { status: 'healthy' });
      commentServiceMock.get('/health').reply(200, { status: 'healthy' });
      industryServiceMock.get('/health').reply(503, { status: 'unhealthy' });
      npsServiceMock.get('/health').reply(200, { status: 'healthy' });

      const res = await request(app)
        .get('/api/gateway/services')
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('services');
      expect(res.body.data).toHaveProperty('gateway');
      expect(res.body.data.gateway).toHaveProperty('uptime');
    });

    it('should validate industries through direct endpoint', async () => {
      industryServiceMock
        .post('/api/industries/validate')
        .reply(200, {
          success: true,
          data: {
            valid: ['SaaS/Technology'],
            invalid: ['NonExistent']
          }
        });

      const res = await request(app)
        .get('/api/gateway/industries/validate')
        .query({ industries: 'SaaS/Technology,NonExistent' })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('valid');
      expect(res.body.data).toHaveProperty('invalid');
    });
  });

  describe('Error Handling', () => {
    it('should provide consistent error format', async () => {
      const res = await request(app)
        .get('/api/non-existent-endpoint')
        .expect(404);

      expect(res.body).toMatchObject({
        success: false,
        error: {
          code: 'RESOURCE_NOT_FOUND',
          message: expect.any(String),
          suggestion: expect.any(String)
        },
        metadata: {
          timestamp: expect.any(String),
          requestId: expect.any(String),
          service: 'gateway'
        }
      });
    });

    it('should handle malformed JSON gracefully', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .set('Content-Type', 'application/json')
        .send('{"invalid": json}')
        .expect(400);

      expect(res.body.success).toBe(false);
      expect(res.body.error).toBeDefined();
    });
  });

  describe('Rate Limiting', () => {
    it('should apply rate limiting to auth endpoints', async () => {
      // Mock auth service to respond quickly
      for (let i = 0; i < 25; i++) {
        authServiceMock.post('/api/auth/login').reply(401, { error: 'Invalid credentials' });
      }

      const requests = [];
      for (let i = 0; i < 25; i++) {
        requests.push(
          request(app)
            .post('/api/auth/login')
            .send({ email: 'test@test.com', password: 'wrong' })
        );
      }

      const responses = await Promise.all(requests);
      
      // Some requests should be rate limited (429)
      const rateLimitedResponses = responses.filter(res => res.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });
  });

  describe('CORS Handling', () => {
    it('should handle CORS preflight requests', async () => {
      const res = await request(app)
        .options('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Content-Type,Authorization')
        .expect(204);

      expect(res.headers['access-control-allow-origin']).toBeDefined();
      expect(res.headers['access-control-allow-methods']).toBeDefined();
    });

    it('should reject requests from non-whitelisted origins', async () => {
      await request(app)
        .get('/health')
        .set('Origin', 'https://malicious-site.com')
        .expect(500); // CORS error
    });
  });
});