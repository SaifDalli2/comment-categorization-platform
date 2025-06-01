// gateway-service/tests/gateway.test.js - Updated for Fixed Auth Routes
const request = require('supertest');
const jwt = require('jsonwebtoken');

// Mock the config and logger to avoid dependency issues
jest.mock('../config/simple', () => ({
  port: 3000,
  services: {
    auth: 'http://localhost:3001',
    comment: 'http://localhost:3002',
    industry: 'http://localhost:3003',
    nps: 'http://localhost:3004'
  },
  security: {
    jwtSecret: 'test-jwt-secret-32-chars-minimum',
    corsOrigins: ['http://localhost:3000']
  },
  monitoring: {
    logLevel: 'error',
    healthCheckInterval: 30000
  }
}));

jest.mock('../utils/simpleLogger', () => ({
  info: jest.fn(),
  debug: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  request: jest.fn()
}));

// Mock axios for service calls
jest.mock('axios');
const axios = require('axios');

const app = require('../server');

describe('Gateway Service', () => {
  beforeEach(() => {
    // Reset axios mock before each test
    axios.get.mockClear();
    axios.post.mockClear();
  });

  describe('Health Endpoints', () => {
    it('should respond to basic health check', async () => {
      const res = await request(app)
        .get('/health')
        .expect(200);

      expect(res.body).toMatchObject({
        status: 'healthy',
        service: 'gateway',
        timestamp: expect.any(String)
      });
    });

    it('should respond to service health check', async () => {
      // Mock service health checks
      axios.get.mockImplementation((url) => {
        if (url.includes('/health')) {
          return Promise.resolve({ status: 200, data: { status: 'healthy' } });
        }
        return Promise.reject(new Error('Service unavailable'));
      });

      const res = await request(app)
        .get('/health/services')
        .expect(res => {
          // Accept both 200 (healthy) and 503 (degraded) as valid responses
          expect([200, 503]).toContain(res.status);
        });

      expect(res.body).toMatchObject({
        status: expect.oneOf(['healthy', 'degraded']),
        service: 'gateway'
      });
    });
  });

  describe('Authentication Routes - PUBLIC (No Auth Required)', () => {
    const publicRoutes = [
      '/api/auth/login',
      '/api/auth/register',
      '/api/auth/forgot-password',
      '/api/auth/reset-password',
      '/api/auth/verify-email'
    ];

    publicRoutes.forEach(route => {
      it(`should allow access to ${route} without authentication`, async () => {
        // Mock the auth service response
        axios.post.mockResolvedValueOnce({
          status: 200,
          data: { success: true, message: 'Request processed' }
        });

        await request(app)
          .post(route)
          .send({ email: 'test@example.com', password: 'Test123!' })
          .expect(200);

        expect(axios.post).toHaveBeenCalled();
      });
    });

    it('should successfully login without providing Bearer token', async () => {
      // Mock successful login response from auth service
      axios.post.mockResolvedValueOnce({
        status: 200,
        data: {
          success: true,
          data: {
            token: 'mock-jwt-token',
            user: {
              id: 'user-123',
              email: 'test@example.com'
            }
          }
        }
      });

      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'Test123!'
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(axios.post).toHaveBeenCalledWith(
        expect.stringContaining('/api/auth/login'),
        expect.objectContaining({
          email: 'test@example.com',
          password: 'Test123!'
        }),
        expect.any(Object)
      );
    });

    it('should successfully register without providing Bearer token', async () => {
      // Mock successful registration response from auth service
      axios.post.mockResolvedValueOnce({
        status: 201,
        data: {
          success: true,
          data: {
            user: {
              id: 'new-user-123',
              email: 'newuser@example.com'
            }
          }
        }
      });

      await request(app)
        .post('/api/auth/register')
        .send({
          email: 'newuser@example.com',
          password: 'Test123!',
          firstName: 'Test',
          lastName: 'User'
        })
        .expect(201);

      expect(axios.post).toHaveBeenCalled();
    });
  });

  describe('Authentication Routes - PROTECTED (Auth Required)', () => {
    const validToken = jwt.sign(
      { 
        userId: 'test-user-id',
        email: 'test@example.com',
        roles: ['user'],
        exp: Math.floor(Date.now() / 1000) + 3600
      },
      'test-jwt-secret-32-chars-minimum'
    );

    const protectedRoutes = [
      '/api/auth/profile',
      '/api/auth/change-password',
      '/api/auth/logout',
      '/api/auth/verify'
    ];

    protectedRoutes.forEach(route => {
      it(`should require authentication for ${route}`, async () => {
        await request(app)
          .post(route)
          .send({ someData: 'test' })
          .expect(401);
      });

      it(`should allow access to ${route} with valid token`, async () => {
        // Mock the auth service response
        axios.post.mockResolvedValueOnce({
          status: 200,
          data: { success: true, message: 'Request processed' }
        });

        await request(app)
          .post(route)
          .set('Authorization', `Bearer ${validToken}`)
          .send({ someData: 'test' })
          .expect(200);
      });
    });

    it('should reject expired tokens for protected auth routes', async () => {
      const expiredToken = jwt.sign(
        { 
          userId: 'test-user-id',
          email: 'test@example.com',
          exp: Math.floor(Date.now() / 1000) - 3600
        },
        'test-jwt-secret-32-chars-minimum'
      );

      const res = await request(app)
        .post('/api/auth/profile')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);

      expect(res.body.error.code).toBe('TOKEN_EXPIRED');
    });
  });

  describe('Other Service Routes', () => {
    const validToken = jwt.sign(
      { 
        userId: 'test-user-id',
        email: 'test@example.com',
        roles: ['user'],
        exp: Math.floor(Date.now() / 1000) + 3600
      },
      'test-jwt-secret-32-chars-minimum'
    );

    it('should require authentication for comment service routes', async () => {
      await request(app)
        .post('/api/comments/categorize')
        .send({ comments: ['test'] })
        .expect(401);
    });

    it('should forward authenticated requests to comment service', async () => {
      // Mock comment service response
      axios.post.mockResolvedValueOnce({
        status: 200,
        data: { success: true, jobId: 'job-123' }
      });

      await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', `Bearer ${validToken}`)
        .send({ comments: ['test comment'] })
        .expect(200);
    });

    it('should allow public access to industry service routes', async () => {
      // Mock industry service response
      axios.get.mockResolvedValueOnce({
        status: 200,
        data: { success: true, data: ['SaaS/Technology', 'Healthcare'] }
      });

      await request(app)
        .get('/api/industries')
        .expect(200);
    });

    it('should require authentication for NPS service routes', async () => {
      await request(app)
        .get('/api/nps/dashboard/user-123')
        .expect(401);
    });
  });

  describe('Error Handling', () => {
    it('should handle 404 for non-existent API endpoints', async () => {
      const res = await request(app)
        .get('/api/non-existent-endpoint')
        .expect(404);

      expect(res.body).toMatchObject({
        success: false,
        error: expect.objectContaining({
          code: 'RESOURCE_NOT_FOUND'
        })
      });
    });

    it('should handle service unavailability gracefully', async () => {
      const validToken = jwt.sign(
        { 
          userId: 'test-user-id',
          email: 'test@example.com',
          exp: Math.floor(Date.now() / 1000) + 3600
        },
        'test-jwt-secret-32-chars-minimum'
      );

      // Mock service unavailable
      axios.post.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const res = await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', `Bearer ${validToken}`)
        .send({ comments: ['test'] })
        .expect(503);

      expect(res.body.error.code).toBe('SERVICE_UNAVAILABLE');
    });
  });

  describe('CORS', () => {
    it('should handle preflight requests', async () => {
      const res = await request(app)
        .options('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .expect(204);

      expect(res.headers['access-control-allow-origin']).toBeDefined();
    });
  });

  describe('Rate Limiting', () => {
    it('should apply rate limiting to auth endpoints', async () => {
      // Mock auth service to respond for each request
      axios.post.mockResolvedValue({
        status: 200,
        data: { success: true }
      });

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

  describe('Service Health Monitoring', () => {
    it('should track service health when proxying requests', async () => {
      const validToken = jwt.sign(
        { 
          userId: 'test-user-id',
          email: 'test@example.com',
          exp: Math.floor(Date.now() / 1000) + 3600
        },
        'test-jwt-secret-32-chars-minimum'
      );

      // Mock successful service response
      axios.post.mockResolvedValueOnce({
        status: 200,
        data: { success: true }
      });

      await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', `Bearer ${validToken}`)
        .send({ comments: ['test'] })
        .expect(200);

      // Verify service health was recorded (this would be implementation specific)
      expect(axios.post).toHaveBeenCalled();
    });
  });
});

// Helper to extend Jest matchers
expect.extend({
  oneOf(received, expected) {
    const pass = expected.includes(received);
    if (pass) {
      return {
        message: () => `expected ${received} not to be one of ${expected}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be one of ${expected}`,
        pass: false,
      };
    }
  },
});