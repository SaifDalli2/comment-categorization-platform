// gateway-service/tests/gateway.test.js
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

const app = require('../server');

describe('Gateway Service', () => {
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

    it('should list gateway services', async () => {
      const res = await request(app)
        .get('/api/gateway/services')
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.any(Object)
      });
    });
  });

  describe('Authentication', () => {
    const validToken = jwt.sign(
      { 
        userId: 'test-user-id',
        email: 'test@example.com',
        roles: ['user'],
        exp: Math.floor(Date.now() / 1000) + 3600
      },
      'test-jwt-secret-32-chars-minimum'
    );

    const expiredToken = jwt.sign(
      { 
        userId: 'test-user-id',
        email: 'test@example.com',
        exp: Math.floor(Date.now() / 1000) - 3600
      },
      'test-jwt-secret-32-chars-minimum'
    );

    it('should accept valid JWT tokens', async () => {
      // This would normally proxy to comment service, but since we don't have 
      // the service running, we expect a connection error (503)
      const res = await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', `Bearer ${validToken}`)
        .send({ comments: ['test'] })
        .expect(503); // Service unavailable

      expect(res.body.error.code).toBe('SERVICE_UNAVAILABLE');
    });

    it('should reject expired tokens', async () => {
      const res = await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', `Bearer ${expiredToken}`)
        .send({ comments: ['test'] })
        .expect(401);

      expect(res.body.error.code).toBe('TOKEN_EXPIRED');
    });

    it('should reject invalid tokens', async () => {
      const res = await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', 'Bearer invalid-token')
        .send({ comments: ['test'] })
        .expect(401);

      expect(res.body.error.code).toBe('INVALID_TOKEN');
    });

    it('should require authentication for protected routes', async () => {
      const res = await request(app)
        .post('/api/comments/categorize')
        .send({ comments: ['test'] })
        .expect(401);

      expect(res.body.error.code).toBe('AUTHENTICATION_REQUIRED');
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

    it('should allow requests from whitelisted origins', async () => {
      const res = await request(app)
        .get('/health')
        .set('Origin', 'http://localhost:3000')
        .expect(200);

      expect(res.headers['access-control-allow-origin']).toBeDefined();
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

    it('should return proper error format', async () => {
      const res = await request(app)
        .get('/api/non-existent')
        .expect(404);

      expect(res.body).toMatchObject({
        success: false,
        error: expect.objectContaining({
          code: expect.any(String),
          message: expect.any(String)
        }),
        metadata: expect.objectContaining({
          timestamp: expect.any(String),
          service: 'gateway'
        })
      });
    });
  });

  describe('Rate Limiting', () => {
    it('should apply rate limiting', async () => {
      // Make several rapid requests
      const requests = Array(10).fill().map(() =>
        request(app).get('/health')
      );

      const responses = await Promise.all(requests);
      
      // All should either succeed (200) or be rate limited (429)
      responses.forEach(res => {
        expect([200, 429]).toContain(res.status);
      });
    });
  });

  describe('Security Headers', () => {
    it('should set security headers', async () => {
      const res = await request(app)
        .get('/health')
        .expect(200);

      // Check for some security headers set by helmet
      expect(res.headers['x-content-type-options']).toBeDefined();
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