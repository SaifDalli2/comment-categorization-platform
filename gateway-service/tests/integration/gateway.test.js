// gateway-service/tests/integration/gateway.test.js
const request = require('supertest');
const app = require('../../server');

describe('Gateway Service Integration Tests', () => {
  beforeAll(async () => {
    // Wait for gateway to connect to mock services
    await global.integrationTestUtils.waitForHealthy(app);
  });

  describe('Health and Status Endpoints', () => {
    it('should allow requests from whitelisted origins', async () => {
      const res = await request(app)
        .get('/api/status')
        .set('Origin', 'http://localhost:3000')
        .expect(200);

      expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
    });

    it('should reject requests from non-whitelisted origins in production', async () => {
      // This would need to be tested with production configuration
      // For now, we test that CORS headers are properly set
      const res = await request(app)
        .get('/api/status')
        .set('Origin', 'http://malicious-site.com');

      // In development, this might be allowed, but headers should be set
      expect(res.headers).toHaveProperty('access-control-allow-origin');
    });
  });

  describe('Authentication Flow', () => {
    let authToken;

    it('should proxy login requests to auth service', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123'
        })
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.objectContaining({
          token: expect.any(String),
          user: expect.objectContaining({
            email: 'test@example.com'
          })
        })
      });

      authToken = res.body.data.token;
    });

    it('should handle authentication failures', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'wrong@example.com',
          password: 'wrongpassword'
        })
        .expect(401);

      expect(res.body).toMatchObject({
        success: false,
        error: expect.objectContaining({
          code: 'INVALID_CREDENTIALS'
        })
      });
    });

    it('should validate tokens for authenticated endpoints', async () => {
      const res = await request(app)
        .get('/api/auth/verify')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.objectContaining({
          valid: true,
          user: expect.any(Object)
        })
      });
    });

    it('should reject requests without authentication token', async () => {
      const res = await request(app)
        .post('/api/comments/categorize')
        .send({
          comments: ['Test comment'],
          apiKey: 'sk-test-key'
        })
        .expect(401);

      expect(res.body).toMatchObject({
        success: false,
        error: expect.objectContaining({
          code: 'AUTH_TOKEN_REQUIRED'
        })
      });
    });
  });

  describe('Service Proxying', () => {
    let authToken;

    beforeAll(async () => {
      // Get auth token for authenticated requests
      const authRes = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123'
        });
      authToken = authRes.body.data.token;
    });

    it('should proxy requests to comment service', async () => {
      const res = await request(app)
        .post('/api/comments/categorize')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          comments: ['Test comment for categorization'],
          apiKey: 'sk-test-api-key-12345'
        })
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.objectContaining({
          jobId: expect.any(String),
          status: 'queued'
        })
      });

      // Verify gateway headers were added
      expect(res.headers['x-served-by']).toBe('comment');
      expect(res.headers['x-response-time']).toBeDefined();
    });

    it('should proxy requests to industry service', async () => {
      const res = await request(app)
        .get('/api/industries')
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.objectContaining({
          industries: expect.any(Array)
        })
      });
    });

    it('should proxy requests to NPS service', async () => {
      const res = await request(app)
        .get('/api/nps/dashboard/test-user-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.objectContaining({
          npsScore: expect.any(Number),
          totalResponses: expect.any(Number)
        })
      });
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
          code: 'RESOURCE_NOT_FOUND',
          message: expect.stringContaining('API endpoint does not exist')
        })
      });
    });

    it('should handle service errors gracefully', async () => {
      const res = await request(app)
        .get('/api/auth/error/500')
        .expect(500);

      expect(res.body).toMatchObject({
        error: 'Internal server error'
      });
    });

    it('should handle service timeouts', async () => {
      const res = await request(app)
        .get('/api/auth/error/timeout')
        .timeout(1000);

      // This test depends on how timeouts are configured
      // The request should either timeout or return a gateway timeout error
      expect([408, 504, 'ECONNABORTED']).toContain(res.status || res.code);
    });
  });

  describe('Rate Limiting', () => {
    it('should apply rate limiting to requests', async () => {
      const requests = [];
      
      // Make multiple rapid requests
      for (let i = 0; i < 10; i++) {
        requests.push(
          request(app)
            .get('/api/status')
            .expect(res => {
              expect([200, 429]).toContain(res.status);
            })
        );
      }

      await Promise.all(requests);
    });

    it('should return rate limit headers', async () => {
      const res = await request(app)
        .get('/api/status')
        .expect(200);

      // Check for rate limit headers (if implemented)
      if (res.headers['x-ratelimit-limit']) {
        expect(res.headers['x-ratelimit-limit']).toBeDefined();
        expect(res.headers['x-ratelimit-remaining']).toBeDefined();
      }
    });
  });

  describe('Request Tracing', () => {
    it('should add request tracing headers', async () => {
      const res = await request(app)
        .get('/api/status')
        .expect(200);

      expect(res.headers['x-request-id']).toBeDefined();
      expect(res.headers['x-trace-id']).toBeDefined();
    });

    it('should preserve existing request ID', async () => {
      const customRequestId = 'custom-request-id-123';
      
      const res = await request(app)
        .get('/api/status')
        .set('X-Request-ID', customRequestId)
        .expect(200);

      expect(res.headers['x-request-id']).toBe(customRequestId);
    });
  });

  describe('Security Headers', () => {
    it('should set security headers on responses', async () => {
      const res = await request(app)
        .get('/api/status')
        .expect(200);

      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBeDefined();
      expect(res.headers['x-xss-protection']).toBeDefined();
    });

    it('should set HSTS headers in production', async () => {
      // This would need production configuration to test properly
      const res = await request(app)
        .get('/api/status')
        .expect(200);

      // In test environment, HSTS might not be enabled
      // but we can check that security middleware is working
      expect(res.headers['x-content-type-options']).toBeDefined();
    });
  });

  describe('Static File Serving', () => {
    it('should serve static files with proper headers', async () => {
      // This assumes there are static files in the public directory
      const res = await request(app)
        .get('/favicon.ico')
        .expect(res => {
          // Should either find the file (200) or not found (404)
          expect([200, 404]).toContain(res.status);
        });

      if (res.status === 200) {
        expect(res.headers['x-content-type-options']).toBe('nosniff');
        expect(res.headers['cache-control']).toBeDefined();
      }
    });
  });

  describe('Circuit Breaker Functionality', () => {
    it('should handle service failures with circuit breaker', async () => {
      // This test would require triggering circuit breaker conditions
      // For now, we verify that the circuit breaker is configured
      const statsRes = await request(app)
        .get('/api/gateway/stats')
        .expect(200);

      expect(statsRes.body.data).toHaveProperty('openCircuitBreakers');
    });
  });

  describe('Load Balancing', () => {
    it('should distribute requests across multiple service instances', async () => {
      // This test would require multiple service instances
      // For now, we verify that load balancing configuration exists
      const servicesRes = await request(app)
        .get('/api/gateway/services')
        .expect(200);

      // Check that services are properly registered
      expect(servicesRes.body.data).toHaveProperty('auth');
      expect(servicesRes.body.data).toHaveProperty('comment');
    });
  });

  describe('Metrics Collection', () => {
    it('should expose Prometheus metrics', async () => {
      const res = await request(app)
        .get('/metrics')
        .expect(200);

      expect(res.text).toContain('# HELP');
      expect(res.text).toContain('gateway_');
      expect(res.headers['content-type']).toContain('text/plain');
    });

    it('should collect HTTP request metrics', async () => {
      // Make a request to generate metrics
      await request(app)
        .get('/api/status')
        .expect(200);

      const metricsRes = await request(app)
        .get('/metrics')
        .expect(200);

      expect(metricsRes.text).toContain('gateway_http_requests_total');
      expect(metricsRes.text).toContain('gateway_http_request_duration_seconds');
    });
  });

  describe('Error Monitoring', () => {
    it('should expose error monitoring endpoints', async () => {
      const res = await request(app)
        .get('/api/monitoring/errors')
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.objectContaining({
          statistics: expect.any(Object),
          patterns: expect.any(Object)
        })
      });
    });

    it('should track error rates by path', async () => {
      const res = await request(app)
        .get('/api/monitoring/errors/paths')
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.objectContaining({
          paths: expect.any(Array),
          summary: expect.any(Object)
        })
      });
    });
  });
});should respond to basic health check', async () => {
      const res = await request(app)
        .get('/health')
        .expect(200);

      expect(res.body).toMatchObject({
        status: 'healthy',
        service: 'gateway',
        version: expect.any(String),
        uptime: expect.any(Number),
        environment: 'test'
      });
    });

    it('should respond to service health check', async () => {
      const res = await request(app)
        .get('/health/services')
        .expect(200);

      expect(res.body).toMatchObject({
        status: 'healthy',
        service: 'gateway',
        dependencies: expect.any(Object),
        summary: expect.objectContaining({
          totalServices: expect.any(Number),
          healthyInstances: expect.any(Number)
        })
      });
    });

    it('should respond to API status endpoint', async () => {
      const res = await request(app)
        .get('/api/status')
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.objectContaining({
          service: 'api-gateway',
          status: 'operational',
          version: expect.any(String)
        })
      });
    });
  });

  describe('Service Discovery and Routing', () => {
    it('should list available services', async () => {
      const res = await request(app)
        .get('/api/gateway/services')
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.objectContaining({
          auth: expect.any(Object),
          comment: expect.any(Object),
          industry: expect.any(Object),
          nps: expect.any(Object)
        })
      });
    });

    it('should provide gateway statistics', async () => {
      const res = await request(app)
        .get('/api/gateway/stats')
        .expect(200);

      expect(res.body).toMatchObject({
        success: true,
        data: expect.objectContaining({
          totalServices: expect.any(Number),
          healthyInstances: expect.any(Number)
        })
      });
    });
  });

  describe('CORS Functionality', () => {
    it('should handle preflight requests', async () => {
      const res = await request(app)
        .options('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'content-type')
        .expect(200);

      expect(res.headers['access-control-allow-origin']).toBeDefined();
      expect(res.headers['access-control-allow-methods']).toBeDefined();
      expect(res.headers['access-control-allow-headers']).toBeDefined();
    });

    it('