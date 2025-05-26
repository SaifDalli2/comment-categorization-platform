// gateway-service/tests/unit/middleware/auth.test.js
const AuthenticationManager = require('../../../middleware/auth');
const jwt = require('jsonwebtoken');

// Mock service registry
const mockServiceRegistry = {
  getService: jest.fn(),
  services: new Map()
};

describe('AuthenticationManager', () => {
  let authManager;

  beforeEach(() => {
    authManager = new AuthenticationManager(mockServiceRegistry);
    jest.clearAllMocks();
  });

  describe('authenticate middleware', () => {
    it('should authenticate valid JWT token', async () => {
      const token = testUtils.generateJWT();
      const req = testUtils.createMockRequest({
        headers: {
          authorization: `Bearer ${token}`
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.authenticate();
      await middleware(req, res, next);

      expect(req.user).toBeDefined();
      expect(req.user.id).toBe('test-user-id');
      expect(req.user.email).toBe('test@example.com');
      expect(next).toHaveBeenCalled();
    });

    it('should reject missing token when required', async () => {
      const req = testUtils.createMockRequest();
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.authenticate({ optional: false });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.objectContaining({
            code: 'AUTH_TOKEN_REQUIRED'
          })
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it('should allow missing token when optional', async () => {
      const req = testUtils.createMockRequest();
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.authenticate({ optional: true });
      await middleware(req, res, next);

      expect(req.user).toBeNull();
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should reject invalid JWT token', async () => {
      const req = testUtils.createMockRequest({
        headers: {
          authorization: 'Bearer invalid-token'
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.authenticate();
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.objectContaining({
            code: 'AUTH_TOKEN_INVALID'
          })
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject expired JWT token', async () => {
      const expiredToken = jwt.sign(
        { userId: 'test-user', exp: Math.floor(Date.now() / 1000) - 60 },
        process.env.JWT_SECRET
      );
      
      const req = testUtils.createMockRequest({
        headers: {
          authorization: `Bearer ${expiredToken}`
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.authenticate();
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it('should skip authentication for configured paths', async () => {
      const req = testUtils.createMockRequest({
        path: '/health'
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.authenticate({
        skipPaths: ['/health']
      });
      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should check required roles', async () => {
      const token = testUtils.generateJWT({ roles: ['user'] });
      const req = testUtils.createMockRequest({
        headers: {
          authorization: `Bearer ${token}`
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.authenticate({
        requireRoles: ['admin']
      });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'INSUFFICIENT_PERMISSIONS'
          })
        })
      );
    });
  });

  describe('verifyToken', () => {
    it('should verify valid token', async () => {
      const token = testUtils.generateJWT();
      const result = await authManager.verifyToken(token);
      
      expect(result).toBeDefined();
      expect(result.userId).toBe('test-user-id');
      expect(result.email).toBe('test@example.com');
    });

    it('should cache token verification results', async () => {
      const token = testUtils.generateJWT();
      
      // First call
      const result1 = await authManager.verifyToken(token);
      // Second call (should hit cache)
      const result2 = await authManager.verifyToken(token);
      
      expect(result1).toEqual(result2);
      expect(authManager.tokenCache.has(token)).toBe(true);
    });

    it('should validate token structure', async () => {
      const invalidToken = jwt.sign(
        { invalid: 'structure' },
        process.env.JWT_SECRET
      );
      
      const result = await authManager.verifyToken(invalidToken);
      expect(result).toBeNull();
    });
  });

  describe('authenticateApiKey', () => {
    it('should authenticate valid API key', () => {
      const req = testUtils.createMockRequest({
        headers: {
          'x-api-key': 'sk-valid-api-key-12345'
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      authManager.authenticateApiKey(req, res, next);

      expect(req.apiKey).toBe('sk-valid-api-key-12345');
      expect(req.authType).toBe('api_key');
      expect(next).toHaveBeenCalled();
    });

    it('should reject missing API key', () => {
      const req = testUtils.createMockRequest();
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      authManager.authenticateApiKey(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'API_KEY_REQUIRED'
          })
        })
      );
    });

    it('should reject invalid API key format', () => {
      const req = testUtils.createMockRequest({
        headers: {
          'x-api-key': 'invalid-format'
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      authManager.authenticateApiKey(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'API_KEY_INVALID'
          })
        })
      );
    });
  });

  describe('optionalAuth', () => {
    it('should authenticate when token provided', async () => {
      const token = testUtils.generateJWT();
      const req = testUtils.createMockRequest({
        headers: {
          authorization: `Bearer ${token}`
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      authManager.optionalAuth(req, res, next);

      expect(req.user).toBeDefined();
      expect(next).toHaveBeenCalled();
    });

    it('should continue without authentication when no token', async () => {
      const req = testUtils.createMockRequest();
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      authManager.optionalAuth(req, res, next);

      expect(req.user).toBeUndefined();
      expect(next).toHaveBeenCalled();
    });

    it('should continue when token is invalid', async () => {
      const req = testUtils.createMockRequest({
        headers: {
          authorization: 'Bearer invalid-token'
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      authManager.optionalAuth(req, res, next);

      expect(req.user).toBeUndefined();
      expect(next).toHaveBeenCalled();
    });
  });

  describe('requireRole', () => {
    it('should allow access with correct role', () => {
      const req = testUtils.createMockRequest({
        user: { roles: ['admin'] }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.requireRole('admin');
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should deny access without required role', () => {
      const req = testUtils.createMockRequest({
        user: { roles: ['user'] }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.requireRole('admin');
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it('should require authentication first', () => {
      const req = testUtils.createMockRequest();
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.requireRole('admin');
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should work with array of roles', () => {
      const req = testUtils.createMockRequest({
        user: { roles: ['user'] }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.requireRole(['admin', 'user']);
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });
  });

  describe('addTracingHeaders', () => {
    it('should add tracing headers', () => {
      const req = testUtils.createMockRequest();
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.addTracingHeaders();
      middleware(req, res, next);

      expect(req.headers['x-request-id']).toBeDefined();
      expect(req.headers['x-trace-id']).toBeDefined();
      expect(req.headers['x-service-name']).toBe('gateway');
      expect(res.setHeader).toHaveBeenCalledWith('X-Request-ID', expect.any(String));
      expect(res.setHeader).toHaveBeenCalledWith('X-Trace-ID', expect.any(String));
      expect(next).toHaveBeenCalled();
    });

    it('should use existing request ID if present', () => {
      const existingRequestId = 'existing-req-id';
      const req = testUtils.createMockRequest({
        headers: {
          'x-request-id': existingRequestId
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = authManager.addTracingHeaders();
      middleware(req, res, next);

      expect(req.headers['x-request-id']).toBe(existingRequestId);
      expect(next).toHaveBeenCalled();
    });
  });

  describe('token cache management', () => {
    it('should cache tokens correctly', async () => {
      const token = testUtils.generateJWT();
      
      expect(authManager.tokenCache.size).toBe(0);
      
      await authManager.verifyToken(token);
      expect(authManager.tokenCache.size).toBe(1);
      
      // Verify cache hit
      await authManager.verifyToken(token);
      expect(authManager.tokenCache.size).toBe(1);
    });

    it('should clear token cache', () => {
      const token = testUtils.generateJWT();
      authManager.tokenCache.set(token, { decoded: {}, expiry: Date.now() + 60000 });
      
      expect(authManager.tokenCache.size).toBe(1);
      
      authManager.clearTokenCache();
      expect(authManager.tokenCache.size).toBe(0);
    });

    it('should cleanup expired tokens', async () => {
      const expiredToken = 'expired-token';
      authManager.tokenCache.set(expiredToken, {
        decoded: {},
        expiry: Date.now() - 1000 // Expired
      });
      
      const validToken = 'valid-token';
      authManager.tokenCache.set(validToken, {
        decoded: {},
        expiry: Date.now() + 60000 // Valid
      });
      
      expect(authManager.tokenCache.size).toBe(2);
      
      authManager.cleanupTokenCache();
      
      expect(authManager.tokenCache.size).toBe(1);
      expect(authManager.tokenCache.has(expiredToken)).toBe(false);
      expect(authManager.tokenCache.has(validToken)).toBe(true);
    });
  });

  describe('getAuthStats', () => {
    it('should return authentication statistics', () => {
      const stats = authManager.getAuthStats();
      
      expect(stats).toHaveProperty('cachedTokens');
      expect(stats).toHaveProperty('cacheExpiryMs');
      expect(stats).toHaveProperty('timestamp');
      expect(typeof stats.cachedTokens).toBe('number');
      expect(typeof stats.cacheExpiryMs).toBe('number');
    });
  });
});