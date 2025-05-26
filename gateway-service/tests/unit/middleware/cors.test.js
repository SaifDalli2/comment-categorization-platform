// gateway-service/tests/unit/middleware/cors.test.js
const CorsManager = require('../../../middleware/cors');

describe('CorsManager', () => {
  let corsManager;

  beforeEach(() => {
    corsManager = new CorsManager();
  });

  describe('parseOrigins', () => {
    it('should parse environment variable origins correctly', () => {
      process.env.ALLOWED_ORIGINS = 'http://localhost:3000,http://localhost:3001';
      const manager = new CorsManager();
      const origins = manager.allowedOrigins;
      
      expect(origins).toContain('http://localhost:3000');
      expect(origins).toContain('http://localhost:3001');
    });

    it('should include default development origins', () => {
      const origins = corsManager.allowedOrigins;
      
      expect(origins).toContain('http://localhost:3000');
      expect(origins).toContain('http://127.0.0.1:3000');
    });

    it('should add production domain when configured', () => {
      process.env.PRODUCTION_DOMAIN = 'example.com';
      const manager = new CorsManager();
      const origins = manager.allowedOrigins;
      
      expect(origins).toContain('https://example.com');
      expect(origins).toContain('https://www.example.com');
      
      delete process.env.PRODUCTION_DOMAIN;
    });
  });

  describe('dynamicCors', () => {
    it('should allow requests with no origin', (done) => {
      const req = testUtils.createMockRequest({
        headers: {}
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = corsManager.dynamicCors();
      
      // Mock cors middleware behavior
      jest.doMock('cors', () => (options) => (req, res, next) => {
        const origin = req.headers.origin;
        const callback = options.origin;
        
        if (typeof callback === 'function') {
          callback(origin, (err, allow) => {
            if (err) return next(err);
            if (allow) {
              res.setHeader('Access-Control-Allow-Origin', origin || '*');
            }
            next();
          });
        } else {
          next();
        }
      });

      middleware(req, res, () => {
        expect(next).toHaveBeenCalled();
        done();
      });
    });

    it('should allow whitelisted origins', (done) => {
      const req = testUtils.createMockRequest({
        headers: {
          origin: 'http://localhost:3000'
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = corsManager.dynamicCors();
      
      middleware(req, res, () => {
        expect(next).toHaveBeenCalled();
        done();
      });
    });

    it('should reject non-whitelisted origins in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const req = testUtils.createMockRequest({
        headers: {
          origin: 'http://malicious-site.com'
        }
      });
      const res = testUtils.createMockResponse();
      const next = jest.fn();

      const corsOptions = corsManager.createCorsOptions();
      
      corsOptions.origin('http://malicious-site.com', (err, allowed) => {
        expect(allowed).toBe(false);
        expect(err).toBeDefined();
        expect(err.message).toContain('not allowed');
      });
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('handlePreflight', () => {
    it('should handle OPTIONS requests correctly', () => {
      const req = testUtils.createMockRequest({
        method: 'OPTIONS',
        headers: {
          origin: 'http://localhost:3000',
          'access-control-request-method': 'POST',
          'access-control-request-headers': 'content-type'
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = corsManager.handlePreflight();
      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Max-Age', '86400');
      expect(res.setHeader).toHaveBeenCalledWith('Vary', expect.stringContaining('Origin'));
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.end).toHaveBeenCalled();
    });

    it('should pass through non-OPTIONS requests', () => {
      const req = testUtils.createMockRequest({
        method: 'GET'
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = corsManager.handlePreflight();
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should add special headers for upload endpoints', () => {
      const req = testUtils.createMockRequest({
        method: 'OPTIONS',
        path: '/api/upload',
        headers: {
          origin: 'http://localhost:3000'
        }
      });
      const res = testUtils.createMockResponse();
      res.get = jest.fn().mockReturnValue('content-type, authorization');

      const middleware = corsManager.handlePreflight();
      middleware(req, res, testUtils.createMockNext());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Headers',
        expect.stringContaining('Content-Length, X-File-Name')
      );
    });
  });

  describe('handleCorsError', () => {
    it('should handle CORS errors properly', () => {
      const error = new Error('CORS policy violation');
      const req = testUtils.createMockRequest({
        headers: {
          origin: 'http://malicious-site.com'
        }
      });
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = corsManager.handleCorsError();
      middleware(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'CORS Policy Violation',
          origin: 'http://malicious-site.com'
        })
      );
    });

    it('should pass through non-CORS errors', () => {
      const error = new Error('Some other error');
      const req = testUtils.createMockRequest();
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = corsManager.handleCorsError();
      middleware(error, req, res, next);

      expect(next).toHaveBeenCalledWith(error);
      expect(res.status).not.toHaveBeenCalled();
    });
  });

  describe('securityHeaders', () => {
    it('should set security headers', () => {
      const req = testUtils.createMockRequest();
      const res = testUtils.createMockResponse();
      const next = testUtils.createMockNext();

      const middleware = corsManager.securityHeaders();
      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith('X-Content-Type-Options', 'nosniff');
      expect(res.setHeader).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
      expect(res.setHeader).toHaveBeenCalledWith('X-XSS-Protection', '1; mode=block');
      expect(res.setHeader).toHaveBeenCalledWith('Referrer-Policy', 'strict-origin-when-cross-origin');
      expect(next).toHaveBeenCalled();
    });
  });

  describe('getCorsInfo', () => {
    it('should return CORS configuration info', () => {
      const info = corsManager.getCorsInfo();
      
      expect(info).toHaveProperty('allowedOrigins');
      expect(info).toHaveProperty('allowedMethods');
      expect(info).toHaveProperty('allowedHeaders');
      expect(info).toHaveProperty('credentials');
      expect(info).toHaveProperty('maxAge');
      
      expect(Array.isArray(info.allowedOrigins)).toBe(true);
      expect(Array.isArray(info.allowedMethods)).toBe(true);
      expect(Array.isArray(info.allowedHeaders)).toBe(true);
    });
  });

  describe('updateAllowedOrigins', () => {
    it('should update origins in development mode', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      const newOrigins = ['http://new-origin.com'];
      const result = corsManager.updateAllowedOrigins(newOrigins);
      
      expect(result).toBe(true);
      expect(corsManager.allowedOrigins).toContain('http://new-origin.com');
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should not update origins in production mode', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const newOrigins = ['http://new-origin.com'];
      const result = corsManager.updateAllowedOrigins(newOrigins);
      
      expect(result).toBe(false);
      expect(corsManager.allowedOrigins).not.toContain('http://new-origin.com');
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('isValidOrigin', () => {
    it('should validate HTTP origins', () => {
      expect(corsManager.isValidOrigin('http://localhost:3000')).toBe(true);
      expect(corsManager.isValidOrigin('https://example.com')).toBe(true);
    });

    it('should reject invalid origins', () => {
      expect(corsManager.isValidOrigin('not-a-url')).toBe(false);
      expect(corsManager.isValidOrigin('ftp://example.com')).toBe(false);
      expect(corsManager.isValidOrigin('')).toBe(false);
    });
  });
});