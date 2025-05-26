// gateway-service/tests/unit/services/ServiceRegistry.test.js
const ServiceRegistry = require('../../../services/ServiceRegistry');
const axios = require('axios');

// Mock axios
jest.mock('axios');
const mockedAxios = axios;

describe('ServiceRegistry', () => {
  let serviceRegistry;

  beforeEach(() => {
    jest.clearAllMocks();
    serviceRegistry = new ServiceRegistry({
      healthCheckInterval: 1000, // 1 second for faster tests
      serviceTimeout: 500,
      circuitBreakerEnabled: true
    });
  });

  afterEach(async () => {
    if (serviceRegistry) {
      await serviceRegistry.shutdown();
    }
  });

  describe('initialization', () => {
    it('should initialize with default services', () => {
      expect(serviceRegistry.services.size).toBeGreaterThan(0);
      expect(serviceRegistry.services.has('auth')).toBe(true);
      expect(serviceRegistry.services.has('comment')).toBe(true);
      expect(serviceRegistry.services.has('industry')).toBe(true);
      expect(serviceRegistry.services.has('nps')).toBe(true);
    });

    it('should register monolith service when configured', () => {
      process.env.MONOLITH_SERVICE_URL = 'http://localhost:5000';
      const registry = new ServiceRegistry();
      
      expect(registry.services.has('monolith')).toBe(true);
      
      delete process.env.MONOLITH_SERVICE_URL;
      registry.shutdown();
    });

    it('should parse multiple service URLs correctly', () => {
      process.env.COMMENT_SERVICE_URL = 'http://comment1:3002,http://comment2:3002';
      const registry = new ServiceRegistry();
      
      const commentService = registry.services.get('comment');
      expect(commentService.instances).toHaveLength(2);
      expect(commentService.instances[0].url).toBe('http://comment1:3002');
      expect(commentService.instances[1].url).toBe('http://comment2:3002');
      
      delete process.env.COMMENT_SERVICE_URL;
      registry.shutdown();
    });
  });

  describe('getService', () => {
    it('should return healthy service instance', () => {
      // Set up a healthy service
      const authService = serviceRegistry.services.get('auth');
      authService.instances[0].status = 'healthy';
      authService.instances[0].circuitBreakerState = 'closed';
      
      const service = serviceRegistry.getService('auth');
      expect(service).toBeDefined();
      expect(service.url).toBe('http://localhost:3001');
    });

    it('should return null when no healthy instances available', () => {
      // Set all instances as unhealthy
      const authService = serviceRegistry.services.get('auth');
      authService.instances.forEach(instance => {
        instance.status = 'unhealthy';
      });
      
      const service = serviceRegistry.getService('auth');
      expect(service).toBeNull();
    });

    it('should skip instances with open circuit breakers', () => {
      const authService = serviceRegistry.services.get('auth');
      authService.instances[0].status = 'healthy';
      authService.instances[0].circuitBreakerState = 'open';
      
      const service = serviceRegistry.getService('auth');
      expect(service).toBeNull();
    });

    it('should return half-open circuit breaker instance when no healthy ones', () => {
      const authService = serviceRegistry.services.get('auth');
      authService.instances[0].status = 'unhealthy';
      authService.instances[0].circuitBreakerState = 'half-open';
      
      const service = serviceRegistry.getService('auth');
      expect(service).toBeDefined();
      expect(service.circuitBreakerState).toBe('half-open');
    });

    it('should return null for non-existent service', () => {
      const service = serviceRegistry.getService('non-existent');
      expect(service).toBeNull();
    });
  });

  describe('load balancing', () => {
    beforeEach(() => {
      // Set up multiple healthy instances
      const commentService = serviceRegistry.services.get('comment');
      commentService.instances = [
        {
          id: 'comment-0',
          name: 'comment',
          url: 'http://comment1:3002',
          status: 'healthy',
          circuitBreakerState: 'closed',
          requestCount: 10,
          lastResponseTime: 100
        },
        {
          id: 'comment-1',
          name: 'comment',
          url: 'http://comment2:3002',
          status: 'healthy',
          circuitBreakerState: 'closed',
          requestCount: 5,
          lastResponseTime: 200
        }
      ];
    });

    it('should use round-robin by default', () => {
      serviceRegistry.loadBalanceStrategy = 'round_robin';
      
      const service1 = serviceRegistry.getService('comment');
      const service2 = serviceRegistry.getService('comment');
      
      expect(service1.url).not.toBe(service2.url);
    });

    it('should use least connections strategy', () => {
      serviceRegistry.loadBalanceStrategy = 'least_connections';
      
      const service = serviceRegistry.getService('comment');
      expect(service.url).toBe('http://comment2:3002'); // Has fewer connections (5 vs 10)
    });

    it('should use least response time strategy', () => {
      serviceRegistry.loadBalanceStrategy = 'least_response_time';
      
      const service = serviceRegistry.getService('comment');
      expect(service.url).toBe('http://comment1:3002'); // Has lower response time (100 vs 200)
    });

    it('should use random strategy', () => {
      serviceRegistry.loadBalanceStrategy = 'random';
      
      const service = serviceRegistry.getService('comment');
      expect(['http://comment1:3002', 'http://comment2:3002']).toContain(service.url);
    });
  });

  describe('recordRequest', () => {
    it('should record successful request', () => {
      const authService = serviceRegistry.services.get('auth');
      const instance = authService.instances[0];
      instance.circuitBreakerState = 'closed';
      
      serviceRegistry.recordRequest('auth', instance.id, true, 150);
      
      expect(instance.requestCount).toBe(1);
      expect(instance.lastResponseTime).toBe(150);
      expect(instance.consecutiveFailures).toBe(0);
    });

    it('should record failed request and increment failures', () => {
      const authService = serviceRegistry.services.get('auth');
      const instance = authService.instances[0];
      instance.circuitBreakerState = 'closed';
      
      serviceRegistry.recordRequest('auth', instance.id, false, 5000);
      
      expect(instance.requestCount).toBe(1);
      expect(instance.errorCount).toBe(1);
      expect(instance.consecutiveFailures).toBe(1);
    });

    it('should open circuit breaker after threshold failures', () => {
      const authService = serviceRegistry.services.get('auth');
      const instance = authService.instances[0];
      instance.circuitBreakerState = 'closed';
      
      // Record failures up to threshold
      for (let i = 0; i < 5; i++) {
        serviceRegistry.recordRequest('auth', instance.id, false, 5000);
      }
      
      expect(instance.circuitBreakerState).toBe('open');
    });

    it('should close circuit breaker after successful request in half-open state', () => {
      const authService = serviceRegistry.services.get('auth');
      const instance = authService.instances[0];
      instance.circuitBreakerState = 'half-open';
      
      serviceRegistry.recordRequest('auth', instance.id, true, 150);
      
      expect(instance.circuitBreakerState).toBe('closed');
    });
  });

  describe('health checks', () => {
    it('should mark instance as healthy when health check succeeds', async () => {
      mockedAxios.get.mockResolvedValueOnce({ status: 200 });
      
      const authService = serviceRegistry.services.get('auth');
      const instance = authService.instances[0];
      instance.status = 'unhealthy';
      
      await serviceRegistry.checkInstanceHealth('auth', instance);
      
      expect(instance.status).toBe('healthy');
      expect(instance.lastHealthCheck).toBeDefined();
      expect(mockedAxios.get).toHaveBeenCalledWith(
        'http://localhost:3001/health',
        expect.objectContaining({
          timeout: 5000,
          headers: expect.objectContaining({
            'User-Agent': 'Gateway-Health-Check/1.0',
            'X-Health-Check': 'true'
          })
        })
      );
    });

    it('should mark instance as unhealthy when health check fails', async () => {
      mockedAxios.get.mockRejectedValueOnce(new Error('Connection refused'));
      
      const authService = serviceRegistry.services.get('auth');
      const instance = authService.instances[0];
      instance.status = 'healthy';
      
      await serviceRegistry.checkInstanceHealth('auth', instance);
      
      expect(instance.status).toBe('unhealthy');
      expect(instance.lastHealthCheck).toBeDefined();
    });

    it('should emit serviceRecovered event', async () => {
      mockedAxios.get.mockResolvedValueOnce({ status: 200 });
      
      const authService = serviceRegistry.services.get('auth');
      const instance = authService.instances[0];
      instance.status = 'unhealthy';
      
      const eventSpy = jest.fn();
      serviceRegistry.on('serviceRecovered', eventSpy);
      
      await serviceRegistry.checkInstanceHealth('auth', instance);
      
      expect(eventSpy).toHaveBeenCalledWith({
        serviceName: 'auth',
        instance: instance
      });
    });

    it('should emit serviceUnhealthy event', async () => {
      const error = new Error('Connection refused');
      mockedAxios.get.mockRejectedValueOnce(error);
      
      const authService = serviceRegistry.services.get('auth');
      const instance = authService.instances[0];
      instance.status = 'healthy';
      
      const eventSpy = jest.fn();
      serviceRegistry.on('serviceUnhealthy', eventSpy);
      
      await serviceRegistry.checkInstanceHealth('auth', instance);
      
      expect(eventSpy).toHaveBeenCalledWith({
        serviceName: 'auth',
        instance: instance,
        error: error
      });
    });
  });

  describe('getAllServices', () => {
    it('should return all services with their status', () => {
      const services = serviceRegistry.getAllServices();
      
      expect(services).toHaveProperty('auth');
      expect(services).toHaveProperty('comment');
      expect(services).toHaveProperty('industry');
      expect(services).toHaveProperty('nps');
      
      expect(services.auth).toHaveProperty('totalInstances');
      expect(services.auth).toHaveProperty('healthyInstances');
      expect(services.auth).toHaveProperty('instances');
      expect(Array.isArray(services.auth.instances)).toBe(true);
    });
  });

  describe('getStats', () => {
    it('should return registry statistics', () => {
      const stats = serviceRegistry.getStats();
      
      expect(stats).toHaveProperty('totalServices');
      expect(stats).toHaveProperty('totalInstances');
      expect(stats).toHaveProperty('healthyInstances');
      expect(stats).toHaveProperty('unhealthyInstances');
      expect(stats).toHaveProperty('openCircuitBreakers');
      expect(stats).toHaveProperty('lastHealthCheck');
      expect(stats).toHaveProperty('services');
      
      expect(typeof stats.totalServices).toBe('number');
      expect(typeof stats.totalInstances).toBe('number');
    });

    it('should calculate correct statistics', () => {
      // Set up known state
      const authService = serviceRegistry.services.get('auth');
      authService.instances[0].status = 'healthy';
      authService.instances[0].circuitBreakerState = 'closed';
      
      const commentService = serviceRegistry.services.get('comment');
      commentService.instances[0].status = 'unhealthy';
      commentService.instances[0].circuitBreakerState = 'open';
      
      const stats = serviceRegistry.getStats();
      
      expect(stats.totalServices).toBeGreaterThan(0);
      expect(stats.healthyInstances).toBeGreaterThan(0);
      expect(stats.openCircuitBreakers).toBeGreaterThan(0);
    });
  });

  describe('development features', () => {
    it('should allow dynamic service registration in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      const service = serviceRegistry.dynamicRegister('test-service', {
        urls: ['http://test:3000'],
        healthPath: '/health'
      });
      
      expect(service).toBeDefined();
      expect(serviceRegistry.services.has('test-service')).toBe(true);
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should not allow dynamic registration in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      expect(() => {
        serviceRegistry.dynamicRegister('test-service', {
          urls: ['http://test:3000']
        });
      }).toThrow('Dynamic service registration not allowed in production');
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should allow service unregistration in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      serviceRegistry.dynamicRegister('test-service', {
        urls: ['http://test:3000']
      });
      
      const removed = serviceRegistry.unregisterService('test-service');
      
      expect(removed).toBe(true);
      expect(serviceRegistry.services.has('test-service')).toBe(false);
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('shutdown', () => {
    it('should shutdown gracefully', async () => {
      const shutdownSpy = jest.fn();
      serviceRegistry.on('shutdown', shutdownSpy);
      
      await serviceRegistry.shutdown();
      
      expect(serviceRegistry.isShuttingDown).toBe(true);
      expect(serviceRegistry.healthCheckTimer).toBeNull();
      expect(shutdownSpy).toHaveBeenCalled();
    });
  });
});