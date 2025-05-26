// gateway-service/middleware/cache.js
const Redis = require('redis');
const crypto = require('crypto');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

class CacheMiddleware {
  constructor(options = {}) {
    this.enabled = options.enabled !== false && process.env.CACHE_ENABLED !== 'false';
    this.redisUrl = options.redisUrl || process.env.REDIS_URL || 'redis://localhost:6379';
    this.defaultTTL = options.defaultTTL || parseInt(process.env.CACHE_DEFAULT_TTL) || 300; // 5 minutes
    this.maxKeyLength = options.maxKeyLength || 250;
    this.keyPrefix = options.keyPrefix || 'gateway:cache:';
    
    // Cache strategies by endpoint pattern
    this.cacheStrategies = {
      '/api/industries': { ttl: 3600, strategy: 'static' }, // 1 hour - rarely changes
      '/api/industries/*/categories': { ttl: 1800, strategy: 'static' }, // 30 minutes
      '/api/industries/*/factors': { ttl: 1800, strategy: 'static' }, // 30 minutes
      '/api/auth/verify': { ttl: 60, strategy: 'user-specific' }, // 1 minute - token validation
      '/api/nps/dashboard/*': { ttl: 300, strategy: 'user-specific' }, // 5 minutes
      '/api/nps/trends/*': { ttl: 600, strategy: 'user-specific' }, // 10 minutes
      '/health': { ttl: 30, strategy: 'static' }, // 30 seconds
      '/health/services': { ttl: 15, strategy: 'static' }, // 15 seconds
      '/api/gateway/services': { ttl: 60, strategy: 'static' }, // 1 minute
      '/api/gateway/stats': { ttl: 30, strategy: 'static' } // 30 seconds
    };

    // Methods that should be cached
    this.cacheableMethods = ['GET', 'HEAD'];
    
    // Status codes that should be cached
    this.cacheableStatusCodes = [200, 203, 300, 301, 302, 404, 410];
    
    this.redis = null;
    this.isConnected = false;
    
    // Metrics
    this.cacheHits = 0;
    this.cacheMisses = 0;
    this.cacheErrors = 0;
    
    if (this.enabled) {
      this.initializeRedis();
    }
  }

  async initializeRedis() {
    try {
      this.redis = Redis.createClient({
        url: this.redisUrl,
        retry_delay_on_failover: 100,
        retry_delay_on_cluster_down: 300,
        max_attempts: 3,
        connect_timeout: 5000
      });

      this.redis.on('connect', () => {
        this.isConnected = true;
        logger.info('Cache middleware connected to Redis', {
          cache: {
            url: this.redisUrl,
            status: 'connected'
          }
        });
      });

      this.redis.on('error', (error) => {
        this.isConnected = false;
        this.cacheErrors++;
        logger.error('Redis cache error', {
          cache: {
            error: error.message,
            url: this.redisUrl
          }
        }, error);
      });

      this.redis.on('end', () => {
        this.isConnected = false;
        logger.warn('Redis cache connection ended', {
          cache: {
            url: this.redisUrl,
            status: 'disconnected'
          }
        });
      });

      await this.redis.connect();
      
      // Test connection
      await this.redis.ping();
      
    } catch (error) {
      this.enabled = false;
      logger.error('Failed to initialize Redis cache', {
        cache: {
          error: error.message,
          fallback: 'caching disabled'
        }
      }, error);
    }
  }

  // Main caching middleware
  middleware() {
    return async (req, res, next) => {
      if (!this.shouldCache(req)) {
        return next();
      }

      const cacheKey = this.generateCacheKey(req);
      const strategy = this.getCacheStrategy(req.path);
      
      try {
        // Try to get from cache
        const cachedResponse = await this.getFromCache(cacheKey);
        
        if (cachedResponse) {
          this.cacheHits++;
          this.sendCachedResponse(res, cachedResponse, cacheKey);
          
          // Record cache hit metrics
          metrics.recordCustomCounter('cache_hits_total', 1, {
            strategy: strategy.strategy,
            path: this.normalizePath(req.path)
          });
          
          logger.debug('Cache hit', {
            cache: {
              key: cacheKey,
              path: req.path,
              strategy: strategy.strategy
            }
          });
          
          return;
        }

        // Cache miss - continue with request and cache response
        this.cacheMisses++;
        metrics.recordCustomCounter('cache_misses_total', 1, {
          strategy: strategy.strategy,
          path: this.normalizePath(req.path)
        });

        this.interceptResponse(req, res, cacheKey, strategy);
        next();

      } catch (error) {
        this.cacheErrors++;
        logger.error('Cache middleware error', {
          cache: {
            key: cacheKey,
            error: error.message
          }
        }, error);
        
        // Continue without caching on error
        next();
      }
    };
  }

  shouldCache(req) {
    if (!this.enabled || !this.isConnected) {
      return false;
    }

    // Only cache GET and HEAD requests
    if (!this.cacheableMethods.includes(req.method)) {
      return false;
    }

    // Don't cache requests with authorization unless specifically configured
    if (req.headers.authorization) {
      const strategy = this.getCacheStrategy(req.path);
      if (strategy.strategy !== 'user-specific') {
        return false;
      }
    }

    // Don't cache requests with no-cache header
    if (req.headers['cache-control'] && req.headers['cache-control'].includes('no-cache')) {
      return false;
    }

    // Check if path is configured for caching
    return this.getCacheStrategy(req.path) !== null;
  }

  getCacheStrategy(path) {
    // Direct match
    if (this.cacheStrategies[path]) {
      return this.cacheStrategies[path];
    }

    // Pattern matching
    for (const [pattern, strategy] of Object.entries(this.cacheStrategies)) {
      if (this.matchesPattern(path, pattern)) {
        return strategy;
      }
    }

    return null;
  }

  matchesPattern(path, pattern) {
    // Convert pattern to regex
    const regexPattern = pattern
      .replace(/\*/g, '[^/]+')
      .replace(/\//g, '\\/');
    
    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(path);
  }

  generateCacheKey(req) {
    const strategy = this.getCacheStrategy(req.path);
    let keyComponents = [this.keyPrefix, req.method, req.path];

    // Add query parameters
    if (Object.keys(req.query).length > 0) {
      const sortedQuery = Object.keys(req.query)
        .sort()
        .map(key => `${key}=${req.query[key]}`)
        .join('&');
      keyComponents.push(sortedQuery);
    }

    // Add user-specific component for user-specific strategies
    if (strategy.strategy === 'user-specific' && req.userContext) {
      keyComponents.push(`user:${req.userContext.userId}`);
    }

    // Create hash if key is too long
    const key = keyComponents.join(':');
    if (key.length > this.maxKeyLength) {
      const hash = crypto.createHash('sha256').update(key).digest('hex');
      return `${this.keyPrefix}hash:${hash}`;
    }

    return key;
  }

  async getFromCache(key) {
    if (!this.isConnected) {
      return null;
    }

    try {
      const cached = await this.redis.get(key);
      if (cached) {
        return JSON.parse(cached);
      }
    } catch (error) {
      logger.error('Cache get error', {
        cache: {
          key,
          error: error.message
        }
      }, error);
    }

    return null;
  }

  async setCache(key, data, ttl) {
    if (!this.isConnected) {
      return;
    }

    try {
      const serialized = JSON.stringify(data);
      await this.redis.setEx(key, ttl, serialized);
      
      logger.debug('Cached response', {
        cache: {
          key,
          ttl,
          size: serialized.length
        }
      });
      
    } catch (error) {
      logger.error('Cache set error', {
        cache: {
          key,
          error: error.message
        }
      }, error);
    }
  }

  interceptResponse(req, res, cacheKey, strategy) {
    const originalSend = res.send;
    const originalJson = res.json;
    const originalEnd = res.end;

    const captureResponse = (data) => {
      if (this.shouldCacheResponse(res, strategy)) {
        const responseData = {
          statusCode: res.statusCode,
          headers: this.getCacheableHeaders(res),
          body: data,
          timestamp: Date.now()
        };

        this.setCache(cacheKey, responseData, strategy.ttl);
      }
    };

    res.send = function(data) {
      captureResponse(data);
      return originalSend.call(this, data);
    };

    res.json = function(data) {
      captureResponse(JSON.stringify(data));
      return originalJson.call(this, data);
    };

    res.end = function(data) {
      if (data) {
        captureResponse(data);
      }
      return originalEnd.call(this, data);
    };
  }

  shouldCacheResponse(res, strategy) {
    // Only cache successful responses and specific error codes
    if (!this.cacheableStatusCodes.includes(res.statusCode)) {
      return false;
    }

    // Don't cache responses with no-cache header
    const cacheControl = res.getHeader('cache-control');
    if (cacheControl && cacheControl.includes('no-cache')) {
      return false;
    }

    return true;
  }

  getCacheableHeaders(res) {
    const headers = {};
    const cacheableHeaders = [
      'content-type',
      'content-encoding',
      'content-language',
      'expires',
      'last-modified',
      'etag',
      'cache-control'
    ];

    cacheableHeaders.forEach(header => {
      const value = res.getHeader(header);
      if (value) {
        headers[header] = value;
      }
    });

    return headers;
  }

  sendCachedResponse(res, cachedResponse, cacheKey) {
    // Set cached headers
    Object.entries(cachedResponse.headers).forEach(([name, value]) => {
      res.setHeader(name, value);
    });

    // Add cache headers
    res.setHeader('X-Cache', 'HIT');
    res.setHeader('X-Cache-Key', cacheKey.replace(this.keyPrefix, ''));
    res.setHeader('X-Cache-Age', Math.floor((Date.now() - cachedResponse.timestamp) / 1000));

    // Send cached response
    res.status(cachedResponse.statusCode);
    
    if (typeof cachedResponse.body === 'string') {
      res.send(cachedResponse.body);
    } else {
      res.json(cachedResponse.body);
    }
  }

  // Cache invalidation methods
  async invalidate(pattern) {
    if (!this.isConnected) {
      return false;
    }

    try {
      const keys = await this.redis.keys(`${this.keyPrefix}*${pattern}*`);
      if (keys.length > 0) {
        await this.redis.del(keys);
        logger.info('Cache invalidated', {
          cache: {
            pattern,
            keysRemoved: keys.length
          }
        });
        return true;
      }
    } catch (error) {
      logger.error('Cache invalidation error', {
        cache: {
          pattern,
          error: error.message
        }
      }, error);
    }

    return false;
  }

  async invalidateUser(userId) {
    return this.invalidate(`user:${userId}`);
  }

  async invalidatePath(path) {
    return this.invalidate(path);
  }

  async flush() {
    if (!this.isConnected) {
      return false;
    }

    try {
      const keys = await this.redis.keys(`${this.keyPrefix}*`);
      if (keys.length > 0) {
        await this.redis.del(keys);
        logger.info('Cache flushed', {
          cache: {
            keysRemoved: keys.length
          }
        });
      }
      return true;
    } catch (error) {
      logger.error('Cache flush error', {
        cache: {
          error: error.message
        }
      }, error);
      return false;
    }
  }

  // Express routes for cache management
  getCacheRoutes() {
    const router = require('express').Router();

    // Cache statistics
    router.get('/stats', (req, res) => {
      const stats = this.getStats();
      res.json({
        success: true,
        data: stats,
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'],
          service: 'gateway'
        }
      });
    });

    // Invalidate cache by pattern
    router.delete('/invalidate', async (req, res) => {
      const { pattern } = req.query;
      
      if (!pattern) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Pattern query parameter is required'
          }
        });
      }

      const result = await this.invalidate(pattern);
      res.json({
        success: true,
        data: {
          invalidated: result,
          pattern
        }
      });
    });

    // Invalidate user-specific cache
    router.delete('/invalidate/user/:userId', async (req, res) => {
      const { userId } = req.params;
      const result = await this.invalidateUser(userId);
      
      res.json({
        success: true,
        data: {
          invalidated: result,
          userId
        }
      });
    });

    // Flush entire cache
    router.delete('/flush', async (req, res) => {
      const result = await this.flush();
      res.json({
        success: true,
        data: {
          flushed: result
        }
      });
    });

    return router;
  }

  // Cache statistics
  getStats() {
    const totalRequests = this.cacheHits + this.cacheMisses;
    const hitRate = totalRequests > 0 ? (this.cacheHits / totalRequests) * 100 : 0;

    return {
      enabled: this.enabled,
      connected: this.isConnected,
      redisUrl: this.redisUrl,
      stats: {
        hits: this.cacheHits,
        misses: this.cacheMisses,
        errors: this.cacheErrors,
        hitRate: Math.round(hitRate * 100) / 100,
        totalRequests
      },
      strategies: Object.keys(this.cacheStrategies).length,
      defaultTTL: this.defaultTTL
    };
  }

  // Normalize path for metrics
  normalizePath(path) {
    return path
      .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:uuid')
      .replace(/\/\d+/g, '/:id')
      .replace(/\/[a-zA-Z0-9_-]{20,}/g, '/:token');
  }

  // Warmup cache with common endpoints
  async warmupCache() {
    if (!this.enabled || !this.isConnected) {
      return;
    }

    const warmupEndpoints = [
      '/api/industries',
      '/api/industries/SaaS%2FTechnology/categories',
      '/api/industries/Healthcare/categories',
      '/health',
      '/health/services'
    ];

    logger.info('Starting cache warmup', {
      cache: {
        endpoints: warmupEndpoints.length
      }
    });

    for (const endpoint of warmupEndpoints) {
      try {
        // Make internal request to warm up cache
        const axios = require('axios');
        await axios.get(`http://localhost:${process.env.PORT || 3000}${endpoint}`, {
          timeout: 5000
        });
      } catch (error) {
        logger.warn('Cache warmup failed for endpoint', {
          cache: {
            endpoint,
            error: error.message
          }
        });
      }
    }

    logger.info('Cache warmup completed');
  }

  // Cleanup method
  async cleanup() {
    if (this.redis && this.isConnected) {
      await this.redis.quit();
      this.isConnected = false;
    }
  }
}

module.exports = CacheMiddleware;