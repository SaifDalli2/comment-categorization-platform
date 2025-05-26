// gateway-service/utils/connectionPoolManager.js
const https = require('https');
const http = require('http');
const axios = require('axios');
const logger = require('./logger');
const metrics = require('./metrics');

class ConnectionPoolManager {
  constructor(options = {}) {
    this.pools = new Map();
    this.defaultConfig = {
      maxSockets: parseInt(process.env.MAX_SOCKETS) || 50,
      maxFreeSockets: parseInt(process.env.MAX_FREE_SOCKETS) || 10,
      timeout: parseInt(process.env.CONNECTION_TIMEOUT) || 30000,
      keepAlive: process.env.KEEP_ALIVE !== 'false',
      keepAliveMsecs: parseInt(process.env.KEEP_ALIVE_MS) || 1000,
      freeSocketTimeout: parseInt(process.env.FREE_SOCKET_TIMEOUT) || 30000,
      scheduling: process.env.CONNECTION_SCHEDULING || 'lifo'
    };
    
    this.config = { ...this.defaultConfig, ...options };
    this.stats = {
      totalConnections: 0,
      activeConnections: 0,
      poolHits: 0,
      poolMisses: 0,
      timeouts: 0,
      errors: 0
    };
    
    this.initializeMetrics();
    this.setupCleanupInterval();
  }

  initializeMetrics() {
    // Create custom metrics for connection pool monitoring
    this.connectionPoolGauge = metrics.createCustomGauge(
      'connection_pool_size',
      'Current size of connection pools',
      ['service_name', 'type']
    );

    this.connectionPoolUsageGauge = metrics.createCustomGauge(
      'connection_pool_usage',
      'Current usage of connection pools',
      ['service_name']
    );

    this.connectionPoolHitsCounter = metrics.createCustomCounter(
      'connection_pool_hits_total',
      'Total connection pool hits',
      ['service_name']
    );

    this.connectionPoolMissesCounter = metrics.createCustomCounter(
      'connection_pool_misses_total',
      'Total connection pool misses',
      ['service_name']
    );

    this.connectionTimeoutCounter = metrics.createCustomCounter(
      'connection_timeouts_total',
      'Total connection timeouts',
      ['service_name']
    );
  }

  // Create or get connection pool for a service
  getOrCreatePool(serviceName, serviceUrl) {
    if (this.pools.has(serviceName)) {
      return this.pools.get(serviceName);
    }

    const pool = this.createPool(serviceName, serviceUrl);
    this.pools.set(serviceName, pool);
    
    logger.info('Connection pool created', {
      connectionPool: {
        serviceName,
        serviceUrl,
        maxSockets: this.config.maxSockets,
        maxFreeSockets: this.config.maxFreeSockets
      }
    });

    return pool;
  }

  createPool(serviceName, serviceUrl) {
    const url = new URL(serviceUrl);
    const isHttps = url.protocol === 'https:';
    
    // Create HTTP/HTTPS agent with connection pooling
    const agent = isHttps ? new https.Agent({
      keepAlive: this.config.keepAlive,
      keepAliveMsecs: this.config.keepAliveMsecs,
      maxSockets: this.config.maxSockets,
      maxFreeSockets: this.config.maxFreeSockets,
      timeout: this.config.timeout,
      freeSocketTimeout: this.config.freeSocketTimeout,
      scheduling: this.config.scheduling
    }) : new http.Agent({
      keepAlive: this.config.keepAlive,
      keepAliveMsecs: this.config.keepAliveMsecs,
      maxSockets: this.config.maxSockets,
      maxFreeSockets: this.config.maxFreeSockets,
      timeout: this.config.timeout,
      freeSocketTimeout: this.config.freeSocketTimeout,
      scheduling: this.config.scheduling
    });

    // Create axios instance with the agent
    const axiosInstance = axios.create({
      baseURL: serviceUrl,
      timeout: this.config.timeout,
      httpAgent: !isHttps ? agent : undefined,
      httpsAgent: isHttps ? agent : undefined,
      maxRedirects: 3,
      validateStatus: () => true, // Don't throw on HTTP error statuses
      headers: {
        'Connection': 'keep-alive',
        'User-Agent': 'Claude-Analysis-Gateway/1.0',
        'Accept-Encoding': 'gzip, deflate, br'
      }
    });

    // Add request interceptor for metrics
    axiosInstance.interceptors.request.use(
      (config) => {
        this.stats.totalConnections++;
        this.stats.activeConnections++;
        
        // Check if using pooled connection
        const socket = config.adapter?.socket;
        if (socket && socket.reused) {
          this.stats.poolHits++;
          this.connectionPoolHitsCounter.inc({ service_name: serviceName });
        } else {
          this.stats.poolMisses++;
          this.connectionPoolMissesCounter.inc({ service_name: serviceName });
        }

        return config;
      },
      (error) => {
        this.stats.errors++;
        return Promise.reject(error);
      }
    );

    // Add response interceptor for metrics
    axiosInstance.interceptors.response.use(
      (response) => {
        this.stats.activeConnections--;
        this.updatePoolMetrics(serviceName, agent);
        return response;
      },
      (error) => {
        this.stats.activeConnections--;
        this.stats.errors++;
        
        if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
          this.stats.timeouts++;
          this.connectionTimeoutCounter.inc({ service_name: serviceName });
        }
        
        this.updatePoolMetrics(serviceName, agent);
        return Promise.reject(error);
      }
    );

    // Monitor agent events
    agent.on('socket', (socket) => {
      socket.on('connect', () => {
        logger.debug('Socket connected', {
          connectionPool: {
            serviceName,
            socketReused: socket.reused || false
          }
        });
      });

      socket.on('close', () => {
        logger.debug('Socket closed', {
          connectionPool: {
            serviceName
          }
        });
      });

      socket.on('error', (error) => {
        logger.warn('Socket error', {
          connectionPool: {
            serviceName,
            error: error.message
          }
        });
      });
    });

    return {
      agent,
      axios: axiosInstance,
      serviceName,
      serviceUrl,
      createdAt: new Date(),
      stats: {
        requests: 0,
        errors: 0,
        timeouts: 0
      }
    };
  }

  updatePoolMetrics(serviceName, agent) {
    // Update connection pool metrics
    const sockets = agent.sockets;
    const freeSockets = agent.freeSockets;
    
    let totalSockets = 0;
    let totalFreeSockets = 0;
    
    for (const [host, socketArray] of Object.entries(sockets)) {
      totalSockets += socketArray.length;
    }
    
    for (const [host, socketArray] of Object.entries(freeSockets)) {
      totalFreeSockets += socketArray.length;
    }

    this.connectionPoolGauge.set(
      { service_name: serviceName, type: 'active' },
      totalSockets
    );
    
    this.connectionPoolGauge.set(
      { service_name: serviceName, type: 'free' },
      totalFreeSockets
    );

    const usage = this.config.maxSockets > 0 ? 
      (totalSockets / this.config.maxSockets) * 100 : 0;
    
    this.connectionPoolUsageGauge.set(
      { service_name: serviceName },
      usage
    );
  }

  // Make HTTP request using connection pool
  async makeRequest(serviceName, requestConfig) {
    const pool = this.pools.get(serviceName);
    if (!pool) {
      throw new Error(`No connection pool found for service: ${serviceName}`);
    }

    const startTime = Date.now();
    pool.stats.requests++;

    try {
      const response = await pool.axios.request(requestConfig);
      
      const duration = Date.now() - startTime;
      logger.debug('Pooled request completed', {
        connectionPool: {
          serviceName,
          method: requestConfig.method || 'GET',
          path: requestConfig.url || requestConfig.path,
          statusCode: response.status,
          duration
        }
      });

      return response;

    } catch (error) {
      pool.stats.errors++;
      
      if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
        pool.stats.timeouts++;
      }

      const duration = Date.now() - startTime;
      logger.error('Pooled request failed', {
        connectionPool: {
          serviceName,
          method: requestConfig.method || 'GET',
          path: requestConfig.url || requestConfig.path,
          error: error.message,
          duration
        }
      }, error);

      throw error;
    }
  }

  // Get connection pool statistics
  getPoolStats(serviceName) {
    const pool = this.pools.get(serviceName);
    if (!pool) {
      return null;
    }

    const agent = pool.agent;
    const sockets = agent.sockets;
    const freeSockets = agent.freeSockets;
    
    let totalSockets = 0;
    let totalFreeSockets = 0;
    const socketDetails = {};
    
    for (const [host, socketArray] of Object.entries(sockets)) {
      totalSockets += socketArray.length;
      socketDetails[host] = {
        active: socketArray.length,
        free: freeSockets[host] ? freeSockets[host].length : 0
      };
    }
    
    for (const [host, socketArray] of Object.entries(freeSockets)) {
      totalFreeSockets += socketArray.length;
      if (!socketDetails[host]) {
        socketDetails[host] = {
          active: 0,
          free: socketArray.length
        };
      }
    }

    return {
      serviceName,
      serviceUrl: pool.serviceUrl,
      createdAt: pool.createdAt,
      configuration: {
        maxSockets: this.config.maxSockets,
        maxFreeSockets: this.config.maxFreeSockets,
        keepAlive: this.config.keepAlive,
        timeout: this.config.timeout
      },
      sockets: {
        total: totalSockets,
        free: totalFreeSockets,
        usage: this.config.maxSockets > 0 ? 
          (totalSockets / this.config.maxSockets) * 100 : 0,
        details: socketDetails
      },
      requests: pool.stats
    };
  }

  // Get all pool statistics
  getAllStats() {
    const poolStats = {};
    
    for (const [serviceName] of this.pools) {
      poolStats[serviceName] = this.getPoolStats(serviceName);
    }

    return {
      global: {
        totalPools: this.pools.size,
        configuration: this.config,
        stats: this.stats
      },
      pools: poolStats
    };
  }

  // Health check for connection pools
  async healthCheck() {
    const results = {};
    
    for (const [serviceName, pool] of this.pools) {
      try {
        const startTime = Date.now();
        const response = await pool.axios.get('/health', { timeout: 5000 });
        const duration = Date.now() - startTime;
        
        results[serviceName] = {
          healthy: response.status === 200,
          responseTime: duration,
          statusCode: response.status,
          error: null
        };
        
      } catch (error) {
        results[serviceName] = {
          healthy: false,
          responseTime: null,
          statusCode: null,
          error: error.message
        };
      }
    }

    return results;
  }

  // Cleanup idle connections
  cleanupIdleConnections() {
    for (const [serviceName, pool] of this.pools) {
      const agent = pool.agent;
      
      // Clean up free sockets that have been idle too long
      for (const [host, sockets] of Object.entries(agent.freeSockets)) {
        const now = Date.now();
        const socketsToRemove = [];
        
        for (let i = 0; i < sockets.length; i++) {
          const socket = sockets[i];
          const idleTime = now - (socket._idleStart || now);
          
          if (idleTime > this.config.freeSocketTimeout) {
            socketsToRemove.push(i);
          }
        }
        
        // Remove idle sockets in reverse order to maintain array indices
        socketsToRemove.reverse().forEach(index => {
          const socket = sockets[index];
          socket.destroy();
          sockets.splice(index, 1);
        });
        
        if (socketsToRemove.length > 0) {
          logger.debug('Cleaned up idle connections', {
            connectionPool: {
              serviceName,
              host,
              removedConnections: socketsToRemove.length
            }
          });
        }
      }
    }
  }

  // Setup cleanup interval
  setupCleanupInterval() {
    const cleanupInterval = parseInt(process.env.CONNECTION_CLEANUP_INTERVAL) || 60000; // 1 minute
    
    setInterval(() => {
      this.cleanupIdleConnections();
    }, cleanupInterval);
  }

  // Gracefully close all connection pools
  async closeAllPools() {
    const closePromises = [];
    
    for (const [serviceName, pool] of this.pools) {
      closePromises.push(this.closePool(serviceName));
    }
    
    await Promise.all(closePromises);
    this.pools.clear();
    
    logger.info('All connection pools closed');
  }

  async closePool(serviceName) {
    const pool = this.pools.get(serviceName);
    if (!pool) {
      return;
    }

    return new Promise((resolve) => {
      const agent = pool.agent;
      
      // Close all active sockets
      for (const [host, sockets] of Object.entries(agent.sockets)) {
        sockets.forEach(socket => {
          socket.end();
        });
      }
      
      // Close all free sockets
      for (const [host, sockets] of Object.entries(agent.freeSockets)) {
        sockets.forEach(socket => {
          socket.destroy();
        });
      }

      // Clean up the agent
      agent.destroy();
      
      this.pools.delete(serviceName);
      
      logger.info('Connection pool closed', {
        connectionPool: {
          serviceName
        }
      });
      
      resolve();
    });
  }

  // Express middleware to use connection pools
  middleware() {
    return (req, res, next) => {
      // Add connection pool methods to request
      req.connectionPool = {
        makeRequest: (serviceName, requestConfig) => {
          return this.makeRequest(serviceName, requestConfig);
        },
        getStats: (serviceName) => {
          return this.getPoolStats(serviceName);
        }
      };
      
      next();
    };
  }

  // Express routes for connection pool management
  getPoolRoutes() {
    const router = require('express').Router();

    // Get all pool statistics
    router.get('/stats', (req, res) => {
      const stats = this.getAllStats();
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

    // Get specific pool statistics
    router.get('/stats/:serviceName', (req, res) => {
      const { serviceName } = req.params;
      const stats = this.getPoolStats(serviceName);
      
      if (!stats) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'POOL_NOT_FOUND',
            message: `Connection pool for service '${serviceName}' not found`
          }
        });
      }

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

    // Health check all pools
    router.get('/health', async (req, res) => {
      try {
        const results = await this.healthCheck();
        const overallHealthy = Object.values(results).every(result => result.healthy);
        
        res.status(overallHealthy ? 200 : 503).json({
          success: true,
          data: {
            healthy: overallHealthy,
            pools: results
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          error: {
            code: 'HEALTH_CHECK_FAILED',
            message: 'Failed to perform health check on connection pools'
          }
        });
      }
    });

    // Cleanup idle connections
    router.post('/cleanup', (req, res) => {
      this.cleanupIdleConnections();
      res.json({
        success: true,
        data: {
          message: 'Idle connection cleanup triggered'
        }
      });
    });

    // Close specific pool
    router.delete('/:serviceName', async (req, res) => {
      const { serviceName } = req.params;
      
      if (!this.pools.has(serviceName)) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'POOL_NOT_FOUND',
            message: `Connection pool for service '${serviceName}' not found`
          }
        });
      }

      await this.closePool(serviceName);
      
      res.json({
        success: true,
        data: {
          message: `Connection pool for service '${serviceName}' closed`
        }
      });
    });

    // Update pool configuration
    router.patch('/config', (req, res) => {
      const { maxSockets, maxFreeSockets, timeout, keepAlive } = req.body;
      
      if (maxSockets !== undefined) this.config.maxSockets = maxSockets;
      if (maxFreeSockets !== undefined) this.config.maxFreeSockets = maxFreeSockets;
      if (timeout !== undefined) this.config.timeout = timeout;
      if (keepAlive !== undefined) this.config.keepAlive = keepAlive;
      
      res.json({
        success: true,
        data: {
          configuration: this.config,
          message: 'Configuration updated. New pools will use updated settings.'
        }
      });
    });

    return router;
  }
}

module.exports = ConnectionPoolManager;