// gateway-service/middleware/circuitBreaker.js - Simple Circuit Breaker
const logger = require('../utils/simpleLogger');

class CircuitBreaker {
  constructor(serviceName, options = {}) {
    this.serviceName = serviceName;
    this.failureThreshold = options.failureThreshold || 5;
    this.resetTimeout = options.resetTimeout || 60000; // 1 minute
    this.monitoringPeriod = options.monitoringPeriod || 60000; // 1 minute
    
    // Circuit breaker states: CLOSED, OPEN, HALF_OPEN
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.nextAttemptTime = null;
    
    // Statistics
    this.stats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      circuitOpenCount: 0,
      lastStateChange: new Date().toISOString()
    };
    
    // Reset failure count periodically when circuit is closed
    this.monitoringTimer = setInterval(() => {
      if (this.state === 'CLOSED' && this.failureCount > 0) {
        this.failureCount = Math.max(0, this.failureCount - 1);
        logger.debug(`Circuit breaker ${serviceName}: failure count decremented to ${this.failureCount}`);
      }
    }, this.monitoringPeriod);
  }

  // Execute a function with circuit breaker protection
  async execute(fn) {
    this.stats.totalRequests++;
    
    // Check if circuit is open
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttemptTime) {
        const error = new Error(`Circuit breaker is OPEN for ${this.serviceName}`);
        error.code = 'CIRCUIT_BREAKER_OPEN';
        throw error;
      } else {
        // Time to try again - move to HALF_OPEN
        this.state = 'HALF_OPEN';
        this.stats.lastStateChange = new Date().toISOString();
        logger.info(`Circuit breaker ${this.serviceName}: transitioning to HALF_OPEN`);
      }
    }
    
    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure(error);
      throw error;
    }
  }

  onSuccess() {
    this.stats.successfulRequests++;
    
    if (this.state === 'HALF_OPEN') {
      // Success in HALF_OPEN state - close the circuit
      this.state = 'CLOSED';
      this.failureCount = 0;
      this.lastFailureTime = null;
      this.nextAttemptTime = null;
      this.stats.lastStateChange = new Date().toISOString();
      
      logger.info(`Circuit breaker ${this.serviceName}: closed after successful request`);
    } else if (this.state === 'CLOSED' && this.failureCount > 0) {
      // Reduce failure count on success
      this.failureCount = Math.max(0, this.failureCount - 1);
    }
  }

  onFailure(error) {
    this.stats.failedRequests++;
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    logger.warn(`Circuit breaker ${this.serviceName}: failure recorded (${this.failureCount}/${this.failureThreshold})`, {
      error: error.message,
      state: this.state
    });
    
    if (this.failureCount >= this.failureThreshold) {
      // Open the circuit
      this.state = 'OPEN';
      this.nextAttemptTime = Date.now() + this.resetTimeout;
      this.stats.circuitOpenCount++;
      this.stats.lastStateChange = new Date().toISOString();
      
      logger.error(`Circuit breaker ${this.serviceName}: OPENED due to ${this.failureCount} failures`);
    }
  }

  // Get current state and statistics
  getStats() {
    return {
      serviceName: this.serviceName,
      state: this.state,
      failureCount: this.failureCount,
      failureThreshold: this.failureThreshold,
      lastFailureTime: this.lastFailureTime,
      nextAttemptTime: this.nextAttemptTime,
      resetTimeout: this.resetTimeout,
      stats: {
        ...this.stats,
        failureRate: this.stats.totalRequests > 0 ? 
          Math.round((this.stats.failedRequests / this.stats.totalRequests) * 100) : 0
      }
    };
  }

  // Check if circuit breaker allows requests
  canExecute() {
    if (this.state === 'OPEN') {
      return Date.now() >= this.nextAttemptTime;
    }
    return true;
  }

  // Force circuit to specific state (for testing/admin)
  forceState(state) {
    if (!['CLOSED', 'OPEN', 'HALF_OPEN'].includes(state)) {
      throw new Error('Invalid circuit breaker state');
    }
    
    const oldState = this.state;
    this.state = state;
    this.stats.lastStateChange = new Date().toISOString();
    
    if (state === 'CLOSED') {
      this.failureCount = 0;
      this.lastFailureTime = null;
      this.nextAttemptTime = null;
    } else if (state === 'OPEN') {
      this.nextAttemptTime = Date.now() + this.resetTimeout;
    }
    
    logger.warn(`Circuit breaker ${this.serviceName}: forced state change from ${oldState} to ${state}`);
  }

  // Reset circuit breaker
  reset() {
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.nextAttemptTime = null;
    this.stats.lastStateChange = new Date().toISOString();
    
    logger.info(`Circuit breaker ${this.serviceName}: manually reset`);
  }

  // Cleanup
  cleanup() {
    if (this.monitoringTimer) {
      clearInterval(this.monitoringTimer);
      this.monitoringTimer = null;
    }
  }
}

// Circuit Breaker Manager - manages multiple circuit breakers
class CircuitBreakerManager {
  constructor() {
    this.breakers = new Map();
    this.defaultOptions = {
      failureThreshold: 5,
      resetTimeout: 60000,
      monitoringPeriod: 60000
    };
  }

  // Get or create circuit breaker for a service
  getBreaker(serviceName, options = {}) {
    if (!this.breakers.has(serviceName)) {
      const breakerOptions = { ...this.defaultOptions, ...options };
      const breaker = new CircuitBreaker(serviceName, breakerOptions);
      this.breakers.set(serviceName, breaker);
      
      logger.info(`Created circuit breaker for ${serviceName}`, breakerOptions);
    }
    
    return this.breakers.get(serviceName);
  }

  // Execute function with circuit breaker protection
  async execute(serviceName, fn, options = {}) {
    const breaker = this.getBreaker(serviceName, options);
    return breaker.execute(fn);
  }

  // Get stats for all circuit breakers
  getAllStats() {
    const stats = {};
    for (const [serviceName, breaker] of this.breakers.entries()) {
      stats[serviceName] = breaker.getStats();
    }
    return stats;
  }

  // Get stats for specific service
  getServiceStats(serviceName) {
    const breaker = this.breakers.get(serviceName);
    return breaker ? breaker.getStats() : null;
  }

  // Check if any circuit breakers are open
  hasOpenCircuits() {
    for (const breaker of this.breakers.values()) {
      if (breaker.state === 'OPEN') {
        return true;
      }
    }
    return false;
  }

  // Get list of open circuits
  getOpenCircuits() {
    const openCircuits = [];
    for (const [serviceName, breaker] of this.breakers.entries()) {
      if (breaker.state === 'OPEN') {
        openCircuits.push({
          serviceName,
          nextAttemptTime: breaker.nextAttemptTime,
          failureCount: breaker.failureCount
        });
      }
    }
    return openCircuits;
  }

  // Reset all circuit breakers
  resetAll() {
    for (const breaker of this.breakers.values()) {
      breaker.reset();
    }
    logger.info('All circuit breakers reset');
  }

  // Reset specific circuit breaker
  resetService(serviceName) {
    const breaker = this.breakers.get(serviceName);
    if (breaker) {
      breaker.reset();
      return true;
    }
    return false;
  }

  // Express middleware factory
  middleware(serviceName, options = {}) {
    return async (req, res, next) => {
      const breaker = this.getBreaker(serviceName, options);
      
      // Check if circuit allows request
      if (!breaker.canExecute()) {
        return res.status(503).json({
          success: false,
          error: {
            code: 'CIRCUIT_BREAKER_OPEN',
            message: `${serviceName} service is temporarily unavailable`,
            suggestion: 'Please try again later'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            service: 'gateway',
            targetService: serviceName,
            circuitState: breaker.state,
            nextAttemptTime: breaker.nextAttemptTime
          }
        });
      }
      
      // Add circuit breaker info to request
      req.circuitBreaker = breaker;
      
      next();
    };
  }

  // Cleanup all circuit breakers
  cleanup() {
    for (const breaker of this.breakers.values()) {
      breaker.cleanup();
    }
    this.breakers.clear();
    logger.info('Circuit breaker manager cleaned up');
  }
}

// Create singleton instance
const circuitBreakerManager = new CircuitBreakerManager();

module.exports = {
  CircuitBreaker,
  CircuitBreakerManager,
  manager: circuitBreakerManager
};