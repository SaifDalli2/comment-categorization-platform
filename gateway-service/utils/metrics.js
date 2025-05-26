// gateway-service/utils/metrics.js
const promClient = require('prom-client');

class MetricsCollector {
  constructor() {
    // Clear default metrics
    promClient.register.clear();
    
    // Enable default metrics collection (memory, CPU, etc.)
    promClient.collectDefaultMetrics({
      prefix: 'gateway_',
      gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5],
      register: promClient.register
    });

    this.initializeMetrics();
  }

  initializeMetrics() {
    // HTTP Request metrics
    this.httpRequestDuration = new promClient.Histogram({
      name: 'gateway_http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10]
    });

    this.httpRequestsTotal = new promClient.Counter({
      name: 'gateway_http_requests_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'route', 'status_code']
    });

    this.httpRequestSize = new promClient.Histogram({
      name: 'gateway_http_request_size_bytes',
      help: 'Size of HTTP requests in bytes',
      labelNames: ['method', 'route'],
      buckets: [100, 1000, 10000, 100000, 1000000, 10000000]
    });

    this.httpResponseSize = new promClient.Histogram({
      name: 'gateway_http_response_size_bytes',
      help: 'Size of HTTP responses in bytes',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [100, 1000, 10000, 100000, 1000000, 10000000]
    });

    // Service proxy metrics
    this.serviceRequestDuration = new promClient.Histogram({
      name: 'gateway_service_request_duration_seconds',
      help: 'Duration of service proxy requests in seconds',
      labelNames: ['service_name', 'method', 'status_code'],
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 30]
    });

    this.serviceRequestsTotal = new promClient.Counter({
      name: 'gateway_service_requests_total',
      help: 'Total number of service proxy requests',
      labelNames: ['service_name', 'method', 'status_code']
    });

    this.serviceErrorsTotal = new promClient.Counter({
      name: 'gateway_service_errors_total',
      help: 'Total number of service proxy errors',
      labelNames: ['service_name', 'error_type']
    });

    // Service health metrics
    this.serviceHealthStatus = new promClient.Gauge({
      name: 'gateway_service_health_status',
      help: 'Health status of services (1 = healthy, 0 = unhealthy)',
      labelNames: ['service_name', 'instance_id']
    });

    this.serviceHealthCheckDuration = new promClient.Histogram({
      name: 'gateway_service_health_check_duration_seconds',
      help: 'Duration of service health checks in seconds',
      labelNames: ['service_name', 'instance_id'],
      buckets: [0.001, 0.01, 0.1, 0.5, 1, 2, 5]
    });

    this.serviceHealthChecksTotal = new promClient.Counter({
      name: 'gateway_service_health_checks_total',
      help: 'Total number of service health checks',
      labelNames: ['service_name', 'instance_id', 'status']
    });

    // Authentication metrics
    this.authRequestsTotal = new promClient.Counter({
      name: 'gateway_auth_requests_total',
      help: 'Total number of authentication requests',
      labelNames: ['event', 'status']
    });

    this.authTokenCacheHits = new promClient.Counter({
      name: 'gateway_auth_token_cache_hits_total',
      help: 'Total number of authentication token cache hits'
    });

    this.authTokenCacheMisses = new promClient.Counter({
      name: 'gateway_auth_token_cache_misses_total',
      help: 'Total number of authentication token cache misses'
    });

    // Rate limiting metrics
    this.rateLimitHits = new promClient.Counter({
      name: 'gateway_rate_limit_hits_total',
      help: 'Total number of rate limit hits',
      labelNames: ['limit_type', 'path']
    });

    this.rateLimitRequests = new promClient.Counter({
      name: 'gateway_rate_limit_requests_total',
      help: 'Total number of requests checked against rate limits',
      labelNames: ['limit_type', 'path']
    });

    // CORS metrics
    this.corsRequests = new promClient.Counter({
      name: 'gateway_cors_requests_total',
      help: 'Total number of CORS requests',
      labelNames: ['origin', 'status']
    });

    this.corsPreflightRequests = new promClient.Counter({
      name: 'gateway_cors_preflight_requests_total',
      help: 'Total number of CORS preflight requests',
      labelNames: ['origin', 'method']
    });

    // Circuit breaker metrics
    this.circuitBreakerState = new promClient.Gauge({
      name: 'gateway_circuit_breaker_state',
      help: 'Circuit breaker state (0 = closed, 1 = open, 2 = half-open)',
      labelNames: ['service_name', 'instance_id']
    });

    this.circuitBreakerTrips = new promClient.Counter({
      name: 'gateway_circuit_breaker_trips_total',
      help: 'Total number of circuit breaker trips',
      labelNames: ['service_name', 'instance_id']
    });

    // Business metrics
    this.activeConnections = new promClient.Gauge({
      name: 'gateway_active_connections',
      help: 'Number of active connections'
    });

    this.serviceInstances = new promClient.Gauge({
      name: 'gateway_service_instances_total',
      help: 'Total number of service instances',
      labelNames: ['service_name', 'status']
    });

    // Custom metrics
    this.customMetrics = new Map();
  }

  // HTTP Request metrics recording
  recordHttpRequest(method, route, statusCode, duration, requestSize = 0, responseSize = 0) {
    const labels = { method, route, status_code: statusCode.toString() };
    
    this.httpRequestDuration.observe(labels, duration / 1000); // Convert to seconds
    this.httpRequestsTotal.inc(labels);
    
    if (requestSize > 0) {
      this.httpRequestSize.observe({ method, route }, requestSize);
    }
    
    if (responseSize > 0) {
      this.httpResponseSize.observe(labels, responseSize);
    }
  }

  // Service proxy metrics recording
  recordServiceRequest(serviceName, method, statusCode, duration, success = true) {
    const labels = { 
      service_name: serviceName, 
      method, 
      status_code: statusCode.toString() 
    };
    
    this.serviceRequestDuration.observe(labels, duration / 1000);
    this.serviceRequestsTotal.inc(labels);
    
    if (!success) {
      this.serviceErrorsTotal.inc({ 
        service_name: serviceName, 
        error_type: statusCode >= 500 ? 'server_error' : 'client_error' 
      });
    }
  }

  // Service health metrics recording
  recordServiceHealth(serviceName, instanceId, isHealthy, duration) {
    const healthValue = isHealthy ? 1 : 0;
    const status = isHealthy ? 'healthy' : 'unhealthy';
    
    this.serviceHealthStatus.set(
      { service_name: serviceName, instance_id: instanceId },
      healthValue
    );
    
    this.serviceHealthCheckDuration.observe(
      { service_name: serviceName, instance_id: instanceId },
      duration / 1000
    );
    
    this.serviceHealthChecksTotal.inc({
      service_name: serviceName,
      instance_id: instanceId,
      status
    });
  }

  // Authentication metrics recording
  recordAuthRequest(event, success = true) {
    const status = success ? 'success' : 'failure';
    this.authRequestsTotal.inc({ event, status });
  }

  recordAuthCacheHit() {
    this.authTokenCacheHits.inc();
  }

  recordAuthCacheMiss() {
    this.authTokenCacheMisses.inc();
  }

  // Rate limiting metrics recording
  recordRateLimit(limitType, path, wasHit = false) {
    this.rateLimitRequests.inc({ limit_type: limitType, path });
    
    if (wasHit) {
      this.rateLimitHits.inc({ limit_type: limitType, path });
    }
  }

  // CORS metrics recording
  recordCorsRequest(origin, allowed = true) {
    const status = allowed ? 'allowed' : 'blocked';
    this.corsRequests.inc({ origin: origin || 'none', status });
  }

  recordCorsPreflight(origin, method) {
    this.corsPreflightRequests.inc({ 
      origin: origin || 'none', 
      method: method || 'unknown' 
    });
  }

  // Circuit breaker metrics recording
  recordCircuitBreakerState(serviceName, instanceId, state) {
    // Convert state to numeric: closed = 0, open = 1, half-open = 2
    const stateValues = { closed: 0, open: 1, 'half-open': 2 };
    const stateValue = stateValues[state] || 0;
    
    this.circuitBreakerState.set(
      { service_name: serviceName, instance_id: instanceId },
      stateValue
    );
  }

  recordCircuitBreakerTrip(serviceName, instanceId) {
    this.circuitBreakerTrips.inc({
      service_name: serviceName,
      instance_id: instanceId
    });
  }

  // Business metrics recording
  updateActiveConnections(count) {
    this.activeConnections.set(count);
  }

  updateServiceInstanceCount(serviceName, status, count) {
    this.serviceInstances.set(
      { service_name: serviceName, status },
      count
    );
  }

  // Custom metrics
  createCustomCounter(name, help, labelNames = []) {
    const metric = new promClient.Counter({
      name: `gateway_custom_${name}`,
      help,
      labelNames
    });
    
    this.customMetrics.set(name, metric);
    return metric;
  }

  createCustomGauge(name, help, labelNames = []) {
    const metric = new promClient.Gauge({
      name: `gateway_custom_${name}`,
      help,
      labelNames
    });
    
    this.customMetrics.set(name, metric);
    return metric;
  }

  createCustomHistogram(name, help, labelNames = [], buckets = undefined) {
    const metric = new promClient.Histogram({
      name: `gateway_custom_${name}`,
      help,
      labelNames,
      buckets
    });
    
    this.customMetrics.set(name, metric);
    return metric;
  }

  getCustomMetric(name) {
    return this.customMetrics.get(name);
  }

  // Get metrics for Prometheus endpoint
  async getMetrics() {
    return await promClient.register.metrics();
  }

  // Get metrics in JSON format
  async getMetricsJSON() {
    const metrics = await promClient.register.getMetricsAsJSON();
    return metrics;
  }

  // Health check for metrics system
  isHealthy() {
    try {
      // Try to get metrics to ensure system is working
      promClient.register.getSingleMetric('gateway_http_requests_total');
      return true;
    } catch (error) {
      return false;
    }
  }

  // Reset all metrics (for testing)
  reset() {
    promClient.register.resetMetrics();
  }

  // Cleanup
  cleanup() {
    this.customMetrics.clear();
  }

  // Express middleware for automatic HTTP metrics collection
  middleware() {
    return (req, res, next) => {
      const startTime = Date.now();
      
      // Get request size
      const requestSize = parseInt(req.get('Content-Length')) || 0;
      
      // Override res.end to capture metrics
      const originalEnd = res.end;
      res.end = (...args) => {
        const responseTime = Date.now() - startTime;
        const responseSize = parseInt(res.get('Content-Length')) || 0;
        
        // Record HTTP metrics
        this.recordHttpRequest(
          req.method,
          req.route?.path || req.path || 'unknown',
          res.statusCode,
          responseTime,
          requestSize,
          responseSize
        );
        
        // Call original end method
        originalEnd.apply(res, args);
      };

      next();
    };
  }
}

// Create singleton instance
const metricsCollector = new MetricsCollector();

module.exports = metricsCollector;