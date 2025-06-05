// gateway-service/services/HealthDiagnostics.js
const axios = require('axios');
const config = require('../config/simple');
const logger = require('../utils/simpleLogger');

class HealthDiagnostics {
  constructor() {
    this.services = config.services;
    this.healthHistory = new Map();
    this.maxHistoryEntries = 10;
    this.checkTimeout = 8000;
    this.startTime = Date.now();
  }

  // Comprehensive health check for all services
  async performCompleteHealthCheck() {
    const checkId = `health_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    const startTime = Date.now();

    logger.info(`Starting comprehensive health check`, { checkId });

    const results = {
      checkId,
      timestamp: new Date().toISOString(),
      gateway: await this.checkGatewayHealth(),
      services: {},
      summary: {},
      recommendations: [],
      performance: {
        totalCheckTime: 0,
        fastestService: null,
        slowestService: null,
        averageResponseTime: 0
      }
    };

    // Check all services in parallel for faster results
    const serviceChecks = Object.entries(this.services).map(async ([serviceName, serviceUrl]) => {
      const serviceResult = await this.checkServiceHealth(serviceName, serviceUrl);
      results.services[serviceName] = serviceResult;
      return { serviceName, ...serviceResult };
    });

    const serviceResults = await Promise.all(serviceChecks);
    
    // Calculate performance metrics
    results.performance = this.calculatePerformanceMetrics(serviceResults);
    results.summary = this.generateHealthSummary(results);
    results.recommendations = this.generateRecommendations(results);
    
    const totalTime = Date.now() - startTime;
    results.performance.totalCheckTime = totalTime;

    // Store in history
    this.addToHistory(checkId, results);

    logger.info(`Health check completed`, { 
      checkId, 
      totalTime, 
      healthyServices: results.summary.healthyServices,
      totalServices: results.summary.totalServices 
    });

    return results;
  }

  // Check gateway's own health
  async checkGatewayHealth() {
    const startTime = Date.now();
    
    try {
      const memUsage = process.memoryUsage();
      const cpuUsage = process.cpuUsage();
      
      return {
        status: 'healthy',
        uptime: Math.floor((Date.now() - this.startTime) / 1000),
        version: process.env.npm_package_version || '1.0.1',
        nodeVersion: process.version,
        environment: process.env.NODE_ENV || 'development',
        port: config.port,
        pid: process.pid,
        responseTime: Date.now() - startTime,
        resources: {
          memory: {
            rss: Math.round(memUsage.rss / 1024 / 1024),
            heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
            heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
            external: Math.round(memUsage.external / 1024 / 1024)
          },
          cpu: {
            user: cpuUsage.user,
            system: cpuUsage.system
          },
          loadAverage: require('os').loadavg()
        },
        features: {
          authEnabled: !!config.security.jwtSecret,
          corsEnabled: config.security.corsOrigins.length > 0,
          rateLimitingEnabled: true,
          healthMonitoringEnabled: true
        }
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        responseTime: Date.now() - startTime
      };
    }
  }

  // Check individual service health with comprehensive diagnostics
  async checkServiceHealth(serviceName, serviceUrl) {
    const startTime = Date.now();
    const result = {
      name: serviceName,
      url: serviceUrl,
      status: 'unknown',
      timestamp: new Date().toISOString(),
      responseTime: 0,
      checks: {
        connectivity: false,
        healthEndpoint: false,
        responseFormat: false,
        performance: false
      },
      details: {},
      errors: []
    };

    try {
      // Skip placeholder URLs
      if (serviceUrl.includes('your-') || serviceUrl.includes('localhost')) {
        result.status = 'not_configured';
        result.checks.connectivity = false;
        result.details.message = 'Service URL not configured for this environment';
        result.responseTime = Date.now() - startTime;
        return result;
      }

      // Test basic connectivity
      const response = await axios.get(`${serviceUrl}/health`, {
        timeout: this.checkTimeout,
        headers: {
          'User-Agent': 'Gateway-Health-Diagnostics/1.0',
          'X-Health-Check': 'true',
          'X-Request-ID': `health_${serviceName}_${Date.now()}`
        },
        validateStatus: () => true // Accept any status code
      });

      result.responseTime = Date.now() - startTime;
      result.checks.connectivity = true;

      // Analyze response
      const statusCode = response.status;
      const responseData = response.data;

      // Check if health endpoint responded correctly
      if (statusCode === 200) {
        result.checks.healthEndpoint = true;
        result.status = 'healthy';
      } else if (statusCode >= 500) {
        result.status = 'unhealthy';
        result.errors.push(`Server error: HTTP ${statusCode}`);
      } else if (statusCode === 404) {
        result.status = 'degraded';
        result.errors.push('Health endpoint not found');
      } else {
        result.status = 'degraded';
        result.errors.push(`Unexpected status code: ${statusCode}`);
      }

      // Validate response format
      if (responseData && typeof responseData === 'object') {
        result.checks.responseFormat = true;
        
        // Extract service information from response
        result.details = {
          serviceStatus: responseData.status,
          version: responseData.version,
          uptime: responseData.uptime,
          environment: responseData.environment,
          dependencies: responseData.dependencies,
          features: responseData.features,
          database: responseData.database,
          sharedKnowledgeVersion: responseData.sharedKnowledgeVersion
        };

        // Enhanced status detection
        if (responseData.status === 'healthy' || responseData.status === 'ok') {
          result.status = 'healthy';
        } else if (responseData.status === 'degraded' || responseData.status === 'warning') {
          result.status = 'degraded';
          if (responseData.message) {
            result.errors.push(responseData.message);
          }
        } else if (responseData.status === 'unhealthy' || responseData.status === 'error') {
          result.status = 'unhealthy';
          if (responseData.error) {
            result.errors.push(responseData.error);
          }
        }

        // Check for dependency issues
        if (responseData.dependencies) {
          const unhealthyDeps = Object.entries(responseData.dependencies)
            .filter(([, status]) => status !== 'healthy' && status !== 'ok')
            .map(([name]) => name);
          
          if (unhealthyDeps.length > 0) {
            result.status = 'degraded';
            result.errors.push(`Unhealthy dependencies: ${unhealthyDeps.join(', ')}`);
          }
        }
      } else {
        result.checks.responseFormat = false;
        result.errors.push('Invalid response format (expected JSON object)');
      }

      // Performance check
      if (result.responseTime < 1000) {
        result.checks.performance = true;
      } else if (result.responseTime < 5000) {
        result.errors.push(`Slow response time: ${result.responseTime}ms`);
      } else {
        result.status = 'degraded';
        result.errors.push(`Very slow response time: ${result.responseTime}ms`);
      }

      // Additional service-specific checks
      result.diagnostics = await this.performServiceSpecificChecks(serviceName, serviceUrl, response);

    } catch (error) {
      result.responseTime = Date.now() - startTime;
      result.status = 'unreachable';
      result.checks.connectivity = false;
      
      // Categorize the error
      if (error.code === 'ECONNREFUSED') {
        result.errors.push('Connection refused - service may be down');
      } else if (error.code === 'ENOTFOUND') {
        result.errors.push('DNS resolution failed - invalid hostname');
      } else if (error.code === 'ETIMEDOUT') {
        result.errors.push(`Request timeout after ${this.checkTimeout}ms`);
      } else if (error.response) {
        result.errors.push(`HTTP error: ${error.response.status} ${error.response.statusText}`);
      } else {
        result.errors.push(`Network error: ${error.message}`);
      }

      logger.warn(`Health check failed for ${serviceName}`, {
        error: error.message,
        code: error.code,
        responseTime: result.responseTime
      });
    }

    return result;
  }

  // Service-specific diagnostic checks
  async performServiceSpecificChecks(serviceName, serviceUrl, healthResponse) {
    const diagnostics = {
      serviceType: serviceName,
      complianceChecks: {
        sharedKnowledgeCompliant: false,
        apiStandardsCompliant: false,
        authenticationSupported: false
      },
      serviceSpecific: {}
    };

    try {
      const data = healthResponse.data;

      // Check shared knowledge compliance
      if (data.sharedKnowledgeVersion || data.version) {
        diagnostics.complianceChecks.sharedKnowledgeCompliant = true;
      }

      // Check API standards compliance
      if (data.timestamp && data.service) {
        diagnostics.complianceChecks.apiStandardsCompliant = true;
      }

      // Service-specific checks
      switch (serviceName) {
        case 'auth':
          diagnostics.serviceSpecific = await this.checkAuthServiceSpecifics(serviceUrl);
          break;
        case 'comment':
          diagnostics.serviceSpecific = await this.checkCommentServiceSpecifics(serviceUrl);
          break;
        case 'industry':
          diagnostics.serviceSpecific = await this.checkIndustryServiceSpecifics(serviceUrl);
          break;
        case 'analytics':
          diagnostics.serviceSpecific = await this.checkAnalyticsServiceSpecifics(serviceUrl);
          break;
        default:
          diagnostics.serviceSpecific.note = 'No specific checks defined for this service';
      }

    } catch (error) {
      diagnostics.error = `Diagnostic check failed: ${error.message}`;
    }

    return diagnostics;
  }

  // Auth service specific checks
  async checkAuthServiceSpecifics(serviceUrl) {
    try {
      // Check if JWT verification endpoint exists
      const verifyResponse = await axios.post(`${serviceUrl}/api/auth/verify`, {}, {
        timeout: 3000,
        validateStatus: () => true
      });

      return {
        jwtVerificationEndpoint: verifyResponse.status !== 404,
        expectedFeatures: ['user authentication', 'JWT tokens', 'user management']
      };
    } catch (error) {
      return {
        error: `Auth service check failed: ${error.message}`,
        jwtVerificationEndpoint: false
      };
    }
  }

  // Comment service specific checks
  async checkCommentServiceSpecifics(serviceUrl) {
    try {
      // Check if categorization endpoint exists
      const categorizeResponse = await axios.post(`${serviceUrl}/api/comments/categorize`, {}, {
        timeout: 3000,
        validateStatus: () => true
      });

      return {
        categorizationEndpoint: categorizeResponse.status !== 404,
        mongoDbCompliance: 'requires verification',
        expectedFeatures: ['comment processing', 'categorization', 'MongoDB integration']
      };
    } catch (error) {
      return {
        error: `Comment service check failed: ${error.message}`,
        categorizationEndpoint: false
      };
    }
  }

  // Industry service specific checks
  async checkIndustryServiceSpecifics(serviceUrl) {
    try {
      // Check if industries endpoint exists
      const industriesResponse = await axios.get(`${serviceUrl}/api/v1/industries`, {
        timeout: 3000,
        validateStatus: () => true
      });

      return {
        industriesEndpoint: industriesResponse.status !== 404,
        dataAvailable: industriesResponse.status === 200 && industriesResponse.data,
        expectedFeatures: ['industry classification', 'hierarchical data', 'categorization']
      };
    } catch (error) {
      return {
        error: `Industry service check failed: ${error.message}`,
        industriesEndpoint: false
      };
    }
  }

  // Analytics service specific checks
  async checkAnalyticsServiceSpecifics(serviceUrl) {
    try {
      // Check if analytics endpoints exist
      const eventsResponse = await axios.post(`${serviceUrl}/api/analytics/events`, {}, {
        timeout: 3000,
        validateStatus: () => true
      });

      return {
        eventsEndpoint: eventsResponse.status !== 404,
        conditionalCompliance: 'pending UUID migration',
        expectedFeatures: ['event collection', 'real-time processing', 'PostgreSQL + Redis']
      };
    } catch (error) {
      return {
        error: `Analytics service check failed: ${error.message}`,
        eventsEndpoint: false
      };
    }
  }

  // Calculate performance metrics
  calculatePerformanceMetrics(serviceResults) {
    const healthyServices = serviceResults.filter(s => s.status === 'healthy');
    const responseTimes = healthyServices.map(s => s.responseTime).filter(t => t > 0);

    if (responseTimes.length === 0) {
      return {
        fastestService: null,
        slowestService: null,
        averageResponseTime: 0
      };
    }

    const fastest = healthyServices.find(s => s.responseTime === Math.min(...responseTimes));
    const slowest = healthyServices.find(s => s.responseTime === Math.max(...responseTimes));
    const average = responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length;

    return {
      fastestService: fastest ? { name: fastest.serviceName, time: fastest.responseTime } : null,
      slowestService: slowest ? { name: slowest.serviceName, time: slowest.responseTime } : null,
      averageResponseTime: Math.round(average)
    };
  }

  // Generate health summary
  generateHealthSummary(results) {
    const services = Object.values(results.services);
    const statusCounts = {
      healthy: services.filter(s => s.status === 'healthy').length,
      degraded: services.filter(s => s.status === 'degraded').length,
      unhealthy: services.filter(s => s.status === 'unhealthy').length,
      unreachable: services.filter(s => s.status === 'unreachable').length,
      not_configured: services.filter(s => s.status === 'not_configured').length
    };

    const totalServices = services.length;
    const healthyServices = statusCounts.healthy;
    const configuredServices = totalServices - statusCounts.not_configured;

    let overallStatus = 'healthy';
    if (statusCounts.unhealthy > 0 || statusCounts.unreachable > 0) {
      overallStatus = 'unhealthy';
    } else if (statusCounts.degraded > 0) {
      overallStatus = 'degraded';
    }

    return {
      overallStatus,
      gatewayStatus: results.gateway.status,
      totalServices,
      configuredServices,
      healthyServices,
      degradedServices: statusCounts.degraded,
      unhealthyServices: statusCounts.unhealthy + statusCounts.unreachable,
      notConfiguredServices: statusCounts.not_configured,
      healthPercentage: configuredServices > 0 ? Math.round((healthyServices / configuredServices) * 100) : 0,
      statusBreakdown: statusCounts
    };
  }

  // Generate actionable recommendations
  generateRecommendations(results) {
    const recommendations = [];
    const services = Object.values(results.services);

    // Gateway recommendations
    if (results.gateway.status !== 'healthy') {
      recommendations.push({
        priority: 'critical',
        type: 'gateway',
        issue: 'Gateway health check failed',
        action: 'Investigate gateway service immediately',
        service: 'gateway'
      });
    }

    // Service-specific recommendations
    services.forEach(service => {
      switch (service.status) {
        case 'unreachable':
          recommendations.push({
            priority: 'critical',
            type: 'connectivity',
            issue: `${service.name} service is unreachable`,
            action: `Check if ${service.name} service is running and accessible at ${service.url}`,
            service: service.name,
            details: service.errors
          });
          break;

        case 'unhealthy':
          recommendations.push({
            priority: 'high',
            type: 'service_health',
            issue: `${service.name} service reports unhealthy status`,
            action: `Investigate ${service.name} service logs and dependencies`,
            service: service.name,
            details: service.errors
          });
          break;

        case 'degraded':
          recommendations.push({
            priority: 'medium',
            type: 'performance',
            issue: `${service.name} service is degraded`,
            action: `Monitor ${service.name} service performance and consider scaling`,
            service: service.name,
            details: service.errors
          });
          break;

        case 'not_configured':
          if (process.env.NODE_ENV === 'production') {
            recommendations.push({
              priority: 'high',
              type: 'configuration',
              issue: `${service.name} service URL not configured`,
              action: `Configure ${service.name.toUpperCase()}_SERVICE_URL environment variable`,
              service: service.name
            });
          }
          break;
      }

      // Performance recommendations
      if (service.responseTime > 5000) {
        recommendations.push({
          priority: 'medium',
          type: 'performance',
          issue: `${service.name} service has slow response time (${service.responseTime}ms)`,
          action: `Optimize ${service.name} service performance or increase timeout`,
          service: service.name
        });
      }

      // Compliance recommendations
      if (service.diagnostics && !service.diagnostics.complianceChecks.sharedKnowledgeCompliant) {
        recommendations.push({
          priority: 'low',
          type: 'compliance',
          issue: `${service.name} service not following shared knowledge standards`,
          action: `Update ${service.name} service to include version information in health response`,
          service: service.name
        });
      }
    });

    // Overall system recommendations
    const summary = results.summary;
    if (summary.healthPercentage < 50) {
      recommendations.push({
        priority: 'critical',
        type: 'system',
        issue: 'More than half of services are unhealthy',
        action: 'Emergency system maintenance required - check infrastructure and service dependencies'
      });
    } else if (summary.healthPercentage < 80) {
      recommendations.push({
        priority: 'high',
        type: 'system',
        issue: 'System reliability below optimal threshold',
        action: 'Review service health and consider implementing automated recovery procedures'
      });
    }

    return recommendations.sort((a, b) => {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });
  }

  // Add health check result to history
  addToHistory(checkId, results) {
    this.healthHistory.set(checkId, {
      timestamp: results.timestamp,
      summary: results.summary,
      performance: results.performance
    });

    // Keep only recent entries
    if (this.healthHistory.size > this.maxHistoryEntries) {
      const oldestKey = this.healthHistory.keys().next().value;
      this.healthHistory.delete(oldestKey);
    }
  }

  // Get health check history
  getHealthHistory() {
    return Array.from(this.healthHistory.entries()).map(([checkId, data]) => ({
      checkId,
      ...data
    }));
  }

  // Get health trends
  getHealthTrends() {
    const history = this.getHealthHistory();
    if (history.length < 2) return null;

    const latest = history[history.length - 1];
    const previous = history[history.length - 2];

    return {
      healthPercentageChange: latest.summary.healthPercentage - previous.summary.healthPercentage,
      averageResponseTimeChange: latest.performance.averageResponseTime - previous.performance.averageResponseTime,
      trend: latest.summary.healthPercentage >= previous.summary.healthPercentage ? 'improving' : 'declining'
    };
  }

  // Express middleware for health diagnostics endpoint
  healthDiagnosticsEndpoint() {
    return async (req, res) => {
      try {
        const includeHistory = req.query.history === 'true';
        const includeTrends = req.query.trends === 'true';
        
        const results = await this.performCompleteHealthCheck();
        
        if (includeHistory) {
          results.history = this.getHealthHistory();
        }
        
        if (includeTrends) {
          results.trends = this.getHealthTrends();
        }

        // Determine HTTP status based on overall health
        let statusCode = 200;
        if (results.summary.overallStatus === 'unhealthy') {
          statusCode = 503; // Service Unavailable
        } else if (results.summary.overallStatus === 'degraded') {
          statusCode = 200; // OK but with warnings
        }

        res.status(statusCode).json({
          success: true,
          data: results,
          metadata: {
            timestamp: new Date().toISOString(),
            service: 'gateway',
            checkType: 'comprehensive_health_diagnostics',
            requestId: req.requestId
          }
        });

      } catch (error) {
        logger.error('Health diagnostics failed', {
          error: error.message,
          stack: error.stack,
          requestId: req.requestId
        });

        res.status(500).json({
          success: false,
          error: {
            code: 'HEALTH_CHECK_FAILED',
            message: 'Health diagnostics failed',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
          },
          metadata: {
            timestamp: new Date().toISOString(),
            service: 'gateway',
            requestId: req.requestId
          }
        });
      }
    };
  }
}

module.exports = HealthDiagnostics;