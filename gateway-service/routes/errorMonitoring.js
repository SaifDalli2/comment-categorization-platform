// gateway-service/routes/errorMonitoring.js
const express = require('express');
const errorResponses = require('../utils/errorResponses');

class ErrorMonitoringRoutes {
  constructor(errorHandler) {
    this.router = express.Router();
    this.errorHandler = errorHandler;
    this.setupRoutes();
  }

  setupRoutes() {
    // Error statistics endpoint
    this.router.get('/api/monitoring/errors', (req, res) => {
      try {
        const errorStats = this.errorHandler.getErrorStats();
        const errorPatterns = errorResponses.getErrorPatterns();
        
        res.json({
          success: true,
          data: {
            statistics: errorStats,
            patterns: errorPatterns,
            timestamp: new Date().toISOString()
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve error statistics');
      }
    });

    // Error patterns by path
    this.router.get('/api/monitoring/errors/paths', (req, res) => {
      try {
        const errorStats = this.errorHandler.getErrorStats();
        
        // Calculate error rates by path
        const pathAnalysis = Object.entries(errorStats.errorRates).map(([path, stats]) => ({
          path,
          totalRequests: stats.total,
          errorCount: stats.errors,
          serverErrorCount: stats.serverErrors,
          errorRate: (stats.errors / stats.total * 100).toFixed(2) + '%',
          serverErrorRate: (stats.serverErrors / stats.total * 100).toFixed(2) + '%',
          status: this.getPathHealthStatus(stats),
          lastWindow: stats.windowStart
        })).sort((a, b) => parseFloat(b.errorRate) - parseFloat(a.errorRate));

        res.json({
          success: true,
          data: {
            paths: pathAnalysis,
            summary: {
              totalPaths: pathAnalysis.length,
              healthyPaths: pathAnalysis.filter(p => p.status === 'healthy').length,
              warningPaths: pathAnalysis.filter(p => p.status === 'warning').length,
              criticalPaths: pathAnalysis.filter(p => p.status === 'critical').length
            }
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve path error analysis');
      }
    });

    // Error rate trends (last 24 hours simulation)
    this.router.get('/api/monitoring/errors/trends', (req, res) => {
      try {
        const { timeframe = '1h' } = req.query;
        
        // For now, return current error rates
        // In production, this would query a time-series database
        const errorStats = this.errorHandler.getErrorStats();
        
        const trends = {
          timeframe,
          dataPoints: Object.entries(errorStats.errorRates).map(([path, stats]) => ({
            timestamp: stats.windowStart,
            path,
            errorRate: stats.errors / stats.total,
            serverErrorRate: stats.serverErrors / stats.total,
            totalRequests: stats.total
          })),
          aggregated: {
            totalRequests: Object.values(errorStats.errorRates).reduce((sum, stats) => sum + stats.total, 0),
            totalErrors: Object.values(errorStats.errorRates).reduce((sum, stats) => sum + stats.errors, 0),
            totalServerErrors: Object.values(errorStats.errorRates).reduce((sum, stats) => sum + stats.serverErrors, 0)
          }
        };

        trends.aggregated.overallErrorRate = trends.aggregated.totalRequests > 0 
          ? (trends.aggregated.totalErrors / trends.aggregated.totalRequests * 100).toFixed(2) + '%'
          : '0%';

        res.json({
          success: true,
          data: trends,
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve error trends');
      }
    });

    // Error details by category
    this.router.get('/api/monitoring/errors/categories', (req, res) => {
      try {
        const patterns = errorResponses.getErrorPatterns();
        
        const categoryDetails = Object.entries(patterns.categories).map(([category, errorKeys]) => ({
          category,
          errorCount: errorKeys.length,
          errorTypes: errorKeys,
          description: this.getCategoryDescription(category),
          severity: this.getCategorySeverity(category)
        }));

        res.json({
          success: true,
          data: {
            categories: categoryDetails,
            summary: {
              totalCategories: categoryDetails.length,
              totalErrorTypes: patterns.totalErrors,
              statusCodeDistribution: patterns.statusCodes
            }
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve error categories');
      }
    });

    // Trigger test error (development only)
    if (process.env.NODE_ENV === 'development') {
      this.router.post('/api/monitoring/errors/test/:errorType', (req, res) => {
        const { errorType } = req.params;
        const { message, details } = req.body;
        
        // Test different error types
        switch (errorType) {
          case 'validation':
            return res.error.validation(details || 'Test validation error');
          case 'unauthorized':
            return res.error.unauthorized(message || 'Test unauthorized error');
          case 'forbidden':
            return res.error.forbidden(message || 'Test forbidden error');
          case 'notfound':
            return res.error.notFound(message || 'Test not found error');
          case 'ratelimit':
            return res.error.rateLimit('general');
          case 'service':
            return res.error.serviceError('test-service', 'unavailable');
          case 'internal':
            return res.error.send('INTERNAL_ERROR', message || 'Test internal error');
          default:
            return res.error.validation('Invalid error type for testing');
        }
      });
    }

    // Health check for error monitoring system
    this.router.get('/api/monitoring/errors/health', (req, res) => {
      try {
        const errorStats = this.errorHandler.getErrorStats();
        
        const health = {
          status: 'healthy',
          errorHandler: {
            tracking: errorStats.totalPaths > 0,
            thresholds: errorStats.thresholds,
            activePaths: errorStats.totalPaths
          },
          errorResponses: {
            patterns: errorResponses.getErrorPatterns().totalErrors,
            categories: Object.keys(errorResponses.getErrorPatterns().categories).length
          }
        };

        // Check for any critical error rates
        const criticalPaths = Object.values(errorStats.errorRates).filter(stats => 
          stats.total > 10 && (stats.serverErrors / stats.total) > errorStats.thresholds.critical
        );

        if (criticalPaths.length > 0) {
          health.status = 'degraded';
          health.issues = [`${criticalPaths.length} paths with critical error rates`];
        }

        res.json({
          status: health.status,
          timestamp: new Date().toISOString(),
          service: 'gateway-error-monitoring',
          details: health
        });
      } catch (error) {
        res.status(503).json({
          status: 'unhealthy',
          timestamp: new Date().toISOString(),
          service: 'gateway-error-monitoring',
          error: error.message
        });
      }
    });
  }

  // Determine path health status based on error rates
  getPathHealthStatus(stats) {
    if (stats.total < 10) return 'insufficient_data';
    
    const errorRate = stats.errors / stats.total;
    const serverErrorRate = stats.serverErrors / stats.total;
    
    if (serverErrorRate > 0.15 || errorRate > 0.5) return 'critical';
    if (serverErrorRate > 0.05 || errorRate > 0.2) return 'warning';
    return 'healthy';
  }

  // Get category descriptions
  getCategoryDescription(category) {
    const descriptions = {
      authentication: 'Errors related to user authentication and token validation',
      authorization: 'Errors related to user permissions and access control',
      validation: 'Errors related to request validation and input formatting',
      rate_limiting: 'Errors related to rate limiting and request throttling',
      service: 'Errors related to downstream service availability and communication',
      resource: 'Errors related to resource availability and routing',
      cors: 'Errors related to Cross-Origin Resource Sharing policies',
      server: 'Internal server errors and configuration issues'
    };
    
    return descriptions[category] || 'Unknown error category';
  }

  // Get category severity levels
  getCategorySeverity(category) {
    const severities = {
      authentication: 'medium',
      authorization: 'high',
      validation: 'low',
      rate_limiting: 'medium',
      service: 'high',
      resource: 'low',
      cors: 'medium',
      server: 'critical'
    };
    
    return severities[category] || 'medium';
  }

  // Get the router instance
  getRouter() {
    return this.router;
  }
}

module.exports = ErrorMonitoringRoutes;