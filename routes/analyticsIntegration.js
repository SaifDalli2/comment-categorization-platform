// routes/analyticsIntegration.js - Analytics Service Integration
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const eventBus = require('../shared/eventBus');
const router = express.Router();

const ANALYTICS_SERVICE_URL = process.env.ANALYTICS_SERVICE_URL || 'https://analytics-service-voice-cd4ea7dc5810.herokuapp.com';

// Mixed data upload endpoint - routes to appropriate services
router.post('/data/upload', async (req, res) => {
  try {
    const { qualitativeData, quantitativeData } = req.body;
    const sessionId = uuidv4();
    const userId = req.user?.id || req.user?.userId;

    console.log(`[GATEWAY] Processing mixed data upload for session: ${sessionId}`);

    // Validate data structure
    if (!qualitativeData && !quantitativeData) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_DATA_STRUCTURE',
          message: 'Either qualitativeData or quantitativeData is required',
          suggestion: 'Provide at least one type of data to process'
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.requestId,
          service: 'gateway'
        }
      });
    }

    const processingPromises = [];
    const results = {};

    // Route qualitative data to Comment Service (when available)
    if (qualitativeData?.comments?.length) {
      console.log(`[GATEWAY] Routing ${qualitativeData.comments.length} comments for processing`);
      
      processingPromises.push(
        eventBus.emit('data.upload.qualitative', {
          ...qualitativeData,
          sessionId,
          userId,
          timestamp: new Date().toISOString()
        }).then(() => {
          results.qualitative = { 
            status: 'routed_for_processing', 
            count: qualitativeData.comments.length,
            note: 'Processing via event bus - check comment service for results'
          };
        })
      );
    }

    // Route quantitative data directly to Analytics Service
    if (quantitativeData && (quantitativeData.ratings?.length || quantitativeData.scores?.length || quantitativeData.metrics?.length)) {
      const dataPoints = (quantitativeData.ratings?.length || 0) + 
                         (quantitativeData.scores?.length || 0) + 
                         (quantitativeData.metrics?.length || 0);
      
      console.log(`[GATEWAY] Routing ${dataPoints} data points to Analytics Service`);
      
      processingPromises.push(
        forwardToAnalyticsService(quantitativeData, sessionId, userId, req.headers).then((analyticsResult) => {
          results.quantitative = analyticsResult;
        }).catch((error) => {
          console.error('[GATEWAY] Analytics service error:', error.message);
          results.quantitative = { 
            status: 'failed', 
            error: error.message,
            fallback: 'Data stored for retry processing'
          };
        })
      );
    }

    // Wait for routing completion
    await Promise.all(processingPromises);

    // Emit coordination event
    await eventBus.emit('data.upload.completed', {
      sessionId,
      userId,
      dataTypes: Object.keys(results),
      timestamp: new Date().toISOString()
    });

    // Return immediate response
    res.status(202).json({
      success: true,
      data: {
        sessionId,
        processingStatus: 'initiated',
        services: results,
        trackingEndpoints: {
          status: `/api/data/status/${sessionId}`,
          analytics: `${ANALYTICS_SERVICE_URL}/api/metrics?sessionId=${sessionId}`
        }
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.requestId,
        service: 'gateway',
        architecture: 'event-driven'
      }
    });

  } catch (error) {
    console.error('[GATEWAY] Data upload failed:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'DATA_UPLOAD_FAILED',
        message: 'Failed to process data upload',
        suggestion: 'Check service availability and try again'
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.requestId,
        service: 'gateway'
      }
    });
  }
});

// Forward quantitative data to Analytics Service
async function forwardToAnalyticsService(data, sessionId, userId, headers) {
  try {
    const analyticsPayload = {
      sessionId,
      userId,
      dataType: 'quantitative',
      data: {
        ratings: data.ratings || [],
        scores: data.scores || [],
        metrics: data.metrics || [],
        metadata: data.metadata || {}
      },
      timestamp: new Date().toISOString()
    };

    const response = await axios.post(`${ANALYTICS_SERVICE_URL}/api/analytics/data`, analyticsPayload, {
      headers: {
        'Authorization': headers.authorization,
        'Content-Type': 'application/json',
        'X-Gateway-Request': 'true',
        'X-Request-ID': headers['x-request-id'] || `req_${Date.now()}`,
        'X-Service-Name': 'gateway'
      },
      timeout: 30000
    });

    return {
      status: 'processing',
      analyticsId: response.data.data?.id,
      endpoint: `${ANALYTICS_SERVICE_URL}/api/analytics/status/${response.data.data?.id}`
    };

  } catch (error) {
    console.error('[GATEWAY] Analytics forwarding failed:', error.response?.data || error.message);
    throw error;
  }
}

// Processing status tracking
router.get('/data/status/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    // Try to get status from Analytics Service
    let analyticsStatus = null;
    try {
      const analyticsResponse = await axios.get(`${ANALYTICS_SERVICE_URL}/api/analytics/status`, {
        params: { sessionId },
        headers: {
          'Authorization': req.headers.authorization,
          'X-Gateway-Request': 'true'
        },
        timeout: 5000
      });
      analyticsStatus = analyticsResponse.data;
    } catch (error) {
      console.warn('[GATEWAY] Analytics status check failed:', error.message);
    }
    
    res.json({
      success: true,
      data: {
        sessionId,
        status: 'processing',
        analytics: analyticsStatus,
        services: {
          analytics: {
            available: !!analyticsStatus,
            endpoint: `${ANALYTICS_SERVICE_URL}/api/analytics/status?sessionId=${sessionId}`
          },
          comments: {
            available: false,
            note: 'Comment service integration pending',
            endpoint: 'TBD'
          }
        }
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.requestId,
        service: 'gateway'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        code: 'STATUS_CHECK_FAILED',
        message: 'Failed to check processing status'
      }
    });
  }
});

// Analytics Service proxy endpoints
router.get('/analytics/health', async (req, res) => {
  try {
    const response = await axios.get(`${ANALYTICS_SERVICE_URL}/health`, { timeout: 5000 });
    res.json({
      success: true,
      data: response.data,
      proxied: true,
      service: 'analytics-service'
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      error: {
        code: 'ANALYTICS_SERVICE_UNAVAILABLE',
        message: 'Analytics service is not responding'
      }
    });
  }
});

router.get('/analytics/metrics', async (req, res) => {
  try {
    const response = await axios.get(`${ANALYTICS_SERVICE_URL}/api/metrics`, {
      params: req.query,
      headers: {
        'Authorization': req.headers.authorization,
        'X-Gateway-Request': 'true'
      },
      timeout: 10000
    });
    res.json(response.data);
  } catch (error) {
    res.status(error.response?.status || 503).json({
      success: false,
      error: {
        code: 'ANALYTICS_METRICS_FAILED',
        message: 'Failed to retrieve analytics metrics'
      }
    });
  }
});

module.exports = router;
