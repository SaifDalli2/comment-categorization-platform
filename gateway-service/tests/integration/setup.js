// gateway-service/tests/integration/setup.js
const express = require('express');
const request = require('supertest');

// Mock service servers for integration testing
class MockServiceServer {
  constructor(name, port) {
    this.name = name;
    this.port = port;
    this.app = express();
    this.server = null;
    this.setupRoutes();
  }

  setupRoutes() {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.json({ 
        status: 'healthy', 
        service: this.name,
        timestamp: new Date().toISOString()
      });
    });

    this.app.get('/ready', (req, res) => {
      res.json({ 
        status: 'ready', 
        service: this.name,
        timestamp: new Date().toISOString()
      });
    });

    // Service-specific endpoints
    if (this.name === 'auth') {
      this.setupAuthRoutes();
    } else if (this.name === 'comment') {
      this.setupCommentRoutes();
    } else if (this.name === 'industry') {
      this.setupIndustryRoutes();
    } else if (this.name === 'nps') {
      this.setupNpsRoutes();
    }

    // Error endpoints for testing error handling
    this.app.get('/error/500', (req, res) => {
      res.status(500).json({ error: 'Internal server error' });
    });

    this.app.get('/error/timeout', (req, res) => {
      // Never respond to simulate timeout
    });

    this.app.get('/error/404', (req, res) => {
      res.status(404).json({ error: 'Not found' });
    });
  }

  setupAuthRoutes() {
    this.app.use(express.json());

    this.app.post('/api/auth/login', (req, res) => {
      const { email, password } = req.body;
      
      if (email === 'test@example.com' && password === 'password123') {
        res.json({
          success: true,
          data: {
            token: global.testUtils.generateJWT({ email, userId: 'test-user-id' }),
            user: {
              id: 'test-user-id',
              email: 'test@example.com',
              roles: ['user']
            }
          }
        });
      } else {
        res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Invalid email or password'
          }
        });
      }
    });

    this.app.get('/api/auth/verify', (req, res) => {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          error: { code: 'TOKEN_MISSING', message: 'Token required' }
        });
      }

      const token = authHeader.split(' ')[1];
      
      try {
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        res.json({
          success: true,
          data: {
            valid: true,
            user: {
              id: decoded.userId,
              email: decoded.email,
              roles: decoded.roles || ['user']
            }
          }
        });
      } catch (error) {
        res.status(401).json({
          success: false,
          error: { code: 'TOKEN_INVALID', message: 'Invalid token' }
        });
      }
    });
  }

  setupCommentRoutes() {
    this.app.use(express.json());

    this.app.post('/api/comments/categorize', (req, res) => {
      const { comments, apiKey } = req.body;
      
      if (!comments || !Array.isArray(comments)) {
        return res.status(400).json({
          success: false,
          error: { code: 'VALIDATION_ERROR', message: 'Comments array required' }
        });
      }

      if (!apiKey || !apiKey.startsWith('sk-')) {
        return res.status(401).json({
          success: false,
          error: { code: 'API_KEY_REQUIRED', message: 'Valid API key required' }
        });
      }

      res.json({
        success: true,
        data: {
          jobId: 'job-123',
          status: 'queued',
          estimatedTime: comments.length * 5 // 5 seconds per comment
        }
      });
    });

    this.app.get('/api/comments/job/:jobId/status', (req, res) => {
      const { jobId } = req.params;
      
      res.json({
        success: true,
        data: {
          jobId,
          status: 'completed',
          progress: 100,
          results: {
            categorizedComments: [
              {
                id: 1,
                comment: 'Test comment',
                category: 'General Feedback',
                sentiment: 0.5,
                confidence: 0.8
              }
            ]
          }
        }
      });
    });
  }

  setupIndustryRoutes() {
    this.app.get('/api/industries', (req, res) => {
      res.json({
        success: true,
        data: {
          industries: [
            'SaaS/Technology',
            'E-commerce/Retail',
            'Healthcare',
            'Financial Services'
          ]
        }
      });
    });

    this.app.get('/api/industries/:industry/categories', (req, res) => {
      const { industry } = req.params;
      
      const categories = {
        'SaaS/Technology': [
          'Technical Issues: Bug Reports',
          'Technical Issues: Feature Requests',
          'Customer Success: Support Quality'
        ],
        'E-commerce/Retail': [
          'Product Quality',
          'Shipping Issues',
          'Customer Service'
        ]
      };

      res.json({
        success: true,
        data: {
          categories: categories[industry] || []
        }
      });
    });
  }

  setupNpsRoutes() {
    this.app.use(express.json());

    this.app.get('/api/nps/dashboard/:userId', (req, res) => {
      const { userId } = req.params;
      
      res.json({
        success: true,
        data: {
          npsScore: 45,
          totalResponses: 1000,
          promoters: { count: 450, percentage: 45 },
          passives: { count: 350, percentage: 35 },
          detractors: { count: 200, percentage: 20 }
        }
      });
    });

    this.app.post('/api/nps/upload', (req, res) => {
      res.json({
        success: true,
        data: {
          uploadId: 'upload-123',
          status: 'processing'
        }
      });
    });
  }

  async start() {
    return new Promise((resolve, reject) => {
      this.server = this.app.listen(this.port, (err) => {
        if (err) {
          reject(err);
        } else {
          console.log(`Mock ${this.name} service started on port ${this.port}`);
          resolve();
        }
      });
    });
  }

  async stop() {
    if (this.server) {
      return new Promise((resolve) => {
        this.server.close(() => {
          console.log(`Mock ${this.name} service stopped`);
          resolve();
        });
      });
    }
  }
}

// Global test setup
let mockServices = [];

global.integrationTestUtils = {
  async startMockServices() {
    const services = [
      { name: 'auth', port: 3001 },
      { name: 'comment', port: 3002 },
      { name: 'industry', port: 3003 },
      { name: 'nps', port: 3004 }
    ];

    mockServices = services.map(({ name, port }) => new MockServiceServer(name, port));
    
    // Start all services
    await Promise.all(mockServices.map(service => service.start()));
    
    // Wait a bit for services to be fully ready
    await new Promise(resolve => setTimeout(resolve, 100));
  },

  async stopMockServices() {
    await Promise.all(mockServices.map(service => service.stop()));
    mockServices = [];
  },

  async waitForHealthy(app, timeout = 5000) {
    const start = Date.now();
    
    while (Date.now() - start < timeout) {
      try {
        const res = await request(app).get('/health/services');
        if (res.status === 200) {
          return true;
        }
      } catch (error) {
        // Continue waiting
      }
      
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    throw new Error('Services did not become healthy within timeout');
  }
};

// Setup before all integration tests
beforeAll(async () => {
  await global.integrationTestUtils.startMockServices();
});

// Cleanup after all integration tests
afterAll(async () => {
  await global.integrationTestUtils.stopMockServices();
});