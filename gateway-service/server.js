// gateway-service/server.js
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware setup
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
}));

// Service URLs configuration
const SERVICES = {
  auth: process.env.AUTH_SERVICE_URL || 'http://localhost:3001',
  comments: process.env.COMMENT_SERVICE_URL || 'http://localhost:3002',
  industries: process.env.INDUSTRY_SERVICE_URL || 'http://localhost:3003',
  nps: process.env.NPS_SERVICE_URL || 'http://localhost:3004'
};

console.log('🚀 Gateway starting with service configuration:');
Object.entries(SERVICES).forEach(([service, url]) => {
  console.log(`  ${service}: ${url}`);
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: SERVICES,
    version: process.env.npm_package_version || '1.0.0',
    uptime: process.uptime()
  });
});

// API status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    gateway: 'operational',
    services: Object.keys(SERVICES),
    timestamp: new Date().toISOString()
  });
});

// Serve static files from public directory
app.use(express.static(path.join(__dirname, '../public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : '0',
  etag: true,
  lastModified: true
}));

// Basic error handling middleware
app.use((err, req, res, next) => {
  console.error('Gateway Error:', err);
  
  // Don't send error details in production
  const errorResponse = {
    error: 'Internal Server Error',
    timestamp: new Date().toISOString(),
    path: req.path
  };
  
  if (process.env.NODE_ENV !== 'production') {
    errorResponse.details = err.message;
    errorResponse.stack = err.stack;
  }
  
  res.status(err.status || 500).json(errorResponse);
});

// 404 handler for unmatched routes
app.use('*', (req, res) => {
  // If it's an API request, return JSON
  if (req.originalUrl.startsWith('/api/')) {
    return res.status(404).json({
      error: 'API endpoint not found',
      path: req.originalUrl,
      timestamp: new Date().toISOString()
    });
  }
  
  // For non-API requests, try to serve index.html (SPA support)
  res.sendFile(path.join(__dirname, '../public/index.html'), (err) => {
    if (err) {
      res.status(404).json({
        error: 'Resource not found',
        path: req.originalUrl
      });
    }
  });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('🔄 Received SIGTERM, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🔄 Received SIGINT, shutting down gracefully');
  process.exit(0);
});

// Start the server
app.listen(PORT, () => {
  console.log(`🌐 API Gateway running on port ${PORT}`);
  console.log(`📊 Health check available at http://localhost:${PORT}/health`);
  console.log(`🔍 API status available at http://localhost:${PORT}/api/status`);
  
  if (process.env.NODE_ENV !== 'production') {
    console.log(`📁 Static files served from: ${path.join(__dirname, '../public')}`);
  }
});

module.exports = app;