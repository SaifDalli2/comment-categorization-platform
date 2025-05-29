#!/bin/bash
# gateway-upgrade.sh - Automated Gateway Enhancement Script

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${BLUE}📋 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to check if we're in a git repository
check_git_repo() {
    if [ ! -d ".git" ]; then
        print_error "Not in a git repository. Please run this script from your gateway-service root directory."
        exit 1
    fi
}

# Function to handle git changes
manage_git_changes() {
    print_step "Managing Git Changes"
    
    # Check if there are uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        print_warning "You have uncommitted changes."
        echo "Choose an option:"
        echo "1) Stash changes (recommended)"
        echo "2) Reset all changes (DESTRUCTIVE - will lose all changes)"
        echo "3) Commit changes first"
        echo "4) Continue with existing changes"
        
        read -p "Enter your choice (1-4): " choice
        
        case $choice in
            1)
                print_step "Stashing your changes..."
                git stash push -m "Pre-upgrade backup $(date '+%Y-%m-%d %H:%M:%S')"
                print_success "Changes stashed. You can restore them later with: git stash pop"
                ;;
            2)
                print_warning "This will permanently delete all uncommitted changes!"
                read -p "Are you sure? Type 'yes' to confirm: " confirm
                if [ "$confirm" = "yes" ]; then
                    git reset --hard HEAD
                    git clean -fd
                    print_success "All changes reset"
                else
                    print_error "Reset cancelled. Exiting."
                    exit 1
                fi
                ;;
            3)
                print_step "Please commit your changes first, then run this script again."
                git status
                exit 0
                ;;
            4)
                print_warning "Continuing with existing changes. This might cause conflicts."
                ;;
            *)
                print_error "Invalid choice. Exiting."
                exit 1
                ;;
        esac
    else
        print_success "Working directory is clean"
    fi
}

# Function to create backup
create_backup() {
    print_step "Creating backup of current files"
    
    BACKUP_DIR="backup-$(date '+%Y%m%d-%H%M%S')"
    mkdir -p "$BACKUP_DIR"
    
    # Backup key files
    [ -f "server.js" ] && cp "server.js" "$BACKUP_DIR/"
    [ -f "package.json" ] && cp "package.json" "$BACKUP_DIR/"
    [ -f ".env" ] && cp ".env" "$BACKUP_DIR/"
    [ -d "middleware" ] && cp -r "middleware" "$BACKUP_DIR/"
    [ -d "services" ] && cp -r "services" "$BACKUP_DIR/"
    [ -d "utils" ] && cp -r "utils" "$BACKUP_DIR/"
    [ -d "config" ] && cp -r "config" "$BACKUP_DIR/"
    
    print_success "Backup created in $BACKUP_DIR/"
}

# Function to check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites"
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed"
        exit 1
    fi
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed"
        exit 1
    fi
    
    # Check if package.json exists
    if [ ! -f "package.json" ]; then
        print_error "package.json not found. Are you in the right directory?"
        exit 1
    fi
    
    print_success "All prerequisites met"
}

# Function to create enhanced service registry
create_service_registry() {
    print_step "Creating enhanced service registry"
    
    mkdir -p src/services
    
    cat > src/services/ServiceRegistry.js << 'EOF'
// gateway-service/src/services/ServiceRegistry.js
const axios = require('axios');
const logger = require('../../utils/simpleLogger');

class BaseServiceClient {
  constructor(baseUrl, serviceName, options = {}) {
    this.baseUrl = baseUrl;
    this.serviceName = serviceName;
    this.timeout = options.timeout || 30000;
    this.retryAttempts = options.retryAttempts || 3;
    this.retryDelay = options.retryDelay || 1000;
    
    this.client = axios.create({
      baseURL: this.baseUrl,
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Gateway-Service-Client/1.0'
      }
    });

    this.setupInterceptors();
  }

  setupInterceptors() {
    this.client.interceptors.request.use(
      (config) => {
        config.headers['X-Request-ID'] = this.generateRequestId();
        config.headers['X-Service-Name'] = 'gateway';
        config.metadata = { startTime: Date.now() };
        return config;
      }
    );

    this.client.interceptors.response.use(
      (response) => {
        const duration = Date.now() - response.config.metadata.startTime;
        logger.debug(`${this.serviceName} response: ${response.status} (${duration}ms)`);
        return response;
      },
      async (error) => {
        if (this.shouldRetry(error) && !error.config._retry) {
          error.config._retry = true;
          error.config._retryCount = (error.config._retryCount || 0) + 1;

          if (error.config._retryCount <= this.retryAttempts) {
            await this.delay(this.retryDelay * error.config._retryCount);
            return this.client.request(error.config);
          }
        }
        return Promise.reject(this.normalizeError(error));
      }
    );
  }

  shouldRetry(error) {
    return (
      !error.response || 
      error.response.status >= 500 || 
      error.code === 'ECONNRESET' ||
      error.code === 'ETIMEDOUT'
    );
  }

  normalizeError(error) {
    if (error.response) {
      return {
        code: error.response.data?.error?.code || 'SERVICE_ERROR',
        message: error.response.data?.error?.message || error.message,
        status: error.response.status,
        service: this.serviceName
      };
    } else if (error.request) {
      return {
        code: 'SERVICE_UNAVAILABLE',
        message: `${this.serviceName} service is unavailable`,
        status: 503,
        service: this.serviceName
      };
    } else {
      return {
        code: 'REQUEST_ERROR',
        message: error.message,
        status: 500,
        service: this.serviceName
      };
    }
  }

  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async get(endpoint, params = {}, headers = {}) {
    const response = await this.client.get(endpoint, { params, headers });
    return response.data;
  }

  async post(endpoint, data = {}, headers = {}) {
    const response = await this.client.post(endpoint, data, { headers });
    return response.data;
  }

  async put(endpoint, data = {}, headers = {}) {
    const response = await this.client.put(endpoint, data, { headers });
    return response.data;
  }

  async delete(endpoint, headers = {}) {
    const response = await this.client.delete(endpoint, { headers });
    return response.data;
  }

  async healthCheck() {
    try {
      const response = await this.client.get('/health', { timeout: 5000 });
      return {
        healthy: response.status === 200,
        status: response.status,
        responseTime: Date.now() - response.config.metadata.startTime
      };
    } catch (error) {
      return {
        healthy: false,
        error: error.message,
        status: error.response?.status || 0
      };
    }
  }
}

class AuthServiceClient extends BaseServiceClient {
  constructor() {
    super(
      process.env.AUTH_SERVICE_URL || 'https://auth-service-voice-0add8d339257.herokuapp.com',
      'auth-service'
    );
  }

  async verifyToken(token) {
    return this.post('/api/auth/verify', {}, {
      'Authorization': `Bearer ${token}`
    });
  }

  async getUser(userId) {
    return this.get(`/api/users/${userId}`);
  }
}

class CommentServiceClient extends BaseServiceClient {
  constructor() {
    super(
      process.env.COMMENT_SERVICE_URL || 'https://your-comment-service.herokuapp.com',
      'comment-service'
    );
  }

  async categorizeComments(data, userHeaders = {}) {
    return this.post('/api/comments/categorize', data, userHeaders);
  }

  async getJobStatus(jobId, userHeaders = {}) {
    return this.get(`/api/comments/job/${jobId}/status`, {}, userHeaders);
  }
}

class IndustryServiceClient extends BaseServiceClient {
  constructor() {
    super(
      process.env.INDUSTRY_SERVICE_URL || 'https://your-industry-service.herokuapp.com',
      'industry-service'
    );
  }

  async getIndustries() {
    return this.get('/api/industries');
  }

  async getIndustryCategories(industry) {
    return this.get(`/api/industries/${encodeURIComponent(industry)}/categories`);
  }
}

class NPSServiceClient extends BaseServiceClient {
  constructor() {
    super(
      process.env.NPS_SERVICE_URL || 'https://your-nps-service.herokuapp.com',
      'nps-service'
    );
  }

  async getNPSDashboard(userId, params = {}) {
    return this.get(`/api/nps/dashboard/${userId}`, params);
  }
}

class ServiceRegistry {
  constructor() {
    this.services = new Map();
    this.initializeServices();
  }

  initializeServices() {
    this.services.set('auth', new AuthServiceClient());
    this.services.set('comment', new CommentServiceClient());
    this.services.set('industry', new IndustryServiceClient());
    this.services.set('nps', new NPSServiceClient());
    
    logger.info('Enhanced service registry initialized');
  }

  get(serviceName) {
    return this.services.get(serviceName);
  }

  async healthCheckAll() {
    const results = {};
    
    for (const [name, client] of this.services.entries()) {
      try {
        results[name] = await client.healthCheck();
      } catch (error) {
        results[name] = {
          healthy: false,
          error: error.message
        };
      }
    }
    
    return results;
  }

  getServiceNames() {
    return Array.from(this.services.keys());
  }
}

class EnhancedAuth {
  constructor(serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
    this.tokenCache = new Map();
    this.cacheExpiry = 5 * 60 * 1000; // 5 minutes
    
    // Import existing auth for fallback
    const SimpleAuth = require('../../middleware/simpleAuth');
    this.simpleAuth = new SimpleAuth();
  }

  optionalAuth() {
    if (process.env.USE_ENHANCED_AUTH === 'true') {
      return (req, res, next) => {
        // Enhanced optional auth logic would go here
        // For now, use existing implementation
        this.simpleAuth.optionalAuth()(req, res, next);
      };
    } else {
      return this.simpleAuth.optionalAuth();
    }
  }

  requireAuth() {
    if (process.env.USE_ENHANCED_AUTH === 'true') {
      return (req, res, next) => {
        // Enhanced auth logic would go here
        // For now, use existing implementation
        this.simpleAuth.requireAuth()(req, res, next);
      };
    } else {
      return this.simpleAuth.requireAuth();
    }
  }

  getStats() {
    return {
      cachedTokens: this.tokenCache.size,
      cacheExpiryMs: this.cacheExpiry,
      enhancedMode: process.env.USE_ENHANCED_AUTH === 'true'
    };
  }
}

module.exports = {
  BaseServiceClient,
  AuthServiceClient,
  CommentServiceClient,
  IndustryServiceClient,
  NPSServiceClient,
  ServiceRegistry,
  EnhancedAuth
};
EOF
    
    print_success "Service registry created"
}

# Function to create enhanced server.js
create_enhanced_server() {
    print_step "Creating enhanced server.js"
    
    cat > server.js << 'EOF'
// gateway-service/server.js - Enhanced Gateway Server
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

// Keep existing imports
const SimpleAuth = require('./middleware/simpleAuth');
const SimpleHealth = require('./services/simpleHealth');
const config = require('./config/simple');
const logger = require('./utils/simpleLogger');

// NEW: Add enhanced service components
const { ServiceRegistry, EnhancedAuth } = require('./src/services/ServiceRegistry');

const app = express();

// Initialize components
const auth = new SimpleAuth();
const health = new SimpleHealth();
const serviceRegistry = new ServiceRegistry();
const enhancedAuth = new EnhancedAuth(serviceRegistry);

// Trust proxy (important for Heroku)
app.set('trust proxy', 1);

// Basic middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced security
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "wss:", "https:"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors({
  origin: config.security.corsOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Requested-With', 
    'X-API-Key', 
    'X-Request-ID'
  ]
}));

// Enhanced rate limiting
const createRateLimit = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: { 
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message,
        suggestion: 'Please wait before making additional requests'
      }
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/health' || req.path.startsWith('/health/')
  });
};

// Apply rate limits
app.use('/api/auth', createRateLimit(15 * 60 * 1000, 20, 'Too many authentication requests'));
app.use('/api/comments/categorize', createRateLimit(60 * 60 * 1000, 50, 'Too many categorization requests'));
app.use('/api/nps/upload', createRateLimit(60 * 60 * 1000, 10, 'Too many file uploads'));
app.use('/', createRateLimit(15 * 60 * 1000, 100, 'Too many requests'));

// Enhanced request logging
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  res.setHeader('X-Request-ID', req.id);
  
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    res.setHeader('X-Response-Time', `${duration}ms`);
    
    const logData = {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      responseTime: `${duration}ms`,
      requestId: req.id
    };
    
    if (req.user) logData.userId = req.user.id;
    
    const level = res.statusCode >= 500 ? 'error' : 
                  res.statusCode >= 400 ? 'warn' : 'info';
    logger.log(level, `${req.method} ${req.path} ${res.statusCode}`, logData);
  });
  
  next();
});

// Health endpoints
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'gateway',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/health/services', async (req, res) => {
  try {
    const legacyHealth = health.getOverallHealth();
    const enhancedHealth = await serviceRegistry.healthCheckAll();
    
    const allHealthy = legacyHealth.healthy && 
                      Object.values(enhancedHealth).every(h => h.healthy);
    
    res.status(allHealthy ? 200 : 503).json({
      status: allHealthy ? 'healthy' : 'degraded',
      service: 'gateway',
      timestamp: new Date().toISOString(),
      dependencies: {
        ...legacyHealth.services,
        ...enhancedHealth
      },
      summary: {
        totalServices: legacyHealth.totalServices,
        healthyServices: legacyHealth.healthyServices,
        unhealthyServices: legacyHealth.unhealthyServices
      }
    });
  } catch (error) {
    logger.error('Health check failed:', { error: error.message });
    res.status(503).json({
      status: 'unhealthy',
      service: 'gateway',
      timestamp: new Date().toISOString(),
      error: 'Health check system failure'
    });
  }
});

// NEW: Enhanced gateway management endpoint
app.get('/api/gateway/services', enhancedAuth.optionalAuth(), async (req, res) => {
  try {
    const serviceHealth = await serviceRegistry.healthCheckAll();
    const authStats = enhancedAuth.getStats();
    
    res.json({
      success: true,
      data: {
        services: serviceHealth,
        gateway: {
          uptime: Math.floor(process.uptime()),
          version: process.env.npm_package_version || '1.0.0',
          environment: process.env.NODE_ENV || 'development',
          auth: authStats
        }
      },
      metadata: {
        timestamp: new Date().toISOString(),
        requestId: req.id,
        service: 'gateway'
      }
    });
  } catch (error) {
    logger.error('Gateway services endpoint failed:', { error: error.message });
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to retrieve service information'
      }
    });
  }
});

// Enhanced proxy factory
const createEnhancedProxy = (serviceName, targetUrl) => {
  return createProxyMiddleware({
    target: targetUrl,
    changeOrigin: true,
    timeout: 30000,
    
    onProxyReq: (proxyReq, req) => {
      if (req.user) {
        proxyReq.setHeader('X-User-ID', req.user.userId || req.user.id);
        proxyReq.setHeader('X-User-Email', req.user.email);
        proxyReq.setHeader('X-User-Industry', req.user.industry || '');
        
        if (req.user.roles && req.user.roles.length > 0) {
          proxyReq.setHeader('X-User-Roles', req.user.roles.join(','));
        }
      }
      
      proxyReq.setHeader('X-Gateway-Request', 'true');
      proxyReq.setHeader('X-Gateway-Version', '1.0.0');
      proxyReq.setHeader('X-Request-ID', req.id);
      proxyReq.setHeader('X-Service-Name', 'gateway');
      
      if (req.ip) {
        proxyReq.setHeader('X-Forwarded-For', req.ip);
      }
      
      logger.debug(`Proxying to ${serviceName}:`, {
        method: req.method,
        path: req.path,
        userId: req.user?.id,
        requestId: req.id
      });
    },

    onProxyRes: (proxyRes, req, res) => {
      proxyRes.headers['x-served-by'] = serviceName;
      proxyRes.headers['x-gateway-service'] = 'claude-analysis-gateway';
      proxyRes.headers['x-response-time'] = `${Date.now() - req.startTime}ms`;
      
      const success = proxyRes.statusCode < 400;
      health.recordServiceResponse(serviceName, success);
      
      if (success) {
        logger.debug(`Successful proxy to ${serviceName}:`, {
          statusCode: proxyRes.statusCode,
          requestId: req.id
        });
      }
    },

    onError: (err, req, res) => {
      logger.error(`Proxy error for ${serviceName}:`, {
        error: err.message,
        path: req.path,
        method: req.method,
        requestId: req.id
      });
      
      health.recordServiceResponse(serviceName, false);
      
      if (res.headersSent) return;
      
      let errorCode = 'SERVICE_UNAVAILABLE';
      let statusCode = 503;
      let suggestion = 'Please try again in a few moments';
      
      if (err.code === 'ECONNREFUSED') {
        errorCode = 'SERVICE_UNAVAILABLE';
        suggestion = `${serviceName} service is currently unavailable`;
      } else if (err.code === 'ETIMEDOUT') {
        errorCode = 'GATEWAY_TIMEOUT';
        statusCode = 504;
        suggestion = 'The request took too long to process';
      }
      
      res.status(statusCode).json({
        success: false,
        error: {
          code: errorCode,
          message: `${serviceName} service error: ${err.message}`,
          suggestion
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.id,
          service: 'gateway',
          targetService: serviceName
        }
      });
    }
  });
};

// Service routing
app.use('/api/auth', 
  createEnhancedProxy('auth', config.services.auth)
);

app.use('/api/comments', 
  enhancedAuth.requireAuth(),
  createEnhancedProxy('comment', config.services.comment)
);

app.use('/api/industries', 
  enhancedAuth.optionalAuth(),
  createEnhancedProxy('industry', config.services.industry)
);

app.use('/api/nps', 
  enhancedAuth.requireAuth(),
  createEnhancedProxy('nps', config.services.nps)
);

// Static files
app.use(express.static('public', {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  etag: true,
  lastModified: true
}));

// API 404 handler
app.use('/api/*', (req, res) => {
  logger.warn('API endpoint not found:', { path: req.path, method: req.method, requestId: req.id });
  
  res.status(404).json({
    success: false,
    error: {
      code: 'RESOURCE_NOT_FOUND',
      message: 'The requested API endpoint does not exist',
      suggestion: 'Check the API documentation for available endpoints'
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.id,
      service: 'gateway'
    }
  });
});

// SPA fallback
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  res.sendFile(indexPath, (err) => {
    if (err) {
      logger.error('Failed to serve index.html:', { error: err.message, requestId: req.id });
      res.status(404).json({
        success: false,
        error: {
          code: 'RESOURCE_NOT_FOUND',
          message: 'The requested resource was not found'
        }
      });
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', { 
    error: err.message, 
    stack: err.stack, 
    requestId: req.id,
    path: req.path,
    method: req.method
  });
  
  if (res.headersSent) {
    return next(err);
  }
  
  const message = process.env.NODE_ENV === 'production' ? 
    'An unexpected error occurred' : 
    err.message;
  
  res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message,
      suggestion: 'Please try again later'
    },
    metadata: {
      timestamp: new Date().toISOString(),
      requestId: req.id,
      service: 'gateway'
    }
  });
});

// Server startup
const PORT = config.port;
const server = app.listen(PORT, () => {
  logger.info(`Enhanced Gateway server started:`, {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    enhancedMode: process.env.USE_ENHANCED_AUTH === 'true',
    version: process.env.npm_package_version || '1.0.0'
  });
  
  logger.systemInfo();
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received, shutting down gracefully`);
  
  server.close((err) => {
    if (err) {
      logger.error('Error during server shutdown:', { error: err.message });
      process.exit(1);
    }
    
    logger.info('Gateway server closed successfully');
    process.exit(0);
  });
  
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', { 
    error: err.message, 
    stack: err.stack 
  });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection:', { 
    reason: reason instanceof Error ? reason.message : reason,
    stack: reason instanceof Error ? reason.stack : undefined
  });
  process.exit(1);
});

module.exports = app;
EOF
    
    print_success "Enhanced server.js created"
}

# Function to update environment variables
update_env_file() {
    print_step "Updating environment variables"
    
    # Check if .env exists
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_success "Created .env from .env.example"
        else
            touch .env
            print_success "Created new .env file"
        fi
    fi
    
    # Add new environment variables if they don't exist
    if ! grep -q "USE_ENHANCED_AUTH" .env; then
        echo "" >> .env
        echo "# Enhanced Gateway Features" >> .env
        echo "USE_ENHANCED_AUTH=false" >> .env
        echo "ENABLE_AGGREGATED_ENDPOINTS=true" >> .env
        echo "SERVICE_TIMEOUT=30000" >> .env
        echo "SERVICE_RETRY_ATTEMPTS=3" >> .env
        print_success "Added enhanced gateway configuration to .env"
    else
        print_success "Enhanced configuration already exists in .env"
    fi
}

# Function to install dependencies
install_dependencies() {
    print_step "Installing/updating dependencies"
    
    # Check if axios is already installed
    if ! npm list axios &> /dev/null; then
        npm install axios
        print_success "Installed axios"
    else
        print_success "Axios already installed"
    fi
    
    # Install other potential missing dependencies
    npm install --save express http-proxy-middleware cors helmet express-rate-limit jsonwebtoken dotenv
    
    print_success "Dependencies updated"
}

# Function to test the upgrade
test_upgrade() {
    print_step "Testing the upgrade"
    
    # Start the server in background
    npm start &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 5
    
    # Test health endpoint
    if curl -s http://localhost:3000/health > /dev/null; then
        print_success "Health endpoint working"
    else
        print_error "Health endpoint failed"
        kill $SERVER_PID 2>/dev/null
        return 1
    fi
    
    # Test enhanced services endpoint
    if curl -s http://localhost:3000/api/gateway/services > /dev/null; then
        print_success "Enhanced services endpoint working"
    else
        print_warning "Enhanced services endpoint not responding (this is OK, services might be down)"
    fi
    
    # Stop the server
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    
    print_success "Local testing completed"
}

# Function to create deployment script
create_deployment_script() {
    print_step "Creating deployment script"
    
    cat > deploy-enhanced.sh << 'EOF'
#!/bin/bash
# deploy-enhanced.sh - Deploy enhanced gateway

set -e

echo "🚀 Deploying enhanced gateway to Heroku..."

# Add and commit changes
git add .
git commit -m "feat: upgrade gateway with enhanced service management and monitoring" || echo "Nothing to commit"

# Push to Heroku
git push heroku main

# Set enhanced configuration
echo "⚙️ Setting enhanced configuration..."
heroku config:set USE_ENHANCED_AUTH=false --app gateway-service-b25f91548194
heroku config:set ENABLE_AGGREGATED_ENDPOINTS=true --app gateway-service-b25f91548194

echo "✅ Deployment complete!"
echo ""
echo "Test your enhanced gateway:"
echo "curl https://gateway-service-b25f91548194.herokuapp.com/health"
echo "curl https://gateway-service-b25f91548194.herokuapp.com/api/gateway/services"
EOF
    
    chmod +x deploy-enhanced.sh
    print_success "Deployment script created (deploy-enhanced.sh)"
}

# Function to show completion summary
show_completion() {
    echo ""
    echo "🎉 Gateway Enhancement Complete!"
    echo ""
    echo "What was upgraded:"
    echo "✅ Enhanced service registry with retry logic"
    echo "✅ Better error handling and logging"
    echo "✅ Request tracking with unique IDs"
    echo "✅ New /api/gateway/services endpoint"
    echo "✅ Improved security headers"
    echo "✅ Enhanced rate limiting"
    echo ""
    echo "Files created/modified:"
    echo "📁 src/services/ServiceRegistry.js (NEW)"
    echo "📄 server.js (ENHANCED)"
    echo "📄 .env (UPDATED)"
    echo "📄 deploy-enhanced.sh (NEW)"
    echo ""
    echo "Next steps:"
    echo "1. Test locally: npm run dev"
    echo "2. Deploy: ./deploy-enhanced.sh"
    echo "3. Verify: curl https://your-app.herokuapp.com/api/gateway/services"
    echo ""
    echo "To restore from backup: cp backup-*/server.js ."
    echo "To enable enhanced auth later: heroku config:set USE_ENHANCED_AUTH=true"
}

# Main execution
main() {
    echo "🚀 Gateway Enhancement Script"
    echo "============================"
    
    # Check if we're in the right directory
    check_git_repo
    check_prerequisites
    
    # Handle git changes
    manage_git_changes
    
    # Create backup
    create_backup
    
    # Perform upgrade
    create_service_registry
    create_enhanced_server
    update_env_file
    install_dependencies
    
    # Create deployment script
    create_deployment_script
    
    # Test the upgrade
    if [ "$1" != "--skip-test" ]; then
        test_upgrade
    fi
    
    # Show completion
    show_completion
}

# Run main function with all arguments
main "$@"