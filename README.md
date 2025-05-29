# Enhanced Gateway Service with Synchronization

## 🚀 New Features

### Service Synchronization Monitoring
The enhanced gateway now monitors and ensures all microservices are synchronized with the shared knowledge version.

**Key Benefits:**
- **Automatic Sync Detection**: Monitors shared knowledge versions across all services
- **Health Integration**: Combines service health with sync status
- **Proactive Alerts**: Identifies out-of-sync services before they cause issues
- **Zero Downtime**: Ensures compatibility during service updates

### Service Orchestration
Intelligent request coordination across multiple services for complex operations.

**Features:**
- **Dashboard Orchestration**: Combines user data from multiple services
- **Caching Layer**: Reduces redundant service calls
- **Graceful Degradation**: Works even when some services are unavailable
- **Request Tracing**: Full visibility into cross-service requests

### Circuit Breaker Pattern
Automatic fault tolerance to prevent cascade failures.

**Protection:**
- **Failure Detection**: Monitors service failure rates
- **Automatic Recovery**: Tests service health periodically
- **Fast Failure**: Fails fast when services are down
- **Statistics**: Detailed metrics on service reliability

## 🔧 Quick Start

### Environment Variables

```bash
# Required
JWT_SECRET=your-super-secret-jwt-key-32-chars-minimum

# Service URLs
AUTH_SERVICE_URL=https://your-auth-service.herokuapp.com
COMMENT_SERVICE_URL=https://your-comment-service.herokuapp.com
INDUSTRY_SERVICE_URL=https://your-industry-service.herokuapp.com
NPS_SERVICE_URL=https://your-nps-service.herokuapp.com

# Sync Configuration (Optional)
SHARED_KNOWLEDGE_VERSION=1.0.0
SYNC_CHECK_INTERVAL=300000
SYNC_WARNING_THRESHOLD=1800000
SYNC_CRITICAL_THRESHOLD=3600000

# Features (Optional - all enabled by default)
FEATURE_SYNC_MONITORING=true
FEATURE_ORCHESTRATION=true
ORCHESTRATION_CACHE_ENABLED=true
CIRCUIT_BREAKER_ENABLED=true
```

### Development Mode

```bash
# Install dependencies
npm install

# Start with enhanced features
npm run dev:enhanced

# Check sync status
npm run sync:check

# View sync status via API
npm run sync:status
```

## 📊 New API Endpoints

### Sync Monitoring
```bash
# Check overall sync status
GET /health/sync

# Detailed sync information
GET /api/gateway/sync/status

# Force sync check (admin only)
POST /api/gateway/sync/force
```

### Service Orchestration
```bash
# User dashboard (orchestrated)
GET /api/orchestration/user/:userId/dashboard

# Gateway service stats
GET /api/gateway/stats
```

### Enhanced Health Checks
```bash
# Basic health (unchanged)
GET /health

# Enhanced health with sync status
GET /health/services

# Service management
GET /api/gateway/services
```

## 🔍 Monitoring & Debugging

### Sync Status Check Script
```bash
# Check all services
node scripts/check-sync.js

# Gateway only
node scripts/check-sync.js --gateway-only

# Individual services only
node scripts/check-sync.js --services-only

# JSON output
node scripts/check-sync.js --json
```

### Log Levels
```bash
# Development - detailed logs
LOG_LEVEL=debug

# Production - essential logs only
LOG_LEVEL=info

# Enable colored output
ENABLE_COLORS=true
```

## 🏗 Architecture Enhancements

### Service Communication Flow
```
Client Request → Gateway → Enhanced Health Check
                      ↓
                Circuit Breaker Check
                      ↓
                Sync Status Validation
                      ↓
            Service Orchestration (if needed)
                      ↓
                 Proxy to Service
                      ↓
            Response + Sync Info Collection
```

### Sync Monitoring Flow
```
Gateway Timer → Check All Services → Collect Versions
                      ↓
              Compare with Expected Version
                      ↓
              Update Service Status
                      ↓
          Log Warnings/Alerts if Out of Sync
```

### Circuit Breaker States
```
CLOSED → Requests pass through normally
   ↓ (failures exceed threshold)
OPEN → Requests fail fast
   ↓ (timeout expires)
HALF_OPEN → Test single request
   ↓ (success)        ↓ (failure)
CLOSED             OPEN
```

## 🚦 Configuration Examples

### Production Configuration
```javascript
// Recommended production settings
{
  sync: {
    checkInterval: 300000,      // 5 minutes
    warningThreshold: 1800000,  // 30 minutes
    criticalThreshold: 3600000, // 1 hour
    autoUpdate: false           // Manual updates only
  },
  orchestration: {
    timeout: 10000,             // 10 seconds
    cacheExpiry: 300000,        // 5 minutes
    retryAttempts: 3
  },
  circuitBreaker: {
    failureThreshold: 5,        // 5 failures
    resetTimeout: 60000         // 1 minute
  }
}
```

### Development Configuration
```javascript
// Recommended development settings
{
  sync: {
    checkInterval: 60000,       // 1 minute
    warningThreshold: 300000,   // 5 minutes
    criticalThreshold: 600000,  // 10 minutes
    autoUpdate: true            // Auto-update in dev
  },
  orchestration: {
    timeout: 5000,              // 5 seconds
    cacheExpiry: 60000,         // 1 minute
    retryAttempts: 2
  }
}
```

## 🔧 Troubleshooting

### Common Issues

**Services showing as out-of-sync:**
```bash
# Check specific service
curl http://your-service.com/api/shared-knowledge/status

# Force sync check
curl -X POST http://localhost:3000/api/gateway/sync/force \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

**Circuit breaker stuck open:**
```bash
# Check circuit breaker status
curl http://localhost:3000/api/gateway/stats

# Reset circuit breaker (admin)
curl -X POST http://localhost:3000/api/gateway/circuit-breaker/reset \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{"service": "service-name"}'
```

**High response times:**
```bash
# Check orchestration cache stats
curl http://localhost:3000/api/gateway/stats | jq '.orchestration'

# Clear cache if needed
curl -X DELETE http://localhost:3000/api/gateway/cache \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### Debug Mode
```bash
# Enable verbose logging
LOG_LEVEL=debug FEATURE_REQUEST_TRACING=true npm run dev

# Monitor sync in real-time
watch -n 30 'npm run sync:check --services-only'
```

## 📈 Performance Improvements

### Caching Strategy
- **User Data**: 10 minutes TTL
- **Dashboard**: 2 minutes TTL
- **Industries**: 15 minutes TTL
- **Recent Jobs**: 2 minutes TTL

### Request Optimization
- **Parallel Service Calls**: Multiple services called simultaneously
- **Circuit Breaker**: Fast failure for unhealthy services
- **Request Pooling**: Reuse connections where possible
- **Gzip Compression**: Automatic response compression

### Memory Management
- **Automatic Cache Cleanup**: Expired entries removed every minute
- **Token Cache**: JWT tokens cached for 5 minutes
- **Circuit Breaker Reset**: Failure counts decay over time

## 🔒 Security Enhancements

### Enhanced Authentication
- **JWT Token Caching**: Reduce auth service load
- **Role-Based Access**: Granular permission control
- **Request Tracing**: Full audit trail
- **Rate Limiting**: Per-user and per-endpoint limits

### Service-to-Service Security
- **Request Signing**: Gateway signs all outbound requests
- **Header Forwarding**: Secure context propagation
- **API Key Validation**: Service authentication
- **CORS Configuration**: Precise origin control

## 📝 Migration Guide

### From Basic Gateway

1. **Update Environment Variables**:
   ```bash
   # Add sync configuration
   SHARED_KNOWLEDGE_VERSION=1.0.0
   SYNC_CHECK_INTERVAL=300000
   ```

2. **Update Service Dependencies**:
   ```bash
   npm install  # Will install enhanced dependencies
   ```

3. **Test Enhanced Features**:
   ```bash
   npm run sync:check
   npm run dev:enhanced
   ```

4. **Deploy with Zero Downtime**:
   ```bash
   # Services can be updated one at a time
   # Gateway handles mixed versions gracefully
   ```

### Service Requirements

For full sync monitoring, services should implement:
```bash
# Health endpoint with version info
GET /health
Response: { "status": "healthy", "sharedKnowledgeVersion": "1.0.0" }

# Optional: Dedicated sync endpoint
GET /api/shared-knowledge/status
Response: { "version": "1.0.0", "lastUpdated": "2024-01-15T10:30:00Z" }
```

## 🤝 Contributing

### Development Setup
```bash
git clone <repository>
cd gateway-service
npm install
cp .env.example .env
# Update .env with your service URLs
npm run dev:enhanced
```

### Testing
```bash
npm test                # Unit tests
npm run test:coverage   # Coverage report
npm run test:integration # Integration tests
npm run validate        # Lint + test
```

This enhanced gateway maintains the small project size while significantly improving service coordination, monitoring, and reliability. The sync monitoring ensures all services stay coordinated, while orchestration provides intelligent request handling across the microservices architecture.