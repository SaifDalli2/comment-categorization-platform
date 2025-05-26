# Gateway Service API Documentation

## Overview

The Claude Analysis Gateway Service acts as the single entry point for all client requests in the microservices architecture. It provides service discovery, load balancing, authentication, rate limiting, and request routing to backend services.

## Base Information

- **Service Name:** claude-analysis-gateway
- **Version:** 1.0.0
- **Base URL:** `https://api.claude-analysis.com` (Production) / `http://localhost:3000` (Development)
- **Protocol:** HTTP/HTTPS
- **Authentication:** JWT Bearer Token, API Key

## Architecture Overview

```
Client Request → Gateway → Service Discovery → Backend Service
     ↓              ↓            ↓                    ↓
   CORS          Auth         Load Balance        Response
Rate Limit    Validation     Circuit Breaker     Aggregation
```

## Core Endpoints

### Health and Monitoring

#### GET /health
Basic gateway health check.

**Response:**
```json
{
  "status": "healthy",
  "service": "gateway",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime": 3600,
  "version": "1.0.0",
  "environment": "production"
}
```

**Status Codes:**
- `200` - Service is healthy
- `503` - Service is degraded or unhealthy

#### GET /health/services
Detailed health check including backend services.

**Response:**
```json
{
  "status": "healthy",
  "service": "gateway",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "dependencies": {
    "auth": {
      "status": "healthy",
      "responseTime": 45,
      "lastChecked": "2024-01-15T10:30:00.000Z"
    },
    "comment": {
      "status": "healthy", 
      "responseTime": 120,
      "lastChecked": "2024-01-15T10:30:00.000Z"
    }
  },
  "summary": {
    "totalServices": 4,
    "healthyInstances": 4,
    "unhealthyInstances": 0,
    "openCircuitBreakers": 0
  }
}
```

#### GET /metrics
Prometheus-compatible metrics endpoint.

**Response:** Plain text Prometheus metrics

**Headers:**
- `Content-Type: text/plain; version=0.0.4; charset=utf-8`

### Service Management

#### GET /api/gateway/services
List all registered services and their status.

**Authentication:** Required (Bearer Token)

**Response:**
```json
{
  "success": true,
  "data": {
    "auth": {
      "name": "auth",
      "totalInstances": 1,
      "healthyInstances": 1,
      "instances": [
        {
          "id": "auth-0",
          "url": "http://auth-service:3001",
          "status": "healthy",
          "lastHealthCheck": "2024-01-15T10:30:00.000Z",
          "responseTime": 45,
          "circuitBreakerState": "closed",
          "requestCount": 150,
          "errorCount": 2
        }
      ]
    }
  },
  "metadata": {
    "timestamp": "2024-01-15T10:30:00.000Z",
    "requestId": "req_123456789",
    "service": "gateway"
  }
}
```

#### GET /api/gateway/stats
Gateway performance and health statistics.

**Authentication:** Required (Bearer Token)

**Response:**
```json
{
  "success": true,
  "data": {
    "totalServices": 4,
    "totalInstances": 6,
    "healthyInstances": 6,
    "unhealthyInstances": 0,
    "openCircuitBreakers": 0,
    "halfOpenCircuitBreakers": 0,
    "lastHealthCheck": "2024-01-15T10:30:00.000Z",
    "services": {
      "auth": {
        "instances": 1,
        "healthy": 1,
        "unhealthy": 0,
        "avgResponseTime": 45,
        "totalRequests": 150,
        "totalErrors": 2
      }
    },
    "proxy": {
      "activeRetries": 0,
      "maxRetryAttempts": 3,
      "retryDelay": 1000
    },
    "errors": {
      "errorRates": {},
      "thresholds": {
        "warning": 0.05,
        "critical": 0.15
      }
    }
  }
}
```

## Proxied Service Endpoints

The gateway proxies requests to the following services:

### Authentication Service (/api/auth/*)
- **POST /api/auth/login** - User authentication
- **POST /api/auth/register** - User registration  
- **GET /api/auth/verify** - Token verification
- **POST /api/auth/logout** - User logout
- **PUT /api/auth/profile** - Update user profile

### Comment Processing Service (/api/comments/*)
- **POST /api/comments/categorize** - Submit comments for categorization
- **GET /api/comments/job/{jobId}/status** - Check processing status
- **GET /api/comments/job/{jobId}/results** - Get categorization results
- **POST /api/comments/job/{jobId}/cancel** - Cancel processing job

### Industry Configuration Service (/api/industries/*)
- **GET /api/industries** - List available industries
- **GET /api/industries/{industry}/categories** - Get industry categories
- **GET /api/industries/{industry}/factors** - Get NPS factors
- **PUT /api/industries/{industry}/config** - Update industry configuration

### NPS Analytics Service (/api/nps/*)
- **POST /api/nps/upload** - Upload NPS data
- **GET /api/nps/dashboard/{userId}** - Get NPS dashboard
- **GET /api/nps/trends/{userId}** - Get NPS trends
- **GET /api/nps/customer-journey/{userId}** - Get customer journey data

## Authentication

### JWT Bearer Token
Most endpoints require authentication using JWT Bearer tokens.

**Header:**
```
Authorization: Bearer <jwt_token>
```

**Token Structure:**
```json
{
  "userId": "user-123",
  "email": "user@example.com", 
  "roles": ["user"],
  "industry": "SaaS/Technology",
  "exp": 1705392600,
  "iat": 1705306200
}
```

### API Key Authentication
Some endpoints support API key authentication for service-to-service communication.

**Header:**
```
X-API-Key: sk-your-api-key-here
```

## Error Handling

All API responses follow a consistent error format:

### Success Response
```json
{
  "success": true,
  "data": { ... },
  "metadata": {
    "timestamp": "2024-01-15T10:30:00.000Z",
    "requestId": "req_123456789", 
    "service": "gateway"
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "suggestion": "Suggested action to resolve the error",
    "details": "Additional error details (optional)"
  },
  "metadata": {
    "timestamp": "2024-01-15T10:30:00.000Z",
    "requestId": "req_123456789",
    "service": "gateway"
  }
}
```

### Common Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `AUTHENTICATION_REQUIRED` | 401 | Authentication token required |
| `INVALID_CREDENTIALS` | 401 | Invalid or expired token |
| `INSUFFICIENT_PERMISSIONS` | 403 | User lacks required permissions |
| `RESOURCE_NOT_FOUND` | 404 | Endpoint or resource not found |
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `SERVICE_UNAVAILABLE` | 503 | Backend service unavailable |
| `GATEWAY_TIMEOUT` | 504 | Request to backend service timed out |
| `CIRCUIT_BREAKER_OPEN` | 503 | Service circuit breaker is open |

## Request/Response Headers

### Standard Request Headers
- `Content-Type: application/json` - For POST/PUT requests
- `Authorization: Bearer <token>` - Authentication token
- `X-API-Key: <key>` - API key (alternative authentication)
- `X-Request-ID: <id>` - Optional request tracking ID
- `User-Agent: <agent>` - Client identification

### Standard Response Headers
- `X-Request-ID: <id>` - Request tracking ID
- `X-Response-Time: <ms>ms` - Response time in milliseconds
- `X-Served-By: <service>` - Backend service that handled the request
- `X-Gateway-Service: claude-analysis-gateway` - Gateway identification
- `X-Content-Type-Options: nosniff` - Security header
- `Cache-Control: <policy>` - Caching policy

## Rate Limiting

The gateway implements rate limiting to protect backend services:

### Rate Limit Tiers
- **General API**: 100 requests per 15 minutes per IP
- **Authentication**: 5 requests per 15 minutes per IP
- **Comment Processing**: 10 jobs per hour per user
- **File Upload**: 5 files per minute per user

### Rate Limit Headers
When rate limiting is active, responses include:
- `X-RateLimit-Limit: <limit>` - Request limit
- `X-RateLimit-Remaining: <remaining>` - Remaining requests
- `X-RateLimit-Reset: <timestamp>` - Reset time

### Rate Limit Exceeded Response
```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
    "suggestion": "Please wait before making additional requests"
  },
  "metadata": {
    "timestamp": "2024-01-15T10:30:00.000Z",
    "requestId": "req_123456789",
    "service": "gateway",
    "retryAfter": 900
  }
}
```

## CORS Support

The gateway supports Cross-Origin Resource Sharing (CORS):

### Allowed Origins
- `https://claude-analysis.com` (Production)
- `https://app.claude-analysis.com` (Production)
- `http://localhost:3000` (Development)
- `http://localhost:3001` (Development)

### Supported Methods
- GET, POST, PUT, PATCH, DELETE, OPTIONS

### Allowed Headers
- Content-Type, Authorization, X-Requested-With, X-API-Key, X-Request-ID

## Circuit Breaker

The gateway implements circuit breakers to handle service failures:

### Circuit Breaker States
- **Closed**: Normal operation, requests pass through
- **Open**: Service is failing, requests are blocked
- **Half-Open**: Testing if service has recovered

### Circuit Breaker Configuration
- **Failure Threshold**: 5 consecutive failures
- **Timeout**: 60 seconds before moving to half-open
- **Reset Timeout**: 30 seconds in half-open state

## Development Features

Development-only endpoints for testing and debugging:

### POST /api/gateway/services/{serviceName}/register
Register a new service instance (development only).

### DELETE /api/gateway/services/{serviceName}
Unregister a service (development only).

### POST /api/gateway/health-check
Force health check execution (development only).

### GET /api/gateway/services/{serviceName}/discover
Test service discovery (development only).

## Monitoring and Observability

### Metrics Available
- HTTP request duration and count
- Service proxy metrics
- Circuit breaker state
- Rate limiting hits
- Authentication metrics
- Error rates by endpoint

### Log Format
All logs follow structured JSON format:
```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "info",
  "service": "gateway",
  "message": "Request completed",
  "metadata": {
    "request": {
      "method": "GET",
      "path": "/api/status",
      "responseTime": 45
    },
    "user": {
      "userId": "user-123"
    }
  }
}
```

### Health Check Endpoints Summary
- `/health` - Basic gateway health
- `/health/services` - Backend service health
- `/health/monitoring` - Monitoring system health
- `/metrics` - Prometheus metrics

## SDK and Client Examples

### JavaScript/Node.js
```javascript
const axios = require('axios');

const client = axios.create({
  baseURL: 'https://api.claude-analysis.com',
  timeout: 30000,
  headers: {
    'Authorization': 'Bearer your-jwt-token',
    'Content-Type': 'application/json'
  }
});

// Example: Submit comments for categorization
const response = await client.post('/api/comments/categorize', {
  comments: ['Great product!', 'Needs improvement'],
  apiKey: 'sk-your-api-key',
  industry: 'SaaS/Technology'
});
```

### Python
```python
import requests

class ClaudeAnalysisClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })
    
    def categorize_comments(self, comments, api_key, industry):
        response = self.session.post(
            f'{self.base_url}/api/comments/categorize',
            json={
                'comments': comments,
                'apiKey': api_key, 
                'industry': industry
            }
        )
        return response.json()
```

### cURL Examples
```bash
# Health check
curl -X GET https://api.claude-analysis.com/health

# Authenticate
curl -X POST https://api.claude-analysis.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'

# Submit comments
curl -X POST https://api.claude-analysis.com/api/comments/categorize \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"comments":["Test comment"],"apiKey":"sk-key"}'
```

## Support and Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - Check if token is provided and valid
   - Verify token hasn't expired
   - Ensure correct authorization header format

2. **503 Service Unavailable** 
   - Backend service may be down
   - Check circuit breaker status
   - Verify service health endpoints

3. **504 Gateway Timeout**
   - Request to backend service timed out
   - Check service performance
   - Consider reducing request size

### Debug Headers
Include `X-Debug: true` header (development only) for additional debugging information.

### Contact Information
- **Support Email**: support@claude-analysis.com
- **Documentation**: https://docs.claude-analysis.com
- **Status Page**: https://status.claude-analysis.com
