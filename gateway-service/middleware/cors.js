// gateway-service/middleware/cors.js
const cors = require('cors');

class CorsManager {
  constructor() {
    this.allowedOrigins = this.parseOrigins();
    this.corsOptions = this.createCorsOptions();
  }

  parseOrigins() {
    const origins = process.env.ALLOWED_ORIGINS?.split(',') || [];
    
    // Default allowed origins for development
    const defaultOrigins = [
      'http://localhost:3000',
      'http://localhost:3001', 
      'http://localhost:8080',
      'http://127.0.0.1:3000'
    ];

    // Add production origins
    const productionOrigins = [];
    if (process.env.PRODUCTION_DOMAIN) {
      productionOrigins.push(
        `https://${process.env.PRODUCTION_DOMAIN}`,
        `https://www.${process.env.PRODUCTION_DOMAIN}`
      );
    }

    return [...new Set([...origins, ...defaultOrigins, ...productionOrigins])];
  }

  createCorsOptions() {
    return {
      origin: (origin, callback) => {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) {
          return callback(null, true);
        }

        // Check if origin is in allowed list
        if (this.allowedOrigins.includes(origin)) {
          return callback(null, true);
        }

        // Allow localhost in development
        if (process.env.NODE_ENV === 'development' && 
            (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
          return callback(null, true);
        }

        // Log rejected origins for debugging
        console.warn(`🚫 CORS: Rejected origin: ${origin}`);
        
        const error = new Error(`CORS policy violation: Origin ${origin} not allowed`);
        error.status = 403;
        callback(error, false);
      },
      
      credentials: true, // Allow cookies and auth headers
      
      methods: [
        'GET',
        'POST', 
        'PUT',
        'PATCH',
        'DELETE',
        'OPTIONS',
        'HEAD'
      ],
      
      allowedHeaders: [
        'Content-Type',
        'Authorization', 
        'X-Requested-With',
        'Accept',
        'Origin',
        'Cache-Control',
        'X-File-Name',
        process.env.API_KEY_HEADER || 'x-api-key',
        'X-Gateway-Request-ID',
        'X-User-Agent'
      ],
      
      exposedHeaders: [
        'X-Total-Count',
        'X-Rate-Limit-Limit',
        'X-Rate-Limit-Remaining', 
        'X-Rate-Limit-Reset',
        'X-Served-By',
        'X-Service-ID',
        'X-Response-Time'
      ],
      
      optionsSuccessStatus: 200, // For legacy browser support
      
      maxAge: 86400, // Cache preflight response for 24 hours
      
      preflightContinue: false
    };
  }

  // Dynamic CORS middleware
  dynamicCors() {
    return (req, res, next) => {
      // Enhanced CORS for different routes
      let corsOptions = { ...this.corsOptions };
      
      // Stricter CORS for admin endpoints
      if (req.path.startsWith('/admin')) {
        corsOptions.origin = (origin, callback) => {
          // Only allow specific admin origins
          const adminOrigins = process.env.ADMIN_ORIGINS?.split(',') || this.allowedOrigins;
          
          if (!origin || adminOrigins.includes(origin)) {
            callback(null, true);
          } else {
            console.warn(`🚫 Admin CORS: Rejected origin: ${origin}`);
            callback(new Error('Admin access not allowed from this origin'), false);
          }
        };
      }
      
      // More permissive CORS for public API endpoints
      if (req.path.startsWith('/api/public')) {
        corsOptions.origin = true; // Allow all origins
        corsOptions.credentials = false; // No credentials for public endpoints
      }
      
      cors(corsOptions)(req, res, next);
    };
  }

  // Preflight handler for complex requests
  handlePreflight() {
    return (req, res, next) => {
      if (req.method === 'OPTIONS') {
        // Log preflight requests for debugging
        console.log(`✈️ CORS Preflight: ${req.get('Origin')} -> ${req.get('Access-Control-Request-Method')} ${req.path}`);
        
        // Set additional headers for preflight
        res.setHeader('Access-Control-Max-Age', '86400');
        res.setHeader('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
        
        // Custom handling for different routes
        if (req.path.startsWith('/api/upload')) {
          res.setHeader('Access-Control-Allow-Headers', 
            res.get('Access-Control-Allow-Headers') + ', Content-Length, X-File-Name');
        }
        
        return res.status(200).end();
      }
      
      next();
    };
  }

  // CORS error handler
  handleCorsError() {
    return (err, req, res, next) => {
      if (err.message && err.message.includes('CORS')) {
        console.error(`🚫 CORS Error: ${err.message} for ${req.get('Origin')}`);
        
        return res.status(403).json({
          error: 'CORS Policy Violation',
          message: 'Cross-origin request blocked by CORS policy',
          origin: req.get('Origin'),
          allowedOrigins: process.env.NODE_ENV === 'development' ? this.allowedOrigins : undefined,
          timestamp: new Date().toISOString()
        });
      }
      
      next(err);
    };
  }

  // Security headers for CORS
  securityHeaders() {
    return (req, res, next) => {
      // Prevent MIME type sniffing
      res.setHeader('X-Content-Type-Options', 'nosniff');
      
      // Prevent clickjacking
      res.setHeader('X-Frame-Options', 'DENY');
      
      // XSS protection
      res.setHeader('X-XSS-Protection', '1; mode=block');
      
      // Referrer policy
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      
      // Permissions policy
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
      
      next();
    };
  }

  // Get CORS configuration info
  getCorsInfo() {
    return {
      allowedOrigins: this.allowedOrigins,
      allowedMethods: this.corsOptions.methods,
      allowedHeaders: this.corsOptions.allowedHeaders,
      exposedHeaders: this.corsOptions.exposedHeaders,
      credentials: this.corsOptions.credentials,
      maxAge: this.corsOptions.maxAge
    };
  }

  // Update allowed origins dynamically (for development)
  updateAllowedOrigins(origins) {
    if (process.env.NODE_ENV === 'development') {
      this.allowedOrigins = [...new Set([...this.allowedOrigins, ...origins])];
      console.log(`📝 CORS: Updated allowed origins:`, this.allowedOrigins);
      return true;
    }
    return false;
  }

  // Validate origin format
  isValidOrigin(origin) {
    try {
      const url = new URL(origin);
      return ['http:', 'https:'].includes(url.protocol);
    } catch (error) {
      return false;
    }
  }
}

module.exports = CorsManager;