// gateway-service/security/ApiKeyManager.js
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const logger = require('../utils/logger');
const configIntegration = require('../utils/configIntegration');

class ApiKeyManager {
  constructor() {
    this.apiKeys = new Map(); // In production, this would be a database
    this.keyMetrics = new Map();
    this.securityConfig = configIntegration.getSecurityConfig();
    this.rateLimits = new Map();
    this.suspiciousActivity = new Map();
    
    this.initializeDefaultKeys();
    this.setupCleanupInterval();
  }

  initializeDefaultKeys() {
    // In production, load from secure database
    // This is just for development/testing
    if (process.env.NODE_ENV === 'development') {
      this.createApiKey({
        name: 'Development Test Key',
        userId: 'dev-user',
        scopes: ['read', 'write'],
        rateLimitTier: 'development'
      }).then(key => {
        logger.info('Development API key created', {
          security: {
            keyId: key.id,
            name: key.name,
            scopes: key.scopes
          }
        });
      });
    }
  }

  // Create new API key
  async createApiKey(options = {}) {
    const {
      name = 'Unnamed Key',
      userId,
      email,
      scopes = ['read'],
      rateLimitTier = 'basic',
      expiresAt = null,
      ipWhitelist = [],
      metadata = {}
    } = options;

    // Generate secure API key
    const keyId = this.generateKeyId();
    const secret = this.generateSecret();
    const hashedSecret = await bcrypt.hash(secret, this.securityConfig.bcryptRounds);
    
    const apiKey = {
      id: keyId,
      name,
      userId,
      email,
      hashedSecret,
      scopes,
      rateLimitTier,
      ipWhitelist,
      metadata,
      createdAt: new Date().toISOString(),
      expiresAt,
      lastUsed: null,
      isActive: true,
      usage: {
        totalRequests: 0,
        lastHour: 0,
        lastDay: 0,
        lastMonth: 0
      },
      security: {
        failedAttempts: 0,
        lastFailedAttempt: null,
        suspiciousActivity: false,
        compromisedAt: null
      }
    };

    // Store the API key
    this.apiKeys.set(keyId, apiKey);
    
    // Initialize metrics
    this.keyMetrics.set(keyId, {
      requests: 0,
      errors: 0,
      lastUsed: null,
      avgResponseTime: 0
    });

    logger.info('API key created', {
      security: {
        keyId,
        name,
        userId,
        scopes,
        rateLimitTier,
        createdBy: email || userId
      }
    });

    // Return key with secret (only time secret is returned)
    return {
      id: keyId,
      secret: `${keyId}.${secret}`,
      name,
      scopes,
      rateLimitTier,
      createdAt: apiKey.createdAt,
      expiresAt
    };
  }

  // Validate API key
  async validateApiKey(providedKey, req = null) {
    try {
      // Parse the key format: keyId.secret
      if (!providedKey || typeof providedKey !== 'string') {
        return { valid: false, reason: 'INVALID_FORMAT' };
      }

      const [keyId, secret] = providedKey.split('.');
      if (!keyId || !secret) {
        return { valid: false, reason: 'INVALID_FORMAT' };
      }

      // Check if key exists
      const apiKey = this.apiKeys.get(keyId);
      if (!apiKey) {
        this.recordFailedAttempt(keyId, req);
        return { valid: false, reason: 'KEY_NOT_FOUND' };
      }

      // Check if key is active
      if (!apiKey.isActive) {
        this.recordFailedAttempt(keyId, req);
        return { valid: false, reason: 'KEY_DISABLED' };
      }

      // Check if key is expired
      if (apiKey.expiresAt && new Date() > new Date(apiKey.expiresAt)) {
        this.recordFailedAttempt(keyId, req);
        return { valid: false, reason: 'KEY_EXPIRED' };
      }

      // Check if key is compromised
      if (apiKey.security.compromisedAt) {
        this.recordFailedAttempt(keyId, req);
        return { valid: false, reason: 'KEY_COMPROMISED' };
      }

      // Check IP whitelist
      if (apiKey.ipWhitelist.length > 0 && req) {
        const clientIP = this.getClientIP(req);
        if (!this.isIPWhitelisted(clientIP, apiKey.ipWhitelist)) {
          this.recordFailedAttempt(keyId, req);
          return { valid: false, reason: 'IP_NOT_WHITELISTED', clientIP };
        }
      }

      // Validate secret
      const isValidSecret = await bcrypt.compare(secret, apiKey.hashedSecret);
      if (!isValidSecret) {
        this.recordFailedAttempt(keyId, req);
        return { valid: false, reason: 'INVALID_SECRET' };
      }

      // Check for suspicious activity
      if (this.detectSuspiciousActivity(keyId, req)) {
        this.recordFailedAttempt(keyId, req);
        return { valid: false, reason: 'SUSPICIOUS_ACTIVITY' };
      }

      // Check rate limits
      const rateLimitResult = this.checkRateLimit(keyId, apiKey.rateLimitTier);
      if (!rateLimitResult.allowed) {
        return { 
          valid: false, 
          reason: 'RATE_LIMIT_EXCEEDED',
          retryAfter: rateLimitResult.retryAfter
        };
      }

      // Update usage statistics
      this.updateUsageStats(keyId, req);

      // Reset failed attempts on successful validation
      apiKey.security.failedAttempts = 0;
      apiKey.lastUsed = new Date().toISOString();

      return {
        valid: true,
        apiKey: {
          id: keyId,
          name: apiKey.name,
          userId: apiKey.userId,
          email: apiKey.email,
          scopes: apiKey.scopes,
          rateLimitTier: apiKey.rateLimitTier,
          metadata: apiKey.metadata
        }
      };
    } catch (error) {
      logger.error('API key validation error', {
        security: {
          error: error.message,
          ip: req?.ip
        }
      }, error);
      
      return { valid: false, reason: 'VALIDATION_ERROR' };
    }
  }

  // Check if API key has required scope
  hasScope(apiKey, requiredScope) {
    if (!apiKey || !apiKey.scopes) {
      return false;
    }

    // Check for wildcard scope
    if (apiKey.scopes.includes('*')) {
      return true;
    }

    // Check for specific scope
    if (apiKey.scopes.includes(requiredScope)) {
      return true;
    }

    // Check for parent scope (e.g., 'admin' includes 'read', 'write')
    const scopeHierarchy = {
      'admin': ['read', 'write', 'delete', 'manage'],
      'write': ['read'],
      'manage': ['read', 'write']
    };

    for (const scope of apiKey.scopes) {
      if (scopeHierarchy[scope] && scopeHierarchy[scope].includes(requiredScope)) {
        return true;
      }
    }

    return false;
  }

  // Rate limiting for API keys
  checkRateLimit(keyId, tier) {
    const now = Date.now();
    const rateLimitConfig = this.getRateLimitConfig(tier);
    
    if (!this.rateLimits.has(keyId)) {
      this.rateLimits.set(keyId, {
        requests: [],
        resetTime: now + rateLimitConfig.windowMs
      });
    }

    const keyLimits = this.rateLimits.get(keyId);
    
    // Clean old requests outside the window
    keyLimits.requests = keyLimits.requests.filter(
      timestamp => now - timestamp < rateLimitConfig.windowMs
    );

    // Check if limit exceeded
    if (keyLimits.requests.length >= rateLimitConfig.maxRequests) {
      const oldestRequest = Math.min(...keyLimits.requests);
      const retryAfter = Math.ceil((oldestRequest + rateLimitConfig.windowMs - now) / 1000);
      
      return {
        allowed: false,
        retryAfter,
        remaining: 0,
        resetTime: oldestRequest + rateLimitConfig.windowMs
      };
    }

    // Add current request
    keyLimits.requests.push(now);

    return {
      allowed: true,
      remaining: rateLimitConfig.maxRequests - keyLimits.requests.length,
      resetTime: keyLimits.resetTime
    };
  }

  getRateLimitConfig(tier) {
    const configs = {
      development: { maxRequests: 1000, windowMs: 60 * 1000 }, // 1000/minute
      basic: { maxRequests: 100, windowMs: 60 * 1000 }, // 100/minute
      premium: { maxRequests: 500, windowMs: 60 * 1000 }, // 500/minute
      enterprise: { maxRequests: 2000, windowMs: 60 * 1000 }, // 2000/minute
      unlimited: { maxRequests: Infinity, windowMs: 60 * 1000 }
    };

    return configs[tier] || configs.basic;
  }

  // Detect suspicious activity
  detectSuspiciousActivity(keyId, req) {
    if (!req) return false;

    const now = Date.now();
    const clientIP = this.getClientIP(req);
    const userAgent = req.get('User-Agent') || '';
    
    if (!this.suspiciousActivity.has(keyId)) {
      this.suspiciousActivity.set(keyId, {
        ips: new Map(),
        userAgents: new Set(),
        requestPatterns: [],
        lastCheck: now
      });
    }

    const activity = this.suspiciousActivity.get(keyId);
    
    // Track IP usage
    if (!activity.ips.has(clientIP)) {
      activity.ips.set(clientIP, 0);
    }
    activity.ips.set(clientIP, activity.ips.get(clientIP) + 1);

    // Track User-Agent
    activity.userAgents.add(userAgent);

    // Check for suspicious patterns
    const suspiciousPatterns = [
      // Too many different IPs in short time
      activity.ips.size > 10 && (now - activity.lastCheck) < 300000, // 5 minutes
      
      // Too many different user agents
      activity.userAgents.size > 5,
      
      // Suspicious user agent patterns
      /bot|crawler|spider|scraper/i.test(userAgent) && !userAgent.includes('Googlebot'),
      
      // Empty or suspicious user agent
      !userAgent || userAgent.length < 10,
      
      // Rapid requests from single IP (handled by rate limiting, but flag as suspicious)
      activity.ips.get(clientIP) > 50
    ];

    const isSuspicious = suspiciousPatterns.some(pattern => pattern);
    
    if (isSuspicious) {
      logger.warn('Suspicious API key activity detected', {
        security: {
          keyId,
          clientIP,
          userAgent,
          uniqueIPs: activity.ips.size,
          uniqueUserAgents: activity.userAgents.size,
          patterns: suspiciousPatterns.map((p, i) => p ? i : null).filter(i => i !== null)
        }
      });
      
      // Mark key as having suspicious activity
      const apiKey = this.apiKeys.get(keyId);
      if (apiKey) {
        apiKey.security.suspiciousActivity = true;
      }
    }

    activity.lastCheck = now;
    return isSuspicious;
  }

  // Record failed authentication attempt
  recordFailedAttempt(keyId, req) {
    const apiKey = this.apiKeys.get(keyId);
    if (apiKey) {
      apiKey.security.failedAttempts++;
      apiKey.security.lastFailedAttempt = new Date().toISOString();
      
      // Auto-disable key after too many failed attempts
      if (apiKey.security.failedAttempts >= 10) {
        apiKey.isActive = false;
        logger.warn('API key disabled due to failed attempts', {
          security: {
            keyId,
            failedAttempts: apiKey.security.failedAttempts,
            userId: apiKey.userId
          }
        });
      }
    }

    logger.warn('Failed API key authentication', {
      security: {
        keyId: keyId || 'unknown',
        ip: req?.ip,
        userAgent: req?.get('User-Agent'),
        failedAttempts: apiKey?.security.failedAttempts || 0
      }
    });
  }

  // Update usage statistics
  updateUsageStats(keyId, req) {
    const apiKey = this.apiKeys.get(keyId);
    const metrics = this.keyMetrics.get(keyId);
    
    if (apiKey) {
      apiKey.usage.totalRequests++;
      apiKey.usage.lastHour++;
      apiKey.usage.lastDay++;
      apiKey.usage.lastMonth++;
    }

    if (metrics) {
      metrics.requests++;
      metrics.lastUsed = new Date().toISOString();
    }
  }

  // Utility methods
  generateKeyId() {
    return crypto.randomBytes(16).toString('hex');
  }

  generateSecret() {
    return crypto.randomBytes(32).toString('base64url');
  }

  getClientIP(req) {
    return req.ip || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress ||
           (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
           '0.0.0.0';
  }

  isIPWhitelisted(clientIP, whitelist) {
    if (whitelist.length === 0) return true;
    
    return whitelist.some(allowedIP => {
      // Support CIDR notation
      if (allowedIP.includes('/')) {
        return this.isIPInCIDR(clientIP, allowedIP);
      }
      // Support wildcard
      if (allowedIP.includes('*')) {
        const pattern = allowedIP.replace(/\*/g, '.*');
        return new RegExp(`^${pattern}$`).test(clientIP);
      }
      // Exact match
      return clientIP === allowedIP;
    });
  }

  isIPInCIDR(ip, cidr) {
    // Simple CIDR check - in production, use a proper library
    const [network, mask] = cidr.split('/');
    const networkParts = network.split('.').map(Number);
    const ipParts = ip.split('.').map(Number);
    const maskBits = parseInt(mask);
    
    if (maskBits === 0) return true;
    if (maskBits >= 32) return ip === network;
    
    const networkInt = (networkParts[0] << 24) + (networkParts[1] << 16) + (networkParts[2] << 8) + networkParts[3];
    const ipInt = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
    const maskInt = (-1 << (32 - maskBits)) >>> 0;
    
    return (networkInt & maskInt) === (ipInt & maskInt);
  }

  // Management methods
  async revokeApiKey(keyId, reason = 'Revoked by admin') {
    const apiKey = this.apiKeys.get(keyId);
    if (!apiKey) {
      throw new Error('API key not found');
    }

    apiKey.isActive = false;
    apiKey.security.compromisedAt = new Date().toISOString();

    logger.warn('API key revoked', {
      security: {
        keyId,
        userId: apiKey.userId,
        reason
      }
    });

    return true;
  }

  async updateApiKey(keyId, updates) {
    const apiKey = this.apiKeys.get(keyId);
    if (!apiKey) {
      throw new Error('API key not found');
    }

    const allowedUpdates = ['name', 'scopes', 'rateLimitTier', 'expiresAt', 'ipWhitelist', 'metadata'];
    
    for (const [key, value] of Object.entries(updates)) {
      if (allowedUpdates.includes(key)) {
        apiKey[key] = value;
      }
    }

    logger.info('API key updated', {
      security: {
        keyId,
        userId: apiKey.userId,
        updates: Object.keys(updates)
      }
    });

    return this.getApiKeyInfo(keyId);
  }

  getApiKeyInfo(keyId) {
    const apiKey = this.apiKeys.get(keyId);
    if (!apiKey) {
      return null;
    }

    const metrics = this.keyMetrics.get(keyId);

    return {
      id: keyId,
      name: apiKey.name,
      userId: apiKey.userId,
      email: apiKey.email,
      scopes: apiKey.scopes,
      rateLimitTier: apiKey.rateLimitTier,
      ipWhitelist: apiKey.ipWhitelist,
      metadata: apiKey.metadata,
      createdAt: apiKey.createdAt,
      expiresAt: apiKey.expiresAt,
      lastUsed: apiKey.lastUsed,
      isActive: apiKey.isActive,
      usage: apiKey.usage,
      metrics: metrics,
      security: {
        failedAttempts: apiKey.security.failedAttempts,
        suspiciousActivity: apiKey.security.suspiciousActivity,
        compromisedAt: apiKey.security.compromisedAt
      }
    };
  }

  getAllApiKeys(userId = null) {
    const keys = Array.from(this.apiKeys.entries())
      .map(([keyId, apiKey]) => {
        if (userId && apiKey.userId !== userId) {
          return null;
        }
        return this.getApiKeyInfo(keyId);
      })
      .filter(Boolean);

    return keys;
  }

  // Statistics and monitoring
  getSecurityStats() {
    const totalKeys = this.apiKeys.size;
    const activeKeys = Array.from(this.apiKeys.values()).filter(key => key.isActive).length;
    const compromisedKeys = Array.from(this.apiKeys.values()).filter(key => key.security.compromisedAt).length;
    const suspiciousKeys = Array.from(this.apiKeys.values()).filter(key => key.security.suspiciousActivity).length;

    return {
      totalKeys,
      activeKeys,
      inactiveKeys: totalKeys - activeKeys,
      compromisedKeys,
      suspiciousKeys,
      rateLimitedKeys: this.rateLimits.size
    };
  }

  // Cleanup methods
  setupCleanupInterval() {
    // Clean up old rate limit data every 5 minutes
    setInterval(() => {
      this.cleanupRateLimits();
      this.cleanupSuspiciousActivity();
      this.resetUsageCounters();
    }, 5 * 60 * 1000);
  }

  cleanupRateLimits() {
    const now = Date.now();
    
    for (const [keyId, limits] of this.rateLimits.entries()) {
      limits.requests = limits.requests.filter(
        timestamp => now - timestamp < 60 * 60 * 1000 // Keep last hour
      );
      
      if (limits.requests.length === 0) {
        this.rateLimits.delete(keyId);
      }
    }
  }

  cleanupSuspiciousActivity() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    for (const [keyId, activity] of this.suspiciousActivity.entries()) {
      if (now - activity.lastCheck > maxAge) {
        this.suspiciousActivity.delete(keyId);
      }
    }
  }

  resetUsageCounters() {
    const now = new Date();
    const hour = now.getHours();
    const day = now.getDate();
    const month = now.getMonth();
    
    // Reset hourly counters
    if (hour === 0) {
      for (const apiKey of this.apiKeys.values()) {
        apiKey.usage.lastHour = 0;
      }
    }
    
    // Reset daily counters
    if (hour === 0 && day === 1) {
      for (const apiKey of this.apiKeys.values()) {
        apiKey.usage.lastDay = 0;
      }
    }
    
    // Reset monthly counters
    if (hour === 0 && day === 1 && month === 0) {
      for (const apiKey of this.apiKeys.values()) {
        apiKey.usage.lastMonth = 0;
      }
    }
  }

  cleanup() {
    this.apiKeys.clear();
    this.keyMetrics.clear();
    this.rateLimits.clear();
    this.suspiciousActivity.clear();
    
    logger.info('API key manager cleaned up');
  }
}

module.exports = ApiKeyManager;