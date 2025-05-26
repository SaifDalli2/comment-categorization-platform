// gateway-service/routes/securityManagement.js
const express = require('express');
const logger = require('../utils/logger');

class SecurityManagementRoutes {
  constructor(enhancedSecurityManager) {
    this.router = express.Router();
    this.securityManager = enhancedSecurityManager;
    this.apiKeyManager = enhancedSecurityManager.getApiKeyManager();
    this.signatureValidator = enhancedSecurityManager.getSignatureValidator();
    this.setupRoutes();
  }

  setupRoutes() {
    // API Key Management Routes
    this.setupApiKeyRoutes();
    
    // Security Monitoring Routes
    this.setupSecurityMonitoringRoutes();
    
    // Signature Validation Routes
    this.setupSignatureRoutes();
    
    // IP Management Routes
    this.setupIPManagementRoutes();
  }

  setupApiKeyRoutes() {
    // Create new API key (authenticated users)
    this.router.post('/api/security/api-keys', this.requireAuth(), async (req, res) => {
      try {
        const {
          name,
          scopes = ['read'],
          rateLimitTier = 'basic',
          expiresAt,
          ipWhitelist = [],
          metadata = {}
        } = req.body;

        if (!name || name.trim().length === 0) {
          return res.error.validation('API key name is required');
        }

        // Validate scopes
        const validScopes = ['read', 'write', 'delete', 'admin', 'manage'];
        const invalidScopes = scopes.filter(scope => !validScopes.includes(scope));
        if (invalidScopes.length > 0) {
          return res.error.validation(`Invalid scopes: ${invalidScopes.join(', ')}`);
        }

        // Validate rate limit tier
        const validTiers = ['basic', 'premium', 'enterprise', 'unlimited'];
        if (!validTiers.includes(rateLimitTier)) {
          return res.error.validation('Invalid rate limit tier');
        }

        // Check user permissions for advanced features
        const userRoles = req.userContext.roles || [];
        if (scopes.includes('admin') && !userRoles.includes('admin')) {
          return res.error.forbidden('Admin scope requires admin role');
        }

        if (rateLimitTier === 'unlimited' && !userRoles.includes('super_admin')) {
          return res.error.forbidden('Unlimited tier requires super admin role');
        }

        const apiKey = await this.apiKeyManager.createApiKey({
          name: name.trim(),
          userId: req.userContext.userId,
          email: req.userContext.email,
          scopes,
          rateLimitTier,
          expiresAt,
          ipWhitelist,
          metadata
        });

        logger.info('API key created via API', {
          security: {
            keyId: apiKey.id,
            name: apiKey.name,
            createdBy: req.userContext.email,
            scopes: apiKey.scopes,
            rateLimitTier: apiKey.rateLimitTier
          }
        });

        res.json({
          success: true,
          data: {
            ...apiKey,
            warning: 'Store this secret securely. It will not be shown again.'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('API key creation failed', {
          error: error.message,
          userId: req.userContext.userId
        }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to create API key');
      }
    });

    // List user's API keys
    this.router.get('/api/security/api-keys', this.requireAuth(), (req, res) => {
      try {
        const userKeys = this.apiKeyManager.getAllApiKeys(req.userContext.userId);
        
        // Remove sensitive information
        const sanitizedKeys = userKeys.map(key => ({
          id: key.id,
          name: key.name,
          scopes: key.scopes,
          rateLimitTier: key.rateLimitTier,
          createdAt: key.createdAt,
          expiresAt: key.expiresAt,
          lastUsed: key.lastUsed,
          isActive: key.isActive,
          usage: key.usage,
          ipWhitelist: key.ipWhitelist,
          metadata: key.metadata
        }));

        res.json({
          success: true,
          data: {
            apiKeys: sanitizedKeys,
            total: sanitizedKeys.length
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Failed to retrieve API keys', {
          error: error.message,
          userId: req.userContext.userId
        }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve API keys');
      }
    });

    // Get specific API key details
    this.router.get('/api/security/api-keys/:keyId', this.requireAuth(), (req, res) => {
      try {
        const { keyId } = req.params;
        const keyInfo = this.apiKeyManager.getApiKeyInfo(keyId);
        
        if (!keyInfo) {
          return res.error.notFound('API key not found');
        }

        // Check ownership (admins can view any key)
        if (keyInfo.userId !== req.userContext.userId && !req.userContext.roles?.includes('admin')) {
          return res.error.forbidden('You can only view your own API keys');
        }

        res.json({
          success: true,
          data: keyInfo,
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Failed to retrieve API key details', {
          error: error.message,
          keyId: req.params.keyId,
          userId: req.userContext.userId
        }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve API key details');
      }
    });

    // Update API key
    this.router.put('/api/security/api-keys/:keyId', this.requireAuth(), async (req, res) => {
      try {
        const { keyId } = req.params;
        const updates = req.body;
        
        const keyInfo = this.apiKeyManager.getApiKeyInfo(keyId);
        if (!keyInfo) {
          return res.error.notFound('API key not found');
        }

        // Check ownership (admins can update any key)
        if (keyInfo.userId !== req.userContext.userId && !req.userContext.roles?.includes('admin')) {
          return res.error.forbidden('You can only update your own API keys');
        }

        // Validate updates
        if (updates.scopes) {
          const validScopes = ['read', 'write', 'delete', 'admin', 'manage'];
          const invalidScopes = updates.scopes.filter(scope => !validScopes.includes(scope));
          if (invalidScopes.length > 0) {
            return res.error.validation(`Invalid scopes: ${invalidScopes.join(', ')}`);
          }
        }

        const updatedKey = await this.apiKeyManager.updateApiKey(keyId, updates);
        
        logger.info('API key updated via API', {
          security: {
            keyId,
            updatedBy: req.userContext.email,
            updates: Object.keys(updates)
          }
        });

        res.json({
          success: true,
          data: updatedKey,
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('API key update failed', {
          error: error.message,
          keyId: req.params.keyId,
          userId: req.userContext.userId
        }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to update API key');
      }
    });

    // Revoke API key
    this.router.delete('/api/security/api-keys/:keyId', this.requireAuth(), async (req, res) => {
      try {
        const { keyId } = req.params;
        const { reason } = req.body;
        
        const keyInfo = this.apiKeyManager.getApiKeyInfo(keyId);
        if (!keyInfo) {
          return res.error.notFound('API key not found');
        }

        // Check ownership (admins can revoke any key)
        if (keyInfo.userId !== req.userContext.userId && !req.userContext.roles?.includes('admin')) {
          return res.error.forbidden('You can only revoke your own API keys');
        }

        await this.apiKeyManager.revokeApiKey(keyId, reason || `Revoked by ${req.userContext.email}`);
        
        logger.warn('API key revoked via API', {
          security: {
            keyId,
            revokedBy: req.userContext.email,
            reason: reason || 'No reason provided'
          }
        });

        res.json({
          success: true,
          data: {
            keyId,
            revoked: true,
            reason: reason || 'Revoked by user'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('API key revocation failed', {
          error: error.message,
          keyId: req.params.keyId,
          userId: req.userContext.userId
        }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to revoke API key');
      }
    });

    // Admin: List all API keys
    this.router.get('/api/security/admin/api-keys', this.requireAdmin(), (req, res) => {
      try {
        const { userId, status, rateLimitTier } = req.query;
        
        let allKeys = this.apiKeyManager.getAllApiKeys();
        
        // Apply filters
        if (userId) {
          allKeys = allKeys.filter(key => key.userId === userId);
        }
        
        if (status) {
          const isActive = status === 'active';
          allKeys = allKeys.filter(key => key.isActive === isActive);
        }
        
        if (rateLimitTier) {
          allKeys = allKeys.filter(key => key.rateLimitTier === rateLimitTier);
        }

        res.json({
          success: true,
          data: {
            apiKeys: allKeys,
            total: allKeys.length,
            filters: { userId, status, rateLimitTier }
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Failed to retrieve all API keys', {
          error: error.message,
          adminUser: req.userContext.email
        }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve API keys');
      }
    });
  }

  setupSecurityMonitoringRoutes() {
    // Get security statistics
    this.router.get('/api/security/stats', this.requireAuth(), (req, res) => {
      try {
        const stats = this.securityManager.getSecurityStats();
        
        res.json({
          success: true,
          data: stats,
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Failed to retrieve security stats', { error: error.message }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve security statistics');
      }
    });

    // Get recent security events (admin only)
    this.router.get('/api/security/events', this.requireAdmin(), (req, res) => {
      try {
        const { limit = 100, eventType } = req.query;
        const events = this.securityManager.getRecentSecurityEvents(
          parseInt(limit),
          eventType || null
        );

        res.json({
          success: true,
          data: {
            events,
            total: events.length,
            filters: { limit, eventType }
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Failed to retrieve security events', { error: error.message }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve security events');
      }
    });

    // Security health check
    this.router.get('/api/security/health', (req, res) => {
      try {
        const health = this.securityManager.getSecurityHealth();
        
        res.status(health.status === 'healthy' ? 200 : 503).json({
          status: health.status,
          timestamp: health.timestamp,
          service: 'gateway-security',
          details: health
        });
      } catch (error) {
        logger.error('Security health check failed', { error: error.message }, error);
        res.status(503).json({
          status: 'unhealthy',
          timestamp: new Date().toISOString(),
          service: 'gateway-security',
          error: error.message
        });
      }
    });
  }

  setupSignatureRoutes() {
    // Generate signature headers (for client implementation)
    this.router.post('/api/security/signature/generate', this.requireAuth(), async (req, res) => {
      try {
        const {
          method = 'GET',
          path = '/',
          body = '',
          scheme = 'hmac-sha256',
          secret
        } = req.body;

        if (!secret) {
          return res.error.validation('Secret is required for signature generation');
        }

        const headers = await this.signatureValidator.generateSignatureHeaders(
          method,
          path,
          body,
          { scheme, secret }
        );

        res.json({
          success: true,
          data: {
            headers,
            scheme,
            note: 'These headers should be included in your request'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Signature generation failed', { error: error.message }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to generate signature');
      }
    });

    // Get signature validation info
    this.router.get('/api/security/signature/info', (req, res) => {
      try {
        const info = this.signatureValidator.getSignatureStats();
        
        res.json({
          success: true,
          data: {
            ...info,
            documentation: {
              requiredHeaders: [
                'X-Timestamp: Unix timestamp',
                'X-Nonce: Random string',
                'X-Signature: Generated signature',
                'X-Key-Id: API key ID (optional)'
              ],
              supportedAlgorithms: ['hmac-sha256', 'rsa-sha256', 'simple-hash'],
              timestampTolerance: `${info.timestampTolerance} seconds`
            }
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Failed to retrieve signature info', { error: error.message }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve signature information');
      }
    });
  }

  setupIPManagementRoutes() {
    // Block IP address (admin only)
    this.router.post('/api/security/ip/block', this.requireAdmin(), (req, res) => {
      try {
        const { ip, reason, duration } = req.body;
        
        if (!ip) {
          return res.error.validation('IP address is required');
        }

        // Validate IP format
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
          return res.error.validation('Invalid IP address format');
        }

        const blockDuration = duration ? parseInt(duration) * 1000 : undefined;
        this.securityManager.blockIP(ip, reason || `Blocked by ${req.userContext.email}`, blockDuration);

        logger.warn('IP blocked via API', {
          security: {
            ip,
            reason: reason || 'Manual block',
            blockedBy: req.userContext.email,
            duration: blockDuration ? blockDuration / 1000 / 60 : 'permanent'
          }
        });

        res.json({
          success: true,
          data: {
            ip,
            blocked: true,
            reason: reason || 'Manual block',
            duration: blockDuration
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('IP blocking failed', { error: error.message }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to block IP address');
      }
    });

    // Unblock IP address (admin only)
    this.router.delete('/api/security/ip/block/:ip', this.requireAdmin(), (req, res) => {
      try {
        const { ip } = req.params;
        
        // Remove from blocked IPs
        const wasBlocked = this.securityManager.blockedIPs.has(ip);
        this.securityManager.blockedIPs.delete(ip);

        logger.info('IP unblocked via API', {
          security: {
            ip,
            unblockedBy: req.userContext.email,
            wasBlocked
          }
        });

        res.json({
          success: true,
          data: {
            ip,
            unblocked: wasBlocked,
            message: wasBlocked ? 'IP successfully unblocked' : 'IP was not blocked'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('IP unblocking failed', { error: error.message }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to unblock IP address');
      }
    });

    // List blocked IPs (admin only)
    this.router.get('/api/security/ip/blocked', this.requireAdmin(), (req, res) => {
      try {
        const blockedIPs = Array.from(this.securityManager.blockedIPs);
        
        res.json({
          success: true,
          data: {
            blockedIPs,
            total: blockedIPs.length
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      } catch (error) {
        logger.error('Failed to retrieve blocked IPs', { error: error.message }, error);
        return res.error.send('INTERNAL_ERROR', 'Failed to retrieve blocked IPs');
      }
    });
  }

  // Helper middleware methods
  requireAuth() {
    return (req, res, next) => {
      if (!req.userContext || !req.userContext.userId) {
        return res.error.unauthorized('Authentication required');
      }
      next();
    };
  }

  requireAdmin() {
    return (req, res, next) => {
      if (!req.userContext?.roles?.includes('admin')) {
        return res.error.forbidden('Admin access required');
      }
      next();
    };
  }

  getRouter() {
    return this.router;
  }
}

module.exports = SecurityManagementRoutes;