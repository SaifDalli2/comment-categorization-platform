// gateway-service/security/SignatureValidator.js
const crypto = require('crypto');
const logger = require('../utils/logger');

class SignatureValidator {
  constructor(options = {}) {
    this.algorithm = options.algorithm || 'sha256';
    this.timestampTolerance = options.timestampTolerance || 300; // 5 minutes
    this.requiredHeaders = options.requiredHeaders || [
      'x-timestamp',
      'x-nonce', 
      'x-signature'
    ];
    this.signatureSchemes = new Map();
    
    this.initializeSchemes();
  }

  initializeSchemes() {
    // HMAC-SHA256 signature scheme
    this.signatureSchemes.set('hmac-sha256', {
      sign: this.signHMAC.bind(this),
      verify: this.verifyHMAC.bind(this),
      description: 'HMAC-SHA256 signature with timestamp and nonce'
    });

    // RSA signature scheme  
    this.signatureSchemes.set('rsa-sha256', {
      sign: this.signRSA.bind(this),
      verify: this.verifyRSA.bind(this),
      description: 'RSA-SHA256 signature with timestamp and nonce'
    });

    // Simple hash scheme (less secure, for development)
    this.signatureSchemes.set('simple-hash', {
      sign: this.signSimpleHash.bind(this),
      verify: this.verifySimpleHash.bind(this),
      description: 'Simple SHA256 hash (development only)'
    });
  }

  // Main signature validation middleware
  validateSignature(options = {}) {
    const {
      scheme = 'hmac-sha256',
      secret = null,
      publicKey = null,
      privateKey = null,
      optional = false,
      skipPaths = []
    } = options;

    return async (req, res, next) => {
      // Skip validation for certain paths
      if (skipPaths.some(path => req.path.startsWith(path))) {
        return next();
      }

      try {
        const validationResult = await this.validateRequestSignature(req, {
          scheme,
          secret,
          publicKey,
          privateKey
        });

        if (!validationResult.valid) {
          if (optional) {
            req.signatureValidation = validationResult;
            return next();
          }

          logger.warn('Request signature validation failed', {
            security: {
              reason: validationResult.reason,
              scheme,
              path: req.path,
              method: req.method,
              ip: req.ip,
              userAgent: req.get('User-Agent')
            }
          });

          return res.status(401).json({
            success: false,
            error: {
              code: 'INVALID_SIGNATURE',
              message: 'Request signature validation failed',
              suggestion: 'Ensure your request is properly signed according to the API documentation'
            },
            metadata: {
              timestamp: new Date().toISOString(),
              requestId: req.headers['x-request-id'],
              service: 'gateway'
            }
          });
        }

        // Attach signature info to request
        req.signatureValidation = validationResult;
        req.signedRequest = true;

        logger.debug('Request signature validated successfully', {
          security: {
            scheme,
            keyId: validationResult.keyId,
            timestamp: validationResult.timestamp
          }
        });

        next();
      } catch (error) {
        logger.error('Signature validation error', {
          security: {
            error: error.message,
            scheme,
            path: req.path,
            ip: req.ip
          }
        }, error);

        if (optional) {
          req.signatureValidation = { valid: false, reason: 'VALIDATION_ERROR' };
          return next();
        }

        return res.status(500).json({
          success: false,
          error: {
            code: 'SIGNATURE_VALIDATION_ERROR',
            message: 'Unable to validate request signature',
            suggestion: 'Please try again or contact support'
          },
          metadata: {
            timestamp: new Date().toISOString(),
            requestId: req.headers['x-request-id'],
            service: 'gateway'
          }
        });
      }
    };
  }

  // Validate request signature
  async validateRequestSignature(req, options = {}) {
    const { scheme, secret, publicKey } = options;
    
    // Check if scheme is supported
    const signatureScheme = this.signatureSchemes.get(scheme);
    if (!signatureScheme) {
      return { valid: false, reason: 'UNSUPPORTED_SCHEME' };
    }

    // Extract signature headers
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    const keyId = req.headers['x-key-id'];

    // Check required headers
    if (!signature) {
      return { valid: false, reason: 'MISSING_SIGNATURE' };
    }

    if (!timestamp) {
      return { valid: false, reason: 'MISSING_TIMESTAMP' };
    }

    if (!nonce) {
      return { valid: false, reason: 'MISSING_NONCE' };
    }

    // Validate timestamp
    const timestampValidation = this.validateTimestamp(timestamp);
    if (!timestampValidation.valid) {
      return timestampValidation;
    }

    // Validate nonce (check for replay attacks)
    const nonceValidation = await this.validateNonce(nonce, timestamp);
    if (!nonceValidation.valid) {
      return nonceValidation;
    }

    // Create string to sign
    const stringToSign = this.createStringToSign(req, timestamp, nonce);

    // Verify signature based on scheme
    const verificationResult = await signatureScheme.verify(
      stringToSign,
      signature,
      { secret, publicKey, keyId }
    );

    if (!verificationResult.valid) {
      return verificationResult;
    }

    // Store nonce to prevent replay
    await this.storeNonce(nonce, timestamp);

    return {
      valid: true,
      scheme,
      keyId,
      timestamp: new Date(parseInt(timestamp) * 1000).toISOString(),
      nonce
    };
  }

  // Create string to sign (canonical request representation)
  createStringToSign(req, timestamp, nonce) {
    const method = req.method.toUpperCase();
    const path = req.path;
    const query = this.canonicalizeQueryString(req.query);
    const headers = this.canonicalizeHeaders(req.headers);
    const bodyHash = this.hashRequestBody(req.rawBody || '');

    const stringToSign = [
      method,
      path,
      query,
      headers,
      bodyHash,
      timestamp,
      nonce
    ].join('\n');

    return stringToSign;
  }

  // Canonicalize query string
  canonicalizeQueryString(query) {
    if (!query || Object.keys(query).length === 0) {
      return '';
    }

    return Object.keys(query)
      .sort()
      .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(query[key])}`)
      .join('&');
  }

  // Canonicalize headers (include only signed headers)
  canonicalizeHeaders(headers) {
    const signedHeaders = [
      'host',
      'content-type',
      'content-length',
      'x-api-key',
      'authorization'
    ];

    return signedHeaders
      .filter(header => headers[header])
      .sort()
      .map(header => `${header}:${headers[header].trim()}`)
      .join('\n');
  }

  // Hash request body
  hashRequestBody(body) {
    if (!body || body.length === 0) {
      return crypto.createHash(this.algorithm).update('').digest('hex');
    }

    if (typeof body === 'string') {
      return crypto.createHash(this.algorithm).update(body, 'utf8').digest('hex');
    }

    if (Buffer.isBuffer(body)) {
      return crypto.createHash(this.algorithm).update(body).digest('hex');
    }

    // Convert object to JSON string
    const jsonBody = JSON.stringify(body);
    return crypto.createHash(this.algorithm).update(jsonBody, 'utf8').digest('hex');
  }

  // Validate timestamp (prevent replay attacks)
  validateTimestamp(timestamp) {
    const now = Math.floor(Date.now() / 1000);
    const requestTime = parseInt(timestamp);

    if (isNaN(requestTime)) {
      return { valid: false, reason: 'INVALID_TIMESTAMP_FORMAT' };
    }

    const timeDiff = Math.abs(now - requestTime);
    
    if (timeDiff > this.timestampTolerance) {
      return { 
        valid: false, 
        reason: 'TIMESTAMP_OUT_OF_RANGE',
        details: `Request timestamp is ${timeDiff}s off, max allowed: ${this.timestampTolerance}s`
      };
    }

    return { valid: true };
  }

  // Validate nonce (prevent replay attacks)
  async validateNonce(nonce, timestamp) {
    // In production, check against a distributed cache/database
    // For now, use in-memory storage with cleanup
    if (!this.usedNonces) {
      this.usedNonces = new Map();
    }

    const nonceKey = `${nonce}:${timestamp}`;
    
    if (this.usedNonces.has(nonceKey)) {
      return { valid: false, reason: 'NONCE_ALREADY_USED' };
    }

    return { valid: true };
  }

  // Store nonce to prevent replay
  async storeNonce(nonce, timestamp) {
    if (!this.usedNonces) {
      this.usedNonces = new Map();
    }

    const nonceKey = `${nonce}:${timestamp}`;
    const expiresAt = Date.now() + (this.timestampTolerance * 2 * 1000);
    
    this.usedNonces.set(nonceKey, expiresAt);

    // Cleanup old nonces
    this.cleanupExpiredNonces();
  }

  // Clean up expired nonces
  cleanupExpiredNonces() {
    if (!this.usedNonces) return;

    const now = Date.now();
    
    for (const [nonceKey, expiresAt] of this.usedNonces.entries()) {
      if (now > expiresAt) {
        this.usedNonces.delete(nonceKey);
      }
    }
  }

  // HMAC-SHA256 signature methods
  async signHMAC(stringToSign, options) {
    const { secret } = options;
    
    if (!secret) {
      throw new Error('HMAC secret is required');
    }

    const hmac = crypto.createHmac(this.algorithm, secret);
    hmac.update(stringToSign, 'utf8');
    const signature = hmac.digest('base64');

    return { signature, algorithm: `HMAC-${this.algorithm.toUpperCase()}` };
  }

  async verifyHMAC(stringToSign, providedSignature, options) {
    try {
      const { secret } = options;
      
      if (!secret) {
        return { valid: false, reason: 'MISSING_SECRET' };
      }

      const { signature: expectedSignature } = await this.signHMAC(stringToSign, { secret });

      // Use constant-time comparison to prevent timing attacks
      const isValid = crypto.timingSafeEqual(
        Buffer.from(expectedSignature, 'base64'),
        Buffer.from(providedSignature, 'base64')
      );

      return isValid ? { valid: true } : { valid: false, reason: 'SIGNATURE_MISMATCH' };
    } catch (error) {
      return { valid: false, reason: 'HMAC_VERIFICATION_ERROR', error: error.message };
    }
  }

  // RSA signature methods
  async signRSA(stringToSign, options) {
    const { privateKey } = options;
    
    if (!privateKey) {
      throw new Error('RSA private key is required');
    }

    const sign = crypto.createSign('RSA-SHA256');
    sign.update(stringToSign, 'utf8');
    const signature = sign.sign(privateKey, 'base64');

    return { signature, algorithm: 'RSA-SHA256' };
  }

  async verifyRSA(stringToSign, providedSignature, options) {
    try {
      const { publicKey } = options;
      
      if (!publicKey) {
        return { valid: false, reason: 'MISSING_PUBLIC_KEY' };
      }

      const verify = crypto.createVerify('RSA-SHA256');
      verify.update(stringToSign, 'utf8');
      const isValid = verify.verify(publicKey, providedSignature, 'base64');

      return isValid ? { valid: true } : { valid: false, reason: 'RSA_SIGNATURE_MISMATCH' };
    } catch (error) {
      return { valid: false, reason: 'RSA_VERIFICATION_ERROR', error: error.message };
    }
  }

  // Simple hash methods (for development/testing)
  async signSimpleHash(stringToSign, options) {
    const { secret } = options;
    
    if (!secret) {
      throw new Error('Secret is required for simple hash');
    }

    const hash = crypto.createHash(this.algorithm);
    hash.update(stringToSign + secret, 'utf8');
    const signature = hash.digest('hex');

    return { signature, algorithm: `Simple-${this.algorithm.toUpperCase()}` };
  }

  async verifySimpleHash(stringToSign, providedSignature, options) {
    try {
      const { signature: expectedSignature } = await this.signSimpleHash(stringToSign, options);
      
      const isValid = crypto.timingSafeEqual(
        Buffer.from(expectedSignature, 'hex'),
        Buffer.from(providedSignature, 'hex')
      );

      return isValid ? { valid: true } : { valid: false, reason: 'HASH_MISMATCH' };
    } catch (error) {
      return { valid: false, reason: 'HASH_VERIFICATION_ERROR', error: error.message };
    }
  }

  // Utility methods for generating signatures (for client implementation)
  generateSignatureHeaders(method, path, body, options = {}) {
    const {
      secret,
      privateKey,
      scheme = 'hmac-sha256',
      keyId = null
    } = options;

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomBytes(16).toString('hex');

    // Create mock request object for string generation
    const mockReq = {
      method: method.toUpperCase(),
      path,
      query: {},
      headers: {
        'content-type': 'application/json',
        'content-length': body ? Buffer.byteLength(body, 'utf8').toString() : '0'
      },
      rawBody: body || ''
    };

    const stringToSign = this.createStringToSign(mockReq, timestamp, nonce);
    
    // Generate signature based on scheme
    const signatureScheme = this.signatureSchemes.get(scheme);
    if (!signatureScheme) {
      throw new Error(`Unsupported signature scheme: ${scheme}`);
    }

    return signatureScheme.sign(stringToSign, { secret, privateKey }).then(result => ({
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': result.signature,
      'X-Signature-Algorithm': result.algorithm,
      ...(keyId && { 'X-Key-Id': keyId })
    }));
  }

  // Get signature statistics
  getSignatureStats() {
    return {
      supportedSchemes: Array.from(this.signatureSchemes.keys()),
      usedNonces: this.usedNonces ? this.usedNonces.size : 0,
      timestampTolerance: this.timestampTolerance,
      algorithm: this.algorithm
    };
  }

  // Cleanup method
  cleanup() {
    if (this.usedNonces) {
      this.usedNonces.clear();
    }
    
    logger.info('Signature validator cleaned up');
  }
}

module.exports = SignatureValidator;