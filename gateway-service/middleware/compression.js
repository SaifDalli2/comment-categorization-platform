// gateway-service/middleware/compression.js
const compression = require('compression');
const zlib = require('zlib');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

class CompressionMiddleware {
  constructor(options = {}) {
    this.enabled = options.enabled !== false && process.env.COMPRESSION_ENABLED !== 'false';
    this.threshold = options.threshold || parseInt(process.env.COMPRESSION_THRESHOLD) || 1024; // 1KB
    this.level = options.level || parseInt(process.env.COMPRESSION_LEVEL) || 6; // Default compression level
    this.chunkSize = options.chunkSize || parseInt(process.env.COMPRESSION_CHUNK_SIZE) || 16384; // 16KB
    
    // Compression strategies for different content types
    this.strategies = {
      'application/json': {
        level: 6,
        strategy: zlib.constants.Z_DEFAULT_STRATEGY,
        memLevel: 8
      },
      'text/html': {
        level: 6,
        strategy: zlib.constants.Z_DEFAULT_STRATEGY,
        memLevel: 8
      },
      'text/plain': {
        level: 6,
        strategy: zlib.constants.Z_DEFAULT_STRATEGY,
        memLevel: 8
      },
      'text/css': {
        level: 9,
        strategy: zlib.constants.Z_DEFAULT_STRATEGY,
        memLevel: 9
      },
      'application/javascript': {
        level: 9,
        strategy: zlib.constants.Z_DEFAULT_STRATEGY,
        memLevel: 9
      },
      'text/xml': {
        level: 6,
        strategy: zlib.constants.Z_DEFAULT_STRATEGY,
        memLevel: 8
      }
    };

    // Content types that should not be compressed
    this.excludeContentTypes = [
      'image/',
      'video/',
      'audio/',
      'application/zip',
      'application/gzip',
      'application/x-gzip',
      'application/x-compressed',
      'application/x-rar-compressed',
      'application/pdf',
      'application/octet-stream'
    ];

    // Paths that should not be compressed
    this.excludePaths = [
      '/metrics', // Prometheus metrics should be plain text
      '/health'   // Keep health checks simple
    ];

    this.compressionStats = {
      totalRequests: 0,
      compressedRequests: 0,
      totalOriginalBytes: 0,
      totalCompressedBytes: 0,
      compressionRatio: 0
    };

    this.initializeMetrics();
  }

  initializeMetrics() {
    // Create custom metrics for compression monitoring
    this.compressionRatioGauge = metrics.createCustomGauge(
      'compression_ratio',
      'Compression ratio for responses',
      ['content_type', 'path']
    );

    this.compressionTimeHistogram = metrics.createCustomHistogram(
      'compression_duration_seconds',
      'Time taken to compress responses',
      ['content_type', 'algorithm'],
      [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
    );

    this.compressedBytesCounter = metrics.createCustomCounter(
      'compressed_bytes_total',
      'Total bytes compressed',
      ['content_type', 'algorithm']
    );
  }

  // Main compression middleware
  middleware() {
    if (!this.enabled) {
      return (req, res, next) => next();
    }

    return compression({
      threshold: this.threshold,
      level: this.level,
      chunkSize: this.chunkSize,
      filter: (req, res) => this.shouldCompress(req, res),
      strategy: (req, res) => this.getCompressionStrategy(req, res)
    });
  }

  // Advanced compression middleware with custom logic
  advancedCompressionMiddleware() {
    return (req, res, next) => {
      if (!this.enabled || !this.shouldCompress(req, res)) {
        return next();
      }

      // Store original methods
      const originalSend = res.send;
      const originalJson = res.json;
      const originalEnd = res.end;

      // Override response methods to add compression
      res.send = (data) => {
        return this.compressAndSend(res, originalSend, data, req);
      };

      res.json = (data) => {
        const jsonData = JSON.stringify(data);
        return this.compressAndSend(res, originalSend, jsonData, req, 'application/json');
      };

      res.end = (data) => {
        if (data && typeof data === 'string') {
          return this.compressAndSend(res, originalEnd, data, req);
        }
        return originalEnd.call(res, data);
      };

      next();
    };
  }

  shouldCompress(req, res) {
    // Check if path should be excluded
    if (this.excludePaths.some(path => req.path.startsWith(path))) {
      return false;
    }

    // Check if client accepts compression
    const acceptEncoding = req.headers['accept-encoding'] || '';
    if (!acceptEncoding.includes('gzip') && !acceptEncoding.includes('deflate') && !acceptEncoding.includes('br')) {
      return false;
    }

    // Check content type
    const contentType = res.getHeader('content-type');
    if (contentType) {
      const isExcluded = this.excludeContentTypes.some(excluded => 
        contentType.toLowerCase().startsWith(excluded)
      );
      if (isExcluded) {
        return false;
      }
    }

    // Check if response is already compressed
    const contentEncoding = res.getHeader('content-encoding');
    if (contentEncoding) {
      return false;
    }

    return true;
  }

  getCompressionStrategy(req, res) {
    const contentType = res.getHeader('content-type');
    if (contentType) {
      const baseType = contentType.split(';')[0].toLowerCase();
      return this.strategies[baseType] || this.strategies['application/json'];
    }
    return this.strategies['application/json'];
  }

  async compressAndSend(res, originalMethod, data, req, contentType = null) {
    const startTime = Date.now();
    
    try {
      if (!data || typeof data !== 'string') {
        return originalMethod.call(res, data);
      }

      const originalSize = Buffer.byteLength(data, 'utf8');
      
      // Skip compression for small responses
      if (originalSize < this.threshold) {
        return originalMethod.call(res, data);
      }

      // Determine the best compression algorithm
      const acceptEncoding = req.headers['accept-encoding'] || '';
      let algorithm = 'gzip'; // default
      
      if (acceptEncoding.includes('br')) {
        algorithm = 'brotli';
      } else if (acceptEncoding.includes('gzip')) {
        algorithm = 'gzip';
      } else if (acceptEncoding.includes('deflate')) {
        algorithm = 'deflate';
      }

      // Compress the data
      const compressedData = await this.compressData(data, algorithm, contentType);
      const compressedSize = compressedData.length;
      const compressionRatio = ((originalSize - compressedSize) / originalSize) * 100;
      
      // Update statistics
      this.updateCompressionStats(originalSize, compressedSize, compressionRatio, contentType, algorithm);
      
      // Record metrics
      const duration = (Date.now() - startTime) / 1000;
      this.recordCompressionMetrics(contentType, algorithm, compressionRatio, duration, compressedSize);
      
      // Set compression headers
      res.setHeader('Content-Encoding', algorithm);
      res.setHeader('Content-Length', compressedSize);
      res.setHeader('X-Compression-Ratio', `${Math.round(compressionRatio)}%`);
      res.setHeader('X-Original-Size', originalSize);
      res.setHeader('X-Compressed-Size', compressedSize);
      
      // Log compression details
      logger.debug('Response compressed', {
        compression: {
          algorithm,
          originalSize,
          compressedSize,
          ratio: compressionRatio,
          duration,
          path: req.path,
          contentType: contentType || res.getHeader('content-type')
        }
      });

      return originalMethod.call(res, compressedData);

    } catch (error) {
      logger.error('Compression failed', {
        compression: {
          error: error.message,
          path: req.path,
          fallback: 'uncompressed'
        }
      }, error);
      
      // Fall back to uncompressed response
      return originalMethod.call(res, data);
    }
  }

  async compressData(data, algorithm, contentType) {
    const strategy = this.getStrategyForContentType(contentType);
    
    switch (algorithm) {
      case 'brotli':
        return await this.brotliCompress(data, strategy);
      case 'gzip':
        return await this.gzipCompress(data, strategy);
      case 'deflate':
        return await this.deflateCompress(data, strategy);
      default:
        return await this.gzipCompress(data, strategy);
    }
  }

  getStrategyForContentType(contentType) {
    if (!contentType) return this.strategies['application/json'];
    
    const baseType = contentType.split(';')[0].toLowerCase();
    return this.strategies[baseType] || this.strategies['application/json'];
  }

  async brotliCompress(data, strategy) {
    return new Promise((resolve, reject) => {
      const options = {
        params: {
          [zlib.constants.BROTLI_PARAM_QUALITY]: strategy.level,
          [zlib.constants.BROTLI_PARAM_SIZE_HINT]: Buffer.byteLength(data, 'utf8')
        }
      };
      
      zlib.brotliCompress(data, options, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
    });
  }

  async gzipCompress(data, strategy) {
    return new Promise((resolve, reject) => {
      const options = {
        level: strategy.level,
        strategy: strategy.strategy,
        memLevel: strategy.memLevel,
        chunkSize: this.chunkSize
      };
      
      zlib.gzip(data, options, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
    });
  }

  async deflateCompress(data, strategy) {
    return new Promise((resolve, reject) => {
      const options = {
        level: strategy.level,
        strategy: strategy.strategy,
        memLevel: strategy.memLevel,
        chunkSize: this.chunkSize
      };
      
      zlib.deflate(data, options, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
    });
  }

  updateCompressionStats(originalSize, compressedSize, ratio, contentType, algorithm) {
    this.compressionStats.totalRequests++;
    this.compressionStats.compressedRequests++;
    this.compressionStats.totalOriginalBytes += originalSize;
    this.compressionStats.totalCompressedBytes += compressedSize;
    
    // Calculate overall compression ratio
    if (this.compressionStats.totalOriginalBytes > 0) {
      this.compressionStats.compressionRatio = 
        ((this.compressionStats.totalOriginalBytes - this.compressionStats.totalCompressedBytes) / 
         this.compressionStats.totalOriginalBytes) * 100;
    }
  }

  recordCompressionMetrics(contentType, algorithm, ratio, duration, compressedBytes) {
    const baseContentType = contentType ? contentType.split(';')[0] : 'unknown';
    
    this.compressionRatioGauge.set(
      { content_type: baseContentType, path: 'aggregate' },
      ratio
    );
    
    this.compressionTimeHistogram.observe(
      { content_type: baseContentType, algorithm },
      duration
    );
    
    this.compressedBytesCounter.inc(
      { content_type: baseContentType, algorithm },
      compressedBytes
    );
  }

  // Static file compression middleware for serving pre-compressed files
  staticCompressionMiddleware() {
    return (req, res, next) => {
      if (!this.enabled || req.method !== 'GET') {
        return next();
      }

      const acceptEncoding = req.headers['accept-encoding'] || '';
      
      // Check for pre-compressed files
      if (acceptEncoding.includes('br') && this.hasPrecompressedFile(req.path, 'br')) {
        req.url += '.br';
        res.setHeader('Content-Encoding', 'br');
        res.setHeader('Vary', 'Accept-Encoding');
      } else if (acceptEncoding.includes('gzip') && this.hasPrecompressedFile(req.path, 'gz')) {
        req.url += '.gz';
        res.setHeader('Content-Encoding', 'gzip');
        res.setHeader('Vary', 'Accept-Encoding');
      }

      next();
    };
  }

  hasPrecompressedFile(path, extension) {
    // Check if pre-compressed file exists
    // This would typically check the filesystem
    const fs = require('fs');
    const fullPath = `./public${path}.${extension}`;
    
    try {
      return fs.existsSync(fullPath);
    } catch (error) {
      return false;
    }
  }

  // Express routes for compression management
  getCompressionRoutes() {
    const router = require('express').Router();

    // Compression statistics
    router.get('/stats', (req, res) => {
      const stats = this.getStats();
      res.json({
        success: true,
        data: stats,
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'],
          service: 'gateway'
        }
      });
    });

    // Update compression settings
    router.patch('/settings', (req, res) => {
      const { level, threshold, enabled } = req.body;
      
      if (level !== undefined && level >= 1 && level <= 9) {
        this.level = level;
      }
      
      if (threshold !== undefined && threshold >= 0) {
        this.threshold = threshold;
      }
      
      if (enabled !== undefined) {
        this.enabled = enabled;
      }

      res.json({
        success: true,
        data: {
          level: this.level,
          threshold: this.threshold,
          enabled: this.enabled
        }
      });
    });

    return router;
  }

  // Get compression statistics
  getStats() {
    const avgCompressionRatio = this.compressionStats.compressionRatio;
    const totalBytesSaved = this.compressionStats.totalOriginalBytes - this.compressionStats.totalCompressedBytes;
    
    return {
      enabled: this.enabled,
      settings: {
        level: this.level,
        threshold: this.threshold,
        chunkSize: this.chunkSize
      },
      statistics: {
        totalRequests: this.compressionStats.totalRequests,
        compressedRequests: this.compressionStats.compressedRequests,
        compressionRate: this.compressionStats.totalRequests > 0 ? 
          (this.compressionStats.compressedRequests / this.compressionStats.totalRequests) * 100 : 0,
        avgCompressionRatio: Math.round(avgCompressionRatio * 100) / 100,
        totalOriginalBytes: this.compressionStats.totalOriginalBytes,
        totalCompressedBytes: this.compressionStats.totalCompressedBytes,
        totalBytesSaved: totalBytesSaved,
        bandwidthSaved: this.formatBytes(totalBytesSaved)
      },
      strategies: Object.keys(this.strategies).length,
      excludedTypes: this.excludeContentTypes.length,
      excludedPaths: this.excludePaths.length
    };
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // Precompression utility for static files
  async precompressStaticFiles(publicDir = './public') {
    const fs = require('fs').promises;
    const path = require('path');
    
    async function walkDir(dir) {
      const files = [];
      const items = await fs.readdir(dir);
      
      for (const item of items) {
        const fullPath = path.join(dir, item);
        const stat = await fs.stat(fullPath);
        
        if (stat.isDirectory()) {
          files.push(...await walkDir(fullPath));
        } else {
          files.push(fullPath);
        }
      }
      
      return files;
    }

    try {
      const files = await walkDir(publicDir);
      const compressibleExtensions = ['.html', '.css', '.js', '.json', '.xml', '.txt', '.svg'];
      
      for (const file of files) {
        const ext = path.extname(file);
        if (compressibleExtensions.includes(ext)) {
          await this.precompressFile(file);
        }
      }
      
      logger.info('Static file precompression completed', {
        compression: {
          processedFiles: files.length,
          publicDir
        }
      });
      
    } catch (error) {
      logger.error('Static file precompression failed', {
        compression: {
          error: error.message,
          publicDir
        }
      }, error);
    }
  }

  async precompressFile(filePath) {
    const fs = require('fs').promises;
    
    try {
      const content = await fs.readFile(filePath, 'utf8');
      const originalSize = Buffer.byteLength(content, 'utf8');
      
      if (originalSize < this.threshold) {
        return; // Skip small files
      }

      // Create gzip compressed version
      const gzipData = await this.gzipCompress(content, this.strategies['text/html']);
      await fs.writeFile(`${filePath}.gz`, gzipData);
      
      // Create brotli compressed version
      const brotliData = await this.brotliCompress(content, this.strategies['text/html']);
      await fs.writeFile(`${filePath}.br`, brotliData);
      
      logger.debug('File precompressed', {
        compression: {
          file: filePath,
          originalSize,
          gzipSize: gzipData.length,
          brotliSize: brotliData.length
        }
      });
      
    } catch (error) {
      logger.error('File precompression failed', {
        compression: {
          file: filePath,
          error: error.message
        }
      }, error);
    }
  }
}

module.exports = CompressionMiddleware;