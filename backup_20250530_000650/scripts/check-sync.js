#!/usr/bin/env node
// gateway-service/scripts/check-sync.js - Development sync checking script

const axios = require('axios');
const config = require('../config/enhanced');

class SyncChecker {
  constructor() {
    this.gatewayUrl = process.env.GATEWAY_URL || `http://localhost:${config.port}`;
    this.services = config.services;
    this.timeout = 10000;
  }

  async checkGatewaySync() {
    try {
      console.log('🔍 Checking Gateway sync status...');
      
      const response = await axios.get(`${this.gatewayUrl}/health/sync`, {
        timeout: this.timeout
      });
      
      if (response.status === 200) {
        const data = response.data;
        this.displaySyncStatus(data);
        return data;
      } else {
        console.error('❌ Gateway sync check failed:', response.status);
        return null;
      }
      
    } catch (error) {
      console.error('❌ Failed to check gateway sync:', error.message);
      return null;
    }
  }

  async checkAllServices() {
    console.log('🔍 Checking individual service sync status...\n');
    
    const results = {};
    
    for (const [serviceName, serviceUrl] of Object.entries(this.services)) {
      try {
        console.log(`Checking ${serviceName}...`);
        
        // Check basic health
        const healthResponse = await axios.get(`${serviceUrl}/health`, {
          timeout: 5000,
          headers: {
            'User-Agent': 'Gateway-Sync-Checker/1.0'
          }
        });
        
        let syncInfo = null;
        
        // Try to get sync-specific information
        try {
          const syncResponse = await axios.get(`${serviceUrl}/api/shared-knowledge/status`, {
            timeout: 3000
          });
          syncInfo = syncResponse.data;
        } catch (syncError) {
          // Sync endpoint might not exist
          syncInfo = { status: 'unknown', reason: 'No sync endpoint' };
        }
        
        results[serviceName] = {
          status: healthResponse.status === 200 ? 'healthy' : 'unhealthy',
          health: healthResponse.data,
          sync: syncInfo,
          responseTime: healthResponse.headers['x-response-time'] || 'unknown'
        };
        
        console.log(`  ✅ ${serviceName}: ${results[serviceName].status}`);
        
      } catch (error) {
        results[serviceName] = {
          status: 'error',
          error: error.message
        };
        
        console.log(`  ❌ ${serviceName}: ${error.message}`);
      }
    }
    
    return results;
  }

  displaySyncStatus(syncData) {
    console.log('\n📊 Gateway Sync Status Report');
    console.log('================================');
    
    if (syncData.success) {
      const data = syncData.data;
      
      console.log(`Overall Status: ${this.getStatusIcon(data.overallStatus)} ${data.overallStatus.toUpperCase()}`);
      console.log(`Last Check: ${data.lastGlobalCheck || 'Never'}`);
      console.log(`Expected Version: ${data.expectedVersion}`);
      console.log('');
      
      console.log('Service Details:');
      console.log('================');
      
      data.services.forEach(service => {
        const statusIcon = this.getSyncStatusIcon(service.status);
        const versionInfo = service.currentVersion || 'unknown';
        const delayInfo = service.delayMinutes ? ` (${service.delayMinutes}m behind)` : '';
        
        console.log(`${statusIcon} ${service.name}:`);
        console.log(`    Version: ${versionInfo}${delayInfo}`);
        console.log(`    Status: ${service.status}`);
        console.log(`    Last Check: ${service.lastCheck || 'Never'}`);
        
        if (service.recommendation) {
          console.log(`    📝 ${service.recommendation}`);
        }
        console.log('');
      });
      
    } else {
      console.log('❌ Failed to get sync status from gateway');
    }
  }

  displayServiceResults(results) {
    console.log('\n📊 Individual Service Status Report');
    console.log('====================================');
    
    for (const [serviceName, result] of Object.entries(results)) {
      const statusIcon = this.getStatusIcon(result.status);
      
      console.log(`${statusIcon} ${serviceName.toUpperCase()}`);
      console.log(`    Status: ${result.status}`);
      
      if (result.health) {
        console.log(`    Health: ${result.health.status || 'unknown'}`);
        console.log(`    Version: ${result.health.version || 'unknown'}`);
        console.log(`    Uptime: ${result.health.uptime || 'unknown'}`);
      }
      
      if (result.sync) {
        console.log(`    Sync Status: ${result.sync.status || 'unknown'}`);
        console.log(`    Sync Version: ${result.sync.version || 'unknown'}`);
        
        if (result.sync.reason) {
          console.log(`    Sync Note: ${result.sync.reason}`);
        }
      }
      
      if (result.responseTime) {
        console.log(`    Response Time: ${result.responseTime}`);
      }
      
      if (result.error) {
        console.log(`    Error: ${result.error}`);
      }
      
      console.log('');
    }
  }

  getStatusIcon(status) {
    switch (status) {
      case 'healthy': return '✅';
      case 'unhealthy': return '❌';
      case 'degraded': return '⚠️';
      case 'unknown': return '❓';
      case 'error': return '💥';
      default: return '⚪';
    }
  }

  getSyncStatusIcon(status) {
    switch (status) {
      case 'in-sync': return '✅';
      case 'out-of-sync': return '❌';
      case 'unknown': return '❓';
      default: return '⚪';
    }
  }

  async generateReport() {
    const timestamp = new Date().toISOString();
    
    console.log('🚀 Starting synchronization check...');
    console.log(`Timestamp: ${timestamp}`);
    console.log(`Gateway URL: ${this.gatewayUrl}`);
    console.log(`Services to check: ${Object.keys(this.services).join(', ')}`);
    console.log('');
    
    // Check gateway sync status
    const gatewaySyncData = await this.checkGatewaySync();
    
    console.log('\n' + '='.repeat(50));
    
    // Check individual services
    const serviceResults = await this.checkAllServices();
    
    this.displayServiceResults(serviceResults);
    
    // Summary
    console.log('📋 Summary');
    console.log('==========');
    
    const healthyServices = Object.values(serviceResults).filter(r => r.status === 'healthy').length;
    const totalServices = Object.keys(serviceResults).length;
    
    console.log(`Services: ${healthyServices}/${totalServices} healthy`);
    
    if (gatewaySyncData && gatewaySyncData.success) {
      const syncData = gatewaySyncData.data;
      const inSyncServices = syncData.services.filter(s => s.status === 'in-sync').length;
      console.log(`Sync Status: ${inSyncServices}/${syncData.services.length} in sync`);
      
      if (syncData.services.some(s => s.status === 'out-of-sync')) {
        console.log('⚠️  Some services are out of sync - consider running sync update');
      }
    }
    
    console.log(`\nCheck completed at: ${new Date().toISOString()}`);
    
    return {
      gateway: gatewaySyncData,
      services: serviceResults,
      summary: {
        healthyServices,
        totalServices,
        timestamp
      }
    };
  }
}

// CLI execution
if (require.main === module) {
  const checker = new SyncChecker();
  
  // Parse command line arguments
  const args = process.argv.slice(2);
  const showHelp = args.includes('--help') || args.includes('-h');
  const onlyGateway = args.includes('--gateway-only');
  const onlyServices = args.includes('--services-only');
  const outputJson = args.includes('--json');
  
  if (showHelp) {
    console.log('Sync Check Script - Check service synchronization status');
    console.log('');
    console.log('Usage: node check-sync.js [options]');
    console.log('');
    console.log('Options:');
    console.log('  --help, -h          Show this help message');
    console.log('  --gateway-only      Check only gateway sync status');
    console.log('  --services-only     Check only individual services');
    console.log('  --json              Output results in JSON format');
    console.log('');
    console.log('Environment variables:');
    console.log('  GATEWAY_URL         Gateway URL (default: http://localhost:3000)');
    process.exit(0);
  }
  
  // Run the appropriate check
  if (onlyGateway) {
    checker.checkGatewaySync().then(result => {
      if (outputJson) {
        console.log(JSON.stringify(result, null, 2));
      }
      process.exit(result ? 0 : 1);
    });
  } else if (onlyServices) {
    checker.checkAllServices().then(results => {
      if (outputJson) {
        console.log(JSON.stringify(results, null, 2));
      } else {
        checker.displayServiceResults(results);
      }
      
      const hasErrors = Object.values(results).some(r => r.status === 'error' || r.status === 'unhealthy');
      process.exit(hasErrors ? 1 : 0);
    });
  } else {
    checker.generateReport().then(results => {
      if (outputJson) {
        console.log(JSON.stringify(results, null, 2));
      }
      
      const hasIssues = results.summary.healthyServices < results.summary.totalServices;
      process.exit(hasIssues ? 1 : 0);
    }).catch(error => {
      console.error('❌ Sync check failed:', error.message);
      process.exit(1);
    });
  }
}

module.exports = SyncChecker;