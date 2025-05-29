#!/usr/bin/env node
// Production sync checker

const https = require('https');
const http = require('http');

class ProductionSyncChecker {
  constructor() {
    this.gatewayUrl = 'https://gateway-service-b25f91548194.herokuapp.com';
    this.services = {
      auth: 'https://auth-service-voice-0add8d339257.herokuapp.com'
    };
  }

  async makeRequest(url) {
    return new Promise((resolve, reject) => {
      const client = url.startsWith('https:') ? https : http;
      const startTime = Date.now();
      
      const req = client.get(url, { timeout: 10000 }, (res) => {
        let data = '';
        
        res.on('data', chunk => {
          data += chunk;
        });
        
        res.on('end', () => {
          const responseTime = Date.now() - startTime;
          try {
            const parsed = JSON.parse(data);
            resolve({
              status: res.statusCode,
              data: parsed,
              responseTime,
              headers: res.headers
            });
          } catch (error) {
            resolve({
              status: res.statusCode,
              data: data,
              responseTime,
              headers: res.headers
            });
          }
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
    });
  }

  async checkGatewayHealth() {
    console.log('🔍 Checking Gateway health...');
    
    try {
      const response = await this.makeRequest(`${this.gatewayUrl}/health`);
      
      if (response.status === 200) {
        console.log('✅ Gateway is healthy');
        console.log(`   Version: ${response.data.version || 'unknown'}`);
        console.log(`   Uptime: ${response.data.uptime || 'unknown'} seconds`);
        console.log(`   Environment: ${response.data.environment || 'unknown'}`);
        
        if (response.data.features) {
          console.log(`   Features: ${Object.keys(response.data.features).join(', ')}`);
        }
        
        return true;
      } else {
        console.log(`❌ Gateway health check failed: ${response.status}`);
        return false;
      }
    } catch (error) {
      console.log(`❌ Gateway health check error: ${error.message}`);
      return false;
    }
  }

  async checkGatewaySync() {
    console.log('🔍 Checking Gateway sync status...');
    
    try {
      const response = await this.makeRequest(`${this.gatewayUrl}/health/sync`);
      
      if (response.status === 200 && response.data.success) {
        const syncData = response.data.data;
        
        console.log(`✅ Gateway sync status: ${syncData.overallStatus}`);
        console.log(`   Expected version: ${syncData.expectedVersion}`);
        console.log(`   Last check: ${syncData.lastGlobalCheck}`);
        
        console.log('\n   Service sync details:');
        syncData.services.forEach(service => {
          const icon = service.status === 'in-sync' ? '✅' : 
                      service.status === 'unknown' ? '❓' : '❌';
          console.log(`   ${icon} ${service.name}: ${service.status} (v${service.currentVersion})`);
          
          if (service.recommendation && service.status !== 'in-sync') {
            console.log(`      💡 ${service.recommendation}`);
          }
        });
        
        return syncData;
      } else {
        console.log(`❌ Gateway sync check failed: ${response.status}`);
        return null;
      }
    } catch (error) {
      console.log(`❌ Gateway sync check error: ${error.message}`);
      return null;
    }
  }

  async checkServiceHealth(serviceName, serviceUrl) {
    console.log(`🔍 Checking ${serviceName} service...`);
    
    try {
      const response = await this.makeRequest(`${serviceUrl}/health`);
      
      if (response.status === 200) {
        console.log(`   ✅ ${serviceName}: healthy (${response.responseTime}ms)`);
        
        if (response.data.version) {
          console.log(`      Version: ${response.data.version}`);
        }
        
        if (response.data.uptime) {
          console.log(`      Uptime: ${response.data.uptime} seconds`);
        }
        
        return {
          status: 'healthy',
          data: response.data,
          responseTime: response.responseTime
        };
      } else {
        console.log(`   ❌ ${serviceName}: unhealthy (${response.status})`);
        return {
          status: 'unhealthy',
          error: `HTTP ${response.status}`
        };
      }
    } catch (error) {
      console.log(`   ❌ ${serviceName}: error - ${error.message}`);
      return {
        status: 'error',
        error: error.message
      };
    }
  }

  async checkAllServices() {
    console.log('\n🔍 Checking individual services...');
    
    const results = {};
    
    for (const [serviceName, serviceUrl] of Object.entries(this.services)) {
      results[serviceName] = await this.checkServiceHealth(serviceName, serviceUrl);
    }
    
    return results;
  }

  async generateReport() {
    const timestamp = new Date().toISOString();
    
    console.log('🚀 Production Sync Check Report');
    console.log('================================');
    console.log(`Timestamp: ${timestamp}`);
    console.log(`Gateway: ${this.gatewayUrl}`);
    console.log('');
    
    const gatewayHealthy = await this.checkGatewayHealth();
    console.log('');
    const syncData = await this.checkGatewaySync();
    const serviceResults = await this.checkAllServices();
    
    console.log('\n📋 Summary');
    console.log('==========');
    
    const totalServices = Object.keys(this.services).length;
    const healthyServices = Object.values(serviceResults).filter(r => r.status === 'healthy').length;
    
    console.log(`Gateway Health: ${gatewayHealthy ? '✅ Healthy' : '❌ Unhealthy'}`);
    console.log(`Services: ${healthyServices}/${totalServices} healthy`);
    
    if (syncData) {
      const inSyncServices = syncData.services.filter(s => s.status === 'in-sync').length;
      console.log(`Sync Status: ${inSyncServices}/${syncData.services.length} in sync`);
    }
    
    console.log(`\nCheck completed at: ${new Date().toISOString()}`);
    
    return {
      gateway: { healthy: gatewayHealthy, sync: syncData },
      services: serviceResults,
      summary: { totalServices, healthyServices, timestamp }
    };
  }
}

if (require.main === module) {
  const checker = new ProductionSyncChecker();
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log('Production Sync Check - Check deployed services');
    console.log('Usage: node scripts/simple-sync-check.js [options]');
    console.log('Options:');
    console.log('  --help, -h       Show this help');
    console.log('  --json           Output in JSON format');
    console.log('  --gateway-only   Check only gateway');
    process.exit(0);
  }
  
  if (args.includes('--gateway-only')) {
    Promise.all([
      checker.checkGatewayHealth(),
      checker.checkGatewaySync()
    ]).then(([health, sync]) => {
      if (args.includes('--json')) {
        console.log(JSON.stringify({ health, sync }, null, 2));
      }
      process.exit(health ? 0 : 1);
    });
  } else {
    checker.generateReport().then(results => {
      if (args.includes('--json')) {
        console.log(JSON.stringify(results, null, 2));
      }
      
      const hasIssues = !results.gateway.healthy || 
                       results.summary.healthyServices < results.summary.totalServices;
      process.exit(hasIssues ? 1 : 0);
    }).catch(error => {
      console.error('❌ Sync check failed:', error.message);
      process.exit(1);
    });
  }
}

module.exports = ProductionSyncChecker;
