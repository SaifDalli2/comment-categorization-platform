// gateway-service/tests/health/health-check.js
const axios = require('axios');
const colors = require('colors');

class HealthChecker {
  constructor(baseUrl = 'http://localhost:3000') {
    this.baseUrl = baseUrl;
    this.results = [];
  }

  async runAllChecks() {
    console.log('🏥 Starting Gateway Health Checks...'.cyan.bold);
    console.log(`🔗 Base URL: ${this.baseUrl}\n`.gray);

    const checks = [
      { name: 'Basic Health', path: '/health' },
      { name: 'Service Health', path: '/health/services' },
      { name: 'Monitoring Health', path: '/health/monitoring' },
      { name: 'API Status', path: '/api/status' },
      { name: 'Metrics Endpoint', path: '/metrics' },
      { name: 'Service Registry', path: '/api/gateway/services' },
      { name: 'Gateway Stats', path: '/api/gateway/stats' },
      { name: 'Error Monitoring', path: '/api/monitoring/errors' },
      { name: 'Error Health', path: '/api/monitoring/errors/health' },
    ];

    for (const check of checks) {
      await this.performCheck(check);
    }

    this.printSummary();
    return this.results.every(r => r.success);
  }

  async performCheck(check) {
    const startTime = Date.now();
    
    try {
      const response = await axios.get(`${this.baseUrl}${check.path}`, {
        timeout: 5000,
        headers: {
          'User-Agent': 'Gateway-Health-Check/1.0'
        }
      });

      const duration = Date.now() - startTime;
      
      const result = {
        name: check.name,
        path: check.path,
        success: true,
        status: response.status,
        duration,
        data: this.extractHealthData(response.data)
      };

      this.results.push(result);
      this.printCheckResult(result);

    } catch (error) {
      const duration = Date.now() - startTime;
      
      const result = {
        name: check.name,
        path: check.path,
        success: false,
        status: error.response?.status || 'TIMEOUT',
        duration,
        error: error.message
      };

      this.results.push(result);
      this.printCheckResult(result);
    }
  }

  extractHealthData(data) {
    if (!data || typeof data !== 'object') return null;

    // Extract relevant health information
    const healthData = {};

    if (data.status) healthData.status = data.status;
    if (data.service) healthData.service = data.service;
    if (data.uptime !== undefined) healthData.uptime = data.uptime;
    if (data.version) healthData.version = data.version;
    
    // Service-specific data
    if (data.dependencies) healthData.dependencies = Object.keys(data.dependencies).length;
    if (data.summary) healthData.summary = data.summary;
    if (data.data && data.data.totalServices) healthData.totalServices = data.data.totalServices;
    if (data.data && data.data.healthyInstances) healthData.healthyInstances = data.data.healthyInstances;

    return Object.keys(healthData).length > 0 ? healthData : null;
  }

  printCheckResult(result) {
    const statusIcon = result.success ? '✅' : '❌';
    const statusColor = result.success ? 'green' : 'red';
    const durationColor = result.duration < 100 ? 'green' : result.duration < 500 ? 'yellow' : 'red';
    
    console.log(`${statusIcon} ${result.name.padEnd(20)}`.concat(
      `${result.status.toString().padEnd(8)}`[statusColor],
      `${result.duration}ms`[durationColor]
    ));

    if (result.data) {
      const dataEntries = Object.entries(result.data);
      if (dataEntries.length > 0) {
        console.log(`   📊 ${dataEntries.map(([k, v]) => `${k}: ${v}`).join(', ')}`.gray);
      }
    }

    if (result.error) {
      console.log(`   ❗ Error: ${result.error}`.red);
    }

    console.log(); // Empty line for readability
  }

  printSummary() {
    const successCount = this.results.filter(r => r.success).length;
    const failureCount = this.results.length - successCount;
    const avgDuration = Math.round(
      this.results.reduce((sum, r) => sum + r.duration, 0) / this.results.length
    );

    console.log('📋 Health Check Summary'.cyan.bold);
    console.log('═'.repeat(50).gray);
    
    console.log(`✅ Successful: ${successCount}`.green);
    console.log(`❌ Failed: ${failureCount}`[failureCount > 0 ? 'red' : 'green']);
    console.log(`⏱️  Average Response Time: ${avgDuration}ms`[avgDuration < 200 ? 'green' : 'yellow']);
    console.log(`🏥 Overall Health: ${successCount === this.results.length ? 'HEALTHY' : 'DEGRADED'}`[
      successCount === this.results.length ? 'green' : 'red'
    ]);

    if (failureCount > 0) {
      console.log('\n🚨 Failed Checks:'.red.bold);
      this.results
        .filter(r => !r.success)
        .forEach(r => {
          console.log(`   • ${r.name} (${r.path}) - ${r.status} - ${r.error || 'Unknown error'}`.red);
        });
    }

    console.log('\n🔧 Recommendations:'.cyan.bold);
    this.printRecommendations();
  }

  printRecommendations() {
    const failedChecks = this.results.filter(r => !r.success);
    const slowChecks = this.results.filter(r => r.success && r.duration > 1000);

    if (failedChecks.length === 0 && slowChecks.length === 0) {
      console.log('   ✨ All checks passed and performance is good!'.green);
      return;
    }

    if (failedChecks.some(r => r.path === '/health')) {
      console.log('   🔴 Basic health check failed - Gateway may not be running'.red);
    }

    if (failedChecks.some(r => r.path === '/health/services')) {
      console.log('   🟡 Service health check failed - Dependent services may be unavailable'.yellow);
    }

    if (failedChecks.some(r => r.path === '/metrics')) {
      console.log('   🟡 Metrics endpoint failed - Monitoring may be impacted'.yellow);
    }

    if (slowChecks.length > 0) {
      console.log(`   🐌 ${slowChecks.length} checks are slow (>1s) - Check service performance`.yellow);
    }

    if (failedChecks.length > 0) {
      console.log('   💡 Check logs and service configuration'.blue);
      console.log('   💡 Verify dependent services are running'.blue);
      console.log('   💡 Check network connectivity'.blue);
    }
  }

  async waitForHealthy(maxWaitTime = 60000, checkInterval = 2000) {
    console.log(`⏳ Waiting for gateway to become healthy (max ${maxWaitTime/1000}s)...`.yellow);
    
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitTime) {
      try {
        const response = await axios.get(`${this.baseUrl}/health`, {
          timeout: checkInterval / 2
        });
        
        if (response.status === 200) {
          console.log('✅ Gateway is healthy!'.green);
          return true;
        }
      } catch (error) {
        // Continue waiting
      }
      
      process.stdout.write('.');
      await new Promise(resolve => setTimeout(resolve, checkInterval));
    }
    
    console.log('\n❌ Timeout waiting for gateway to become healthy'.red);
    return false;
  }
}

// CLI execution
async function main() {
  const args = process.argv.slice(2);
  const baseUrl = args[0] || process.env.GATEWAY_URL || 'http://localhost:3000';
  
  const checker = new HealthChecker(baseUrl);
  
  // Check if we should wait for healthy first
  if (args.includes('--wait')) {
    const isHealthy = await checker.waitForHealthy();
    if (!isHealthy) {
      process.exit(1);
    }
  }
  
  const allHealthy = await checker.runAllChecks();
  
  // Exit with error code if any checks failed
  process.exit(allHealthy ? 0 : 1);
}

// Export for programmatic use
module.exports = HealthChecker;

// Run if called directly
if (require.main === module) {
  main().catch(error => {
    console.error('Health check failed:'.red, error.message);
    process.exit(1);
  });
}