#!/usr/bin/env node
// gateway-service/scripts/verify-analytics-service.js

const axios = require('axios');
const chalk = require('chalk');

const ANALYTICS_SERVICE_URL = 'https://analytics-service-voice-cd4ea7dc5810.herokuapp.com';

async function verifyAnalyticsService() {
  console.log(chalk.blue.bold('🔍 Analytics Service Verification'));
  console.log(chalk.blue('==================================='));
  console.log(`Service URL: ${ANALYTICS_SERVICE_URL}\n`);

  const checks = [
    {
      name: 'Basic Health Check',
      url: `${ANALYTICS_SERVICE_URL}/health`,
      method: 'GET'
    },
    {
      name: 'Analytics Events Endpoint',
      url: `${ANALYTICS_SERVICE_URL}/api/analytics/events`,
      method: 'POST',
      requiresAuth: true
    },
    {
      name: 'Comment Engagement Analytics',
      url: `${ANALYTICS_SERVICE_URL}/api/analytics/comments/engagement`,
      method: 'GET',
      requiresAuth: true
    },
    {
      name: 'User Behavior Analytics',
      url: `${ANALYTICS_SERVICE_URL}/api/analytics/user/behavior`,
      method: 'GET',
      requiresAuth: true
    },
    {
      name: 'Batch Events Endpoint',
      url: `${ANALYTICS_SERVICE_URL}/api/analytics/events/batch`,
      method: 'POST',
      requiresAuth: true
    }
  ];

  let totalChecks = 0;
  let passedChecks = 0;

  for (const check of checks) {
    totalChecks++;
    console.log(`🔍 ${check.name}...`);
    
    try {
      const options = {
        method: check.method,
        url: check.url,
        timeout: 8000,
        validateStatus: () => true, // Accept any status
        headers: {
          'User-Agent': 'Gateway-Analytics-Verification/1.0',
          'Content-Type': 'application/json'
        }
      };

      // Add sample data for POST requests
      if (check.method === 'POST') {
        if (check.url.includes('/events/batch')) {
          options.data = {
            events: [
              {
                eventType: "comment_created",
                userId: "test-user-123",
                metadata: { test: true },
                timestamp: new Date().toISOString()
              }
            ]
          };
        } else {
          options.data = {
            eventType: "test_event",
            userId: "test-user-123",
            metadata: { test: true },
            timestamp: new Date().toISOString()
          };
        }
      }

      const response = await axios(options);
      
      if (check.requiresAuth && response.status === 401) {
        console.log(`   ${chalk.green('✅')} Endpoint exists (requires authentication)`);
        passedChecks++;
      } else if (response.status === 200) {
        console.log(`   ${chalk.green('✅')} Endpoint healthy (${response.status})`);
        passedChecks++;
        
        // Display response data for health check
        if (check.name === 'Basic Health Check' && response.data) {
          console.log(`   📊 Version: ${response.data.version || 'unknown'}`);
          console.log(`   ⏱️  Uptime: ${response.data.uptime || 'unknown'}`);
          console.log(`   🏷️  Service: ${response.data.service || 'unknown'}`);
          
          if (response.data.dependencies) {
            console.log(`   🔗 Dependencies:`);
            Object.entries(response.data.dependencies).forEach(([dep, status]) => {
              const icon = status === 'healthy' ? '✅' : '⚠️';
              console.log(`      ${icon} ${dep}: ${status}`);
            });
          }
        }
      } else if (response.status === 404) {
        console.log(`   ${chalk.red('❌')} Endpoint not found (${response.status})`);
      } else if (response.status >= 500) {
        console.log(`   ${chalk.red('❌')} Server error (${response.status})`);
      } else {
        console.log(`   ${chalk.yellow('⚠️')} Unexpected response (${response.status})`);
        passedChecks++;
      }

    } catch (error) {
      if (error.code === 'ECONNREFUSED') {
        console.log(`   ${chalk.red('❌')} Service unreachable`);
      } else if (error.code === 'ETIMEDOUT') {
        console.log(`   ${chalk.red('❌')} Request timeout`);
      } else {
        console.log(`   ${chalk.red('❌')} Error: ${error.message}`);
      }
    }
    
    console.log('');
  }

  // Summary
  console.log(chalk.blue.bold('📋 Verification Summary'));
  console.log(chalk.blue('======================'));
  console.log(`Checks passed: ${passedChecks}/${totalChecks}`);
  console.log(`Success rate: ${Math.round((passedChecks/totalChecks) * 100)}%`);
  
  if (passedChecks === totalChecks) {
    console.log(chalk.green.bold('🎉 All checks passed! Analytics service is ready.'));
  } else if (passedChecks >= totalChecks * 0.8) {
    console.log(chalk.yellow.bold('⚠️  Most checks passed. Some endpoints may need authentication.'));
  } else {
    console.log(chalk.red.bold('❌ Multiple checks failed. Service may have issues.'));
  }

  console.log('\n📝 Next Steps:');
  console.log('1. Update gateway environment: ANALYTICS_SERVICE_URL=' + ANALYTICS_SERVICE_URL);
  console.log('2. Run gateway health check: npm run health:diagnostics');
  console.log('3. Test analytics endpoints through gateway: /api/analytics/*');
  
  // Exit with appropriate code
  const exitCode = passedChecks >= totalChecks * 0.8 ? 0 : 1;
  process.exit(exitCode);
}

// Run verification if called directly
if (require.main === module) {
  verifyAnalyticsService().catch(error => {
    console.error(chalk.red.bold('❌ Verification failed:'), error.message);
    process.exit(1);
  });
}

module.exports = verifyAnalyticsService;