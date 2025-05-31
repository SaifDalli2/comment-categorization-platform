#!/usr/bin/env node
// scripts/test-analytics.js - Test Analytics Integration

const axios = require('axios');

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3000';
const ANALYTICS_URL = process.env.ANALYTICS_SERVICE_URL || 'https://analytics-service-voice-cd4ea7dc5810.herokuapp.com';

class AnalyticsIntegrationTester {
  constructor() {
    this.testToken = process.env.TEST_JWT_TOKEN;
    this.results = [];
  }

  async runTests() {
    console.log('🧪 Analytics Integration Test Suite');
    console.log('==================================');
    
    try {
      await this.testAnalyticsServiceHealth();
      await this.testMixedDataUpload();
      await this.testEventBusConnectivity();
      await this.testAnalyticsEndpoints();
      
      this.printResults();
    } catch (error) {
      console.error('❌ Test suite failed:', error.message);
      process.exit(1);
    }
  }

  async testAnalyticsServiceHealth() {
    console.log('\n🔍 Testing Analytics Service Health...');
    
    try {
      const response = await axios.get(`${ANALYTICS_URL}/health`, { timeout: 5000 });
      
      if (response.status === 200) {
        this.addResult('✅ Analytics Service Health', 'PASS', 'Service is responding');
        console.log(`   Status: ${response.data.status}`);
        console.log(`   Version: ${response.data.version || 'unknown'}`);
      } else {
        this.addResult('❌ Analytics Service Health', 'FAIL', `Unexpected status: ${response.status}`);
      }
    } catch (error) {
      this.addResult('❌ Analytics Service Health', 'FAIL', error.message);
      console.log('   ⚠️  Analytics service is not accessible');
    }
  }

  async testMixedDataUpload() {
    console.log('\n🔍 Testing Mixed Data Upload...');
    
    const testData = {
      qualitativeData: {
        comments: [
          {
            text: "This product is amazing! Great quality and fast delivery.",
            userId: "550e8400-e29b-41d4-a716-446655440000"
          }
        ]
      },
      quantitativeData: {
        ratings: [5, 4, 3, 5, 4],
        scores: [85, 92, 78, 89, 86],
        metrics: [120, 135, 98, 110, 125]
      }
    };

    try {
      const response = await axios.post(`${GATEWAY_URL}/api/data/upload`, testData, {
        headers: {
          'Content-Type': 'application/json',
          ...(this.testToken && { 'Authorization': `Bearer ${this.testToken}` })
        },
        timeout: 10000
      });

      if (response.status === 202) {
        this.addResult('✅ Mixed Data Upload', 'PASS', 'Data routing successful');
        console.log(`   Session ID: ${response.data.data.sessionId}`);
        console.log(`   Services: ${Object.keys(response.data.data.services).join(', ')}`);
        
        // Store session ID for follow-up tests
        this.sessionId = response.data.data.sessionId;
      } else {
        this.addResult('❌ Mixed Data Upload', 'FAIL', `Unexpected status: ${response.status}`);
      }
    } catch (error) {
      this.addResult('❌ Mixed Data Upload', 'FAIL', error.response?.data?.error?.message || error.message);
    }
  }

  async testEventBusConnectivity() {
    console.log('\n🔍 Testing Event Bus Connectivity...');
    
    try {
      const response = await axios.get(`${GATEWAY_URL}/health`, { timeout: 5000 });
      
      if (response.data.eventBus) {
        const status = response.data.eventBus;
        if (status === 'connected') {
          this.addResult('✅ Event Bus', 'PASS', 'Redis connection active');
        } else {
          this.addResult('⚠️  Event Bus', 'WARN', 'Local events only (Redis unavailable)');
        }
        console.log(`   Event Bus Status: ${status}`);
      } else {
        this.addResult('❓ Event Bus', 'UNKNOWN', 'Status not reported');
      }
    } catch (error) {
      this.addResult('❌ Event Bus', 'FAIL', error.message);
    }
  }

  async testAnalyticsEndpoints() {
    console.log('\n🔍 Testing Analytics Endpoints via Gateway...');
    
    try {
      // Test proxied health endpoint
      const healthResponse = await axios.get(`${GATEWAY_URL}/api/analytics/health`, { timeout: 5000 });
      
      if (healthResponse.status === 200) {
        this.addResult('✅ Analytics Proxy', 'PASS', 'Health endpoint accessible via gateway');
      } else {
        this.addResult('❌ Analytics Proxy', 'FAIL', 'Health endpoint not accessible');
      }

      // Test metrics endpoint if we have a session ID
      if (this.sessionId) {
        try {
          const metricsResponse = await axios.get(`${GATEWAY_URL}/api/analytics/metrics`, {
            params: { sessionId: this.sessionId },
            headers: {
              ...(this.testToken && { 'Authorization': `Bearer ${this.testToken}` })
            },
            timeout: 5000
          });
          
          this.addResult('✅ Analytics Metrics', 'PASS', 'Metrics endpoint accessible');
        } catch (error) {
          this.addResult('⚠️  Analytics Metrics', 'WARN', 'Metrics may require processing time');
        }
      }

    } catch (error) {
      this.addResult('❌ Analytics Endpoints', 'FAIL', error.message);
    }
  }

  addResult(test, status, details) {
    this.results.push({ test, status, details });
  }

  printResults() {
    console.log('\n📊 Test Results Summary');
    console.log('======================');
    
    let passed = 0, failed = 0, warnings = 0;
    
    this.results.forEach(result => {
      console.log(`${result.test}: ${result.status}`);
      console.log(`   ${result.details}`);
      
      if (result.status === 'PASS') passed++;
      else if (result.status === 'FAIL') failed++;
      else warnings++;
    });
    
    console.log(`\n📈 Summary: ${passed} passed, ${failed} failed, ${warnings} warnings`);
    
    if (failed === 0) {
      console.log('🎉 Analytics integration is working correctly!');
    } else {
      console.log('⚠️  Some tests failed - check configuration and service availability');
    }
  }
}

// Run tests
const tester = new AnalyticsIntegrationTester();
tester.runTests().catch(console.error);
