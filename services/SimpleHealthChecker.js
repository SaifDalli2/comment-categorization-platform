// gateway-service/services/SimpleHealthChecker.js
const axios = require('axios');
const config = require('../config/simple');

class SimpleHealthChecker {
  constructor() {
    this.services = config.get('services');
    this.healthStatus = new Map();
    this.checkInterval = 30000; // 30 seconds
    
    this.startHealthChecks();
  }

  startHealthChecks() {
    setInterval(() => {
      this.checkAllServices();
    }, this.checkInterval);
    
    // Initial check
    this.checkAllServices();
  }

  async checkAllServices() {
    for (const [name, url] of Object.entries(this.services)) {
      try {
        const response = await axios.get(`${url}/health`, { timeout: 5000 });
        this.healthStatus.set(name, {
          healthy: response.status === 200,
          url,
          lastCheck: new Date().toISOString(),
          responseTime: response.responseTime || 0
        });
      } catch (error) {
        this.healthStatus.set(name, {
          healthy: false,
          url,
          lastCheck: new Date().toISOString(),
          error: error.message
        });
      }
    }
  }

  getServiceUrl(serviceName) {
    const status = this.healthStatus.get(serviceName);
    return (status?.healthy) ? this.services[serviceName] : null;
  }

  getHealthStatus() {
    return Object.fromEntries(this.healthStatus);
  }
}

module.exports = SimpleHealthChecker;