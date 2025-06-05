#!/usr/bin/env node
// gateway-service/scripts/health-diagnostics.js

const axios = require('axios');
const chalk = require('chalk');

class HealthDiagnosticsScript {
  constructor() {
    this.gatewayUrl = process.env.GATEWAY_URL || 'http://localhost:3000';
    this.timeout = 15000;
  }

  async runHealthDiagnostics(options = {}) {
    const {
      includeHistory = false,
      includeTrends = false,
      outputFormat = 'detailed',
      filterServices = null
    } = options;

    console.log(chalk.blue.bold('🏥 Gateway Health Diagnostics'));
    console.log(chalk.blue('================================'));
    console.log(`Gateway URL: ${this.gatewayUrl}`);
    console.log(`Timestamp: ${new Date().toISOString()}\n`);

    try {
      const params = new URLSearchParams();
      if (includeHistory) params.append('history', 'true');
      if (includeTrends) params.append('trends', 'true');

      const url = `${this.gatewayUrl}/health/diagnostics${params.toString() ? '?' + params.toString() : ''}`;
      
      console.log(chalk.gray(`Requesting: ${url}\n`));

      const response = await axios.get(url, {
        timeout: this.timeout,
        headers: {
          'User-Agent': 'Health-Diagnostics-Script/1.0',
          'X-Requested-With': 'health-script'
        }
      });

      const data = response.data.data;
      
      if (outputFormat === 'json') {
        console.log(JSON.stringify(data, null, 2));
        return;
      }

      this.displayResults(data, { filterServices });
      
      // Exit with appropriate code
      const exitCode = this.getExitCode(data.summary.overallStatus);
      process.exit(exitCode);

    } catch (error) {
      this.handleError(error);
      process.exit(1);
    }
  }

  displayResults(data, options = {}) {
    const { filterServices } = options;

    // Display summary
    this.displaySummary(data);
    
    // Display gateway health
    console.log(chalk.blue.bold('\n🌐 Gateway Health'));
    console.log(chalk.blue('=================='));
    this.displayGatewayHealth(data.gateway);
    
    // Display service health
    console.log(chalk.blue.bold('\n🔧 Service Health Details'));
    console.log(chalk.blue('=========================='));
    this.displayServiceHealth(data.services, filterServices);
    
    // Display performance metrics
    console.log(chalk.blue.bold('\n⚡ Performance Metrics'));
    console.log(chalk.blue('======================'));
    this.displayPerformanceMetrics(data.performance);
    
    // Display recommendations
    if (data.recommendations && data.recommendations.length > 0) {
      console.log(chalk.blue.bold('\n💡 Recommendations'));
      console.log(chalk.blue('==================='));
      this.displayRecommendations(data.recommendations);
    }
    
    // Display trends if available
    if (data.trends) {
      console.log(chalk.blue.bold('\n📈 Health Trends'));
      console.log(chalk.blue('================='));
      this.displayTrends(data.trends);
    }
    
    // Display history if available
    if (data.history && data.history.length > 0) {
      console.log(chalk.blue.bold('\n📊 Recent Health History'));
      console.log(chalk.blue('========================='));
      this.displayHistory(data.history);
    }
  }

  displaySummary(data) {
    const summary = data.summary;
    const statusIcon = this.getStatusIcon(summary.overallStatus);
    const statusColor = this.getStatusColor(summary.overallStatus);
    
    console.log(chalk.yellow.bold('📋 Overall Health Summary'));
    console.log(chalk.yellow('========================='));
    console.log(`${statusIcon} Overall Status: ${chalk[statusColor].bold(summary.overallStatus.toUpperCase())}`);
    console.log(`🏢 Gateway Status: ${this.getStatusIcon(summary.gatewayStatus)} ${summary.gatewayStatus}`);
    console.log(`📊 Health Score: ${this.getHealthScoreDisplay(summary.healthPercentage)}%`);
    console.log(`🔧 Services: ${summary.healthyServices}/${summary.configuredServices} healthy (${summary.totalServices} total)`);
    
    if (summary.notConfiguredServices > 0) {
      console.log(chalk.gray(`   ⚙️  ${summary.notConfiguredServices} not configured`));
    }
    
    console.log('\n📈 Service Status Breakdown:');
    Object.entries(summary.statusBreakdown).forEach(([status, count]) => {
      if (count > 0) {
        const icon = this.getStatusIcon(status);
        const color = this.getStatusColor(status);
        console.log(`   ${icon} ${chalk[color](status)}: ${count}`);
      }
    });
  }

  displayGatewayHealth(gateway) {
    const statusIcon = this.getStatusIcon(gateway.status);
    const statusColor = this.getStatusColor(gateway.status);
    
    console.log(`${statusIcon} Status: ${chalk[statusColor](gateway.status)}`);
    console.log(`⏱️  Uptime: ${this.formatUptime(gateway.uptime)}`);
    console.log(`🏷️  Version: ${gateway.version}`);
    console.log(`⚙️  Node.js: ${gateway.nodeVersion}`);
    console.log(`🌍 Environment: ${gateway.environment}`);
    console.log(`🔌 Port: ${gateway.port}`);
    console.log(`⚡ Response Time: ${gateway.responseTime}ms`);
    
    if (gateway.resources) {
      console.log(`\n💾 Resource Usage:`);
      console.log(`   Memory: ${gateway.resources.memory.heapUsed}MB / ${gateway.resources.memory.heapTotal}MB`);
      console.log(`   RSS: ${gateway.resources.memory.rss}MB`);
      console.log(`   Load: ${gateway.resources.loadAverage.map(l => l.toFixed(2)).join(', ')}`);
    }
    
    if (gateway.features) {
      console.log(`\n🔧 Features:`);
      Object.entries(gateway.features).forEach(([feature, enabled]) => {
        const icon = enabled ? '✅' : '❌';
        console.log(`   ${icon} ${feature}: ${enabled ? 'enabled' : 'disabled'}`);
      });
    }
  }

  displayServiceHealth(services, filterServices) {
    Object.entries(services).forEach(([serviceName, service]) => {
      if (filterServices && !filterServices.includes(serviceName)) {
        return;
      }

      const statusIcon = this.getStatusIcon(service.status);
      const statusColor = this.getStatusColor(service.status);
      
      console.log(`\n${statusIcon} ${chalk.bold(serviceName.toUpperCase())} Service`);
      console.log(`   Status: ${chalk[statusColor](service.status)}`);
      console.log(`   URL: ${service.url}`);
      console.log(`   Response Time: ${service.responseTime}ms`);
      console.log(`   Last Check: ${new Date(service.timestamp).toLocaleString()}`);
      
      // Display checks
      console.log(`   Checks:`);
      Object.entries(service.checks).forEach(([check, passed]) => {
        const checkIcon = passed ? '✅' : '❌';
        console.log(`     ${checkIcon} ${check}: ${passed ? 'passed' : 'failed'}`);
      });
      
      // Display service details
      if (service.details && Object.keys(service.details).length > 0) {
        console.log(`   Details:`);
        Object.entries(service.details).forEach(([key, value]) => {
          if (value !== null && value !== undefined) {
            console.log(`     ${key}: ${value}`);
          }
        });
      }
      
      // Display diagnostics
      if (service.diagnostics) {
        const diag = service.diagnostics;
        if (diag.complianceChecks) {
          console.log(`   Compliance:`);
          Object.entries(diag.complianceChecks).forEach(([check, passed]) => {
            const checkIcon = passed ? '✅' : '❌';
            console.log(`     ${checkIcon} ${check}`);
          });
        }
        
        if (diag.serviceSpecific && !diag.serviceSpecific.error) {
          console.log(`   Service Features:`);
          if (diag.serviceSpecific.expectedFeatures) {
            diag.serviceSpecific.expectedFeatures.forEach(feature => {
              console.log(`     • ${feature}`);
            });
          }
        }
      }
      
      // Display errors
      if (service.errors && service.errors.length > 0) {
        console.log(`   ${chalk.red('Issues')}:`);
        service.errors.forEach(error => {
          console.log(`     ⚠️  ${chalk.red(error)}`);
        });
      }
    });
  }

  displayPerformanceMetrics(performance) {
    console.log(`⏱️  Total Check Time: ${performance.totalCheckTime}ms`);
    console.log(`📊 Average Response Time: ${performance.averageResponseTime}ms`);
    
    if (performance.fastestService) {
      console.log(`🏃 Fastest Service: ${chalk.green(performance.fastestService.name)} (${performance.fastestService.time}ms)`);
    }
    
    if (performance.slowestService) {
      console.log(`🐌 Slowest Service: ${chalk.yellow(performance.slowestService.name)} (${performance.slowestService.time}ms)`);
    }
  }

  displayRecommendations(recommendations) {
    recommendations.forEach((rec, index) => {
      const priorityColor = this.getPriorityColor(rec.priority);
      const priorityIcon = this.getPriorityIcon(rec.priority);
      
      console.log(`\n${priorityIcon} ${chalk[priorityColor].bold(rec.priority.toUpperCase())} - ${rec.type}`);
      console.log(`   Service: ${rec.service || 'system'}`);
      console.log(`   Issue: ${chalk.red(rec.issue)}`);
      console.log(`   Action: ${chalk.green(rec.action)}`);
      
      if (rec.details && rec.details.length > 0) {
        console.log(`   Details:`);
        rec.details.forEach(detail => {
          console.log(`     • ${detail}`);
        });
      }
    });
  }

  displayTrends(trends) {
    const healthTrend = trends.healthPercentageChange >= 0 ? '📈' : '📉';
    const healthColor = trends.healthPercentageChange >= 0 ? 'green' : 'red';
    
    console.log(`${healthTrend} Health Trend: ${chalk[healthColor](trends.trend)}`);
    console.log(`   Health Change: ${trends.healthPercentageChange >= 0 ? '+' : ''}${trends.healthPercentageChange}%`);
    console.log(`   Response Time Change: ${trends.averageResponseTimeChange >= 0 ? '+' : ''}${trends.averageResponseTimeChange}ms`);
  }

  displayHistory(history) {
    const recentHistory = history.slice(-5); // Show last 5 checks
    
    console.log('Recent Health Checks:');
    recentHistory.forEach((entry, index) => {
      const date = new Date(entry.timestamp).toLocaleString();
      const statusIcon = this.getStatusIcon(entry.summary.overallStatus);
      console.log(`   ${statusIcon} ${date} - ${entry.summary.healthPercentage}% healthy (${entry.performance.averageResponseTime}ms avg)`);
    });
  }

  getStatusIcon(status) {
    const icons = {
      healthy: '✅',
      degraded: '⚠️',
      unhealthy: '❌',
      unreachable: '💥',
      not_configured: '🔧',
      unknown: '❓'
    };
    return icons[status] || '❓';
  }

  getStatusColor(status) {
    const colors = {
      healthy: 'green',
      degraded: 'yellow',
      unhealthy: 'red',
      unreachable: 'red',
      not_configured: 'gray',
      unknown: 'gray'
    };
    return colors[status] || 'gray';
  }

  getPriorityIcon(priority) {
    const icons = {
      critical: '🚨',
      high: '⚠️',
      medium: '📢',
      low: 'ℹ️'
    };
    return icons[priority] || 'ℹ️';
  }

  getPriorityColor(priority) {
    const colors = {
      critical: 'red',
      high: 'yellow',
      medium: 'blue',
      low: 'gray'
    };
    return colors[priority] || 'gray';
  }

  getHealthScoreDisplay(percentage) {
    if (percentage >= 90) return chalk.green.bold(percentage);
    if (percentage >= 70) return chalk.yellow.bold(percentage);
    return chalk.red.bold(percentage);
  }

  formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) {
      return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
      return `${hours}h ${minutes}m`;
    } else {
      return `${minutes}m ${seconds % 60}s`;
    }
  }

  getExitCode(overallStatus) {
    const exitCodes = {
      healthy: 0,
      degraded: 1,
      unhealthy: 2
    };
    return exitCodes[overallStatus] || 3;
  }

  handleError(error) {
    console.error(chalk.red.bold('\n❌ Health Check Failed'));
    console.error(chalk.red('====================='));
    
    if (error.code === 'ECONNREFUSED') {
      console.error(chalk.red(`Cannot connect to gateway at ${this.gatewayUrl}`));
      console.error(chalk.gray('Make sure the gateway service is running'));
    } else if (error.code === 'ENOTFOUND') {
      console.error(chalk.red(`Cannot resolve hostname: ${this.gatewayUrl}`));
      console.error(chalk.gray('Check the GATEWAY_URL environment variable'));
    } else if (error.response) {
      console.error(chalk.red(`HTTP ${error.response.status}: ${error.response.statusText}`));
      if (error.response.data) {
        console.error(chalk.gray('Response:', JSON.stringify(error.response.data, null, 2)));
      }
    } else {
      console.error(chalk.red(`Error: ${error.message}`));
    }
    
    console.error(chalk.gray('\nTroubleshooting:'));
    console.error(chalk.gray('- Verify gateway is running: curl http://localhost:3000/health'));
    console.error(chalk.gray('- Check environment variables: GATEWAY_URL'));
    console.error(chalk.gray('- Review gateway logs for errors'));
  }
}

// CLI Interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const script = new HealthDiagnosticsScript();
  
  // Parse command line arguments
  const options = {
    includeHistory: args.includes('--history'),
    includeTrends: args.includes('--trends'),
    outputFormat: args.includes('--json') ? 'json' : 'detailed',
    filterServices: null
  };
  
  // Parse filter services
  const filterIndex = args.indexOf('--services');
  if (filterIndex !== -1 && args[filterIndex + 1]) {
    options.filterServices = args[filterIndex + 1].split(',').map(s => s.trim());
  }
  
  // Help text
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
${chalk.blue.bold('Gateway Health Diagnostics Script')}

Performs comprehensive health checks on all services in the gateway.

${chalk.yellow('Usage:')}
  node scripts/health-diagnostics.js [options]

${chalk.yellow('Options:')}
  --help, -h          Show this help message
  --json              Output results in JSON format
  --history           Include health check history
  --trends            Include health trends analysis
  --services <list>   Filter specific services (comma-separated)

${chalk.yellow('Environment Variables:')}
  GATEWAY_URL         Gateway URL (default: http://localhost:3000)

${chalk.yellow('Examples:')}
  node scripts/health-diagnostics.js
  node scripts/health-diagnostics.js --history --trends
  node scripts/health-diagnostics.js --services auth,comment
  node scripts/health-diagnostics.js --json > health-report.json

${chalk.yellow('Exit Codes:')}
  0 - All services healthy
  1 - Some services degraded
  2 - Some services unhealthy
  3 - Health check failed
`);
    process.exit(0);
  }
  
  // Run the health diagnostics
  script.runHealthDiagnostics(options);
}

module.exports = HealthDiagnosticsScript;