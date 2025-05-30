#!/usr/bin/env node

// Script to discover and test service connectivity
const config = require('./config/simple');

async function discoverServices() {
  console.log('=== Service Discovery ===\n');
  
  try {
    const discoveries = await config.discoverServices();
    
    console.log('Service Status:');
    Object.entries(discoveries).forEach(([name, info]) => {
      let statusIcon = '❌';
      if (info.status === 'healthy') statusIcon = '✅';
      else if (info.status === 'unhealthy') statusIcon = '⚠️';
      else if (info.status === 'not_configured') statusIcon = '🔧';
      
      console.log(`${statusIcon} ${name.toUpperCase()}: ${info.status}`);
      console.log(`   URL: ${info.url}`);
      if (info.responseTime) console.log(`   Response Time: ${info.responseTime}ms`);
      if (info.version) console.log(`   Version: ${info.version}`);
      if (info.error) console.log(`   Error: ${info.error}`);
      console.log('');
    });
    
    const healthyServices = Object.values(discoveries).filter(s => s.status === 'healthy').length;
    const totalServices = Object.keys(discoveries).length;
    
    console.log(`Summary: ${healthyServices}/${totalServices} services healthy`);
    
  } catch (error) {
    console.error('Discovery failed:', error.message);
    process.exit(1);
  }
}

discoverServices();
