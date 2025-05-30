#!/usr/bin/env node

// Debug script to check configuration
const config = require('./config/simple');

console.log('=== Gateway Configuration Debug ===\n');

console.log('🔧 Basic Configuration:');
console.log(`Port: ${config.port}`);
console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
console.log(`Log Level: ${config.monitoring.logLevel}`);

console.log('\n📡 Service URLs:');
Object.entries(config.services).forEach(([name, url]) => {
  const status = config.isServiceConfigured(name) ? '✅ Configured' : '❌ Not Configured';
  console.log(`${name}: ${url} ${status}`);
});

console.log('\n🔒 Security:');
console.log(`JWT Secret: ${config.security.jwtSecret ? '✅ Set (' + config.security.jwtSecret.length + ' chars)' : '❌ Missing'}`);
console.log(`CORS Origins: ${config.security.corsOrigins.length} configured`);
config.security.corsOrigins.forEach(origin => console.log(`  - ${origin}`));

console.log('\n🛡️  Rate Limiting:');
console.log(`Global: ${config.rateLimit.global.max} req/${config.rateLimit.global.windowMs/1000}s`);
console.log(`Auth: ${config.rateLimit.auth.max} req/${config.rateLimit.auth.windowMs/1000}s`);
console.log(`Comments: ${config.rateLimit.comments.max} req/${config.rateLimit.comments.windowMs/1000}s`);

console.log('\n📊 Environment Info:');
const envInfo = config.getEnvironmentInfo();
console.log(`Node Version: ${envInfo.nodeVersion}`);
console.log(`Platform: ${envInfo.platform}`);
console.log(`Memory Usage: ${Math.round(envInfo.memory.heapUsed / 1024 / 1024)}MB`);
console.log(`Configured Services: ${envInfo.configuredServices.join(', ') || 'none'}`);
