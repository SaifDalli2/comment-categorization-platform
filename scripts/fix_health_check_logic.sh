#!/bin/bash

# Fix Health Check Logic for Industry Service
# Updates the gateway to properly parse industry service health response

echo "🔧 Fixing Gateway Health Check Logic"
echo "=================================="

# Create backup
BACKUP_DIR="backup_health_logic_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
[ -f "server.js" ] && cp "server.js" "$BACKUP_DIR/"

echo "📁 Backup created in $BACKUP_DIR"

# Check current server.js content
if ! grep -q "checkServiceHealth" server.js; then
    echo "❌ Current server.js doesn't have active health checking"
    echo "You need to use the enhanced version with ActiveServiceHealth"
    exit 1
fi

echo "✅ Found health checking logic in server.js"

# Create the fix - replace the health checking method
echo "🔄 Updating health check parsing logic..."

# Use Python to properly update the JavaScript function
python3 << 'EOF'
import re
import sys

# Read the current server.js
try:
    with open('server.js', 'r') as f:
        content = f.read()
except FileNotFoundError:
    print("❌ server.js not found")
    sys.exit(1)

# Find and replace the checkServiceHealth method
old_method_pattern = r'async checkServiceHealth\(serviceName\) \{.*?\n  \}'
new_method = '''async checkServiceHealth(serviceName) {
    const serviceInfo = this.serviceStatus.get(serviceName);
    if (!serviceInfo || !serviceInfo.healthCheckEnabled) return;
    
    const startTime = Date.now();
    
    try {
      const response = await axios.get(`${serviceInfo.url}/health`, {
        timeout: 10000,
        headers: {
          'User-Agent': 'Gateway-Health-Check/1.1.0',
          'X-Gateway-Request': 'true'
        }
      });
      
      const responseTime = Date.now() - startTime;
      let isHealthy = false;
      
      // Enhanced health response parsing
      if (response.status === 200 && response.data) {
        const data = response.data;
        
        // Handle multiple health response formats
        if (typeof data === 'object') {
          // Check for explicit healthy status
          if (data.status === 'healthy' || data.status === 'ok') {
            isHealthy = true;
          }
          // Check for alternative health indicators
          else if (data.health === 'healthy' || data.health === 'ok') {
            isHealthy = true;
          }
          // For complex responses like industry service, check if no errors and has status
          else if (data.status && data.status !== 'unhealthy' && data.status !== 'error' && !data.error) {
            isHealthy = true;
          }
          // If response has timestamp and version, likely healthy
          else if (data.timestamp && data.version && !data.error) {
            isHealthy = true;
          }
        }
        // Simple string responses
        else if (typeof data === 'string' && (data.includes('healthy') || data.includes('ok'))) {
          isHealthy = true;
        }
      }
      
      serviceInfo.status = isHealthy ? 'healthy' : 'unhealthy';
      serviceInfo.lastCheck = new Date().toISOString();
      serviceInfo.responseTime = responseTime;
      
      if (isHealthy) {
        serviceInfo.lastSuccess = serviceInfo.lastCheck;
        serviceInfo.consecutiveFailures = 0;
        logger.debug(`Health check ${serviceName}: healthy (${responseTime}ms)`);
      } else {
        serviceInfo.consecutiveFailures++;
        logger.warn(`Health check ${serviceName}: unhealthy - response: ${JSON.stringify(response.data).substring(0, 100)}`);
      }
      
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      serviceInfo.status = 'unhealthy';
      serviceInfo.lastCheck = new Date().toISOString();
      serviceInfo.responseTime = responseTime;
      serviceInfo.consecutiveFailures++;
      
      // Enhanced error logging
      if (error.code === 'ECONNREFUSED') {
        logger.warn(`Health check ${serviceName}: connection refused`);
      } else if (error.code === 'ETIMEDOUT') {
        logger.warn(`Health check ${serviceName}: timeout`);
      } else if (error.response && error.response.status === 404) {
        logger.debug(`Health check ${serviceName}: /health endpoint not found`);
        serviceInfo.status = 'unknown';
      } else {
        logger.warn(`Health check ${serviceName}: ${error.message}`);
      }
    }
  }'''

# Replace the method using regex with DOTALL flag
updated_content = re.sub(
    old_method_pattern, 
    new_method, 
    content, 
    flags=re.DOTALL
)

# Check if replacement was successful
if updated_content != content:
    # Write the updated content
    with open('server.js', 'w') as f:
        f.write(updated_content)
    print("✅ Successfully updated health check logic")
else:
    print("❌ Could not find or replace health check method")
    print("The method signature might be different")
    sys.exit(1)
EOF

# Check if the Python script succeeded
if [ $? -eq 0 ]; then
    echo "✅ Health check logic updated successfully"
    
    # Verify the change
    if grep -q "Enhanced health response parsing" server.js; then
        echo "✅ Verified: Enhanced parsing logic added"
    else
        echo "⚠️  Could not verify the update"
    fi
    
    echo ""
    echo "🚀 Deploy the fix:"
    echo "git add server.js"
    echo "git commit -m 'Fix health check parsing for industry service'"
    echo "git push heroku main"
    echo ""
    echo "🔍 After deployment, the industry service should show as 'in-sync'"
    echo ""
    echo "⏱️  Expected timeline:"
    echo "1. Deploy (2-3 minutes)"
    echo "2. Wait for next health check cycle (up to 2 minutes)"
    echo "3. Check result: curl https://gateway-service-b25f91548194.herokuapp.com/health/sync"
    
else
    echo "❌ Failed to update health check logic"
    echo "Restoring backup..."
    cp "$BACKUP_DIR/server.js" server.js
    
    echo ""
    echo "🔧 Manual fix option:"
    echo "The issue is that your gateway's health checker is too strict."
    echo "Your industry service returns a valid healthy response, but the gateway"
    echo "doesn't recognize the format."
    echo ""
    echo "Industry service response format:"
    curl -s https://industry-service-voice-f7d40a18c50e.herokuapp.com/health | head -c 150
    echo "..."
fi