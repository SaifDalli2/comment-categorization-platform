#!/bin/bash
# deploy-enhanced.sh - Deploy enhanced gateway

set -e

echo "🚀 Deploying enhanced gateway to Heroku..."

# Add and commit changes
git add .
git commit -m "feat: upgrade gateway with enhanced service management and monitoring" || echo "Nothing to commit"

# Push to Heroku
git push heroku main

# Set enhanced configuration
echo "⚙️ Setting enhanced configuration..."
heroku config:set USE_ENHANCED_AUTH=false --app gateway-service-b25f91548194
heroku config:set ENABLE_AGGREGATED_ENDPOINTS=true --app gateway-service-b25f91548194

echo "✅ Deployment complete!"
echo ""
echo "Test your enhanced gateway:"
echo "curl https://gateway-service-b25f91548194.herokuapp.com/health"
echo "curl https://gateway-service-b25f91548194.herokuapp.com/api/gateway/services"
