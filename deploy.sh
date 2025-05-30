#!/bin/bash

# Deployment script for gateway service
set -e

echo "🚀 Deploying Gateway Service..."

# Check if we're logged into Heroku
if ! heroku auth:whoami &> /dev/null; then
    echo "❌ Please login to Heroku first: heroku login"
    exit 1
fi

# Get app name
APP_NAME=$(heroku apps --json | jq -r '.[] | select(.name | contains("gateway")) | .name' | head -1)

if [ -z "$APP_NAME" ]; then
    echo "❌ No Heroku app found with 'gateway' in the name"
    echo "Available apps:"
    heroku apps --json | jq -r '.[].name'
    exit 1
fi

echo "📱 Deploying to app: $APP_NAME"

# Push to Heroku
echo "📤 Pushing code to Heroku..."
git add .
git commit -m "Update gateway service with fixes" || echo "No changes to commit"
git push heroku main

# Wait for deployment
echo "⏳ Waiting for deployment..."
sleep 10

# Check deployment status
echo "🔍 Checking deployment status..."
heroku ps --app $APP_NAME

# Test health endpoint
echo "🏥 Testing health endpoint..."
APP_URL=$(heroku apps:info --app $APP_NAME --json | jq -r '.app.web_url')
curl -f "${APP_URL}health" || echo "Health check failed"

# Show logs
echo "📋 Recent logs:"
heroku logs --tail --num 20 --app $APP_NAME

echo "✅ Deployment complete!"
echo "🌐 App URL: $APP_URL"
echo "📊 Logs: heroku logs --tail --app $APP_NAME"
