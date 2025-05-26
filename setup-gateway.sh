#!/bin/bash
# setup-gateway.sh - Script to set up the API Gateway structure

echo "🚀 Setting up API Gateway project structure..."

# Create main directory structure
mkdir -p gateway-service/{config,middleware,routes,utils,tests}

# Create configuration files
echo "📝 Creating configuration files..."

# Create basic config directory structure
mkdir -p gateway-service/config/{environments,services}

# Create middleware directory structure  
mkdir -p gateway-service/middleware/{auth,security,logging}

# Create routes directory structure
mkdir -p gateway-service/routes/{api,health}

# Create utils directory structure
mkdir -p gateway-service/utils/{logger,validator,helpers}

# Create tests directory structure
mkdir -p gateway-service/tests/{unit,integration,e2e}

# Copy existing public directory if it exists
if [ -d "public" ]; then
    echo "📁 Copying public directory..."
    cp -r public gateway-service/
else
    echo "📁 Creating empty public directory..."
    mkdir -p gateway-service/public
fi

echo "📦 Installing dependencies..."
cd gateway-service

# Initialize package.json if it doesn't exist
if [ ! -f "package.json" ]; then
    npm init -y
fi

# Install production dependencies
npm install express http-proxy-middleware cors express-rate-limit helmet morgan compression dotenv

# Install development dependencies
npm install --save-dev nodemon jest supertest eslint eslint-config-standard

echo "🔧 Setting up environment file..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✅ Created .env file from .env.example"
    echo "⚠️  Please update the .env file with your actual configuration"
else
    echo "✅ .env file already exists"
fi

echo "📋 Creating basic project files..."

# Create .gitignore
cat > .gitignore << 'EOF'
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.production

# Logs
logs
*.log

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/

# Build outputs
dist/
build/

# IDE files
.vscode/
.idea/
*.swp
*.swo

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
EOF

# Create basic README
cat > README.md << 'EOF'
# API Gateway Service

This is the API Gateway for the Comment Categorization microservices architecture.

## Quick Start

1. Copy environment variables:
   ```bash
   cp .env.example .env
   ```

2. Update the `.env` file with your service URLs

3. Install dependencies:
   ```bash
   npm install
   ```

4. Start the development server:
   ```bash
   npm run dev
   ```

5. Check health status:
   ```bash
   curl http://localhost:3000/health
   ```

## Available Scripts

- `npm start` - Start production server
- `npm run dev` - Start development server with nodemon
- `npm test` - Run tests
- `npm run lint` - Run ESLint

## Endpoints

- `GET /health` - Service health check
- `GET /api/status` - API status
- `/api/auth/*` - Authentication service proxy
- `/api/comments/*` - Comment processing service proxy
- `/api/industries/*` - Industry configuration service proxy
- `/api/nps/*` - NPS analytics service proxy

## Architecture

This gateway acts as the single entry point for all client requests, routing them to the appropriate microservices.
EOF

echo "✅ API Gateway project structure created successfully!"
echo ""
echo "Next steps:"
echo "1. cd gateway-service"
echo "2. Update .env file with your configuration"
echo "3. npm run dev"
echo "4. Test with: curl http://localhost:3000/health"
echo ""
echo "📖 See README.md for more details"