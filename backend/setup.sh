#!/bin/bash

echo "================================================"
echo "  TOR-Unveil Setup Script"
echo "================================================"
echo ""

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose found"
echo ""

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data/pcap
mkdir -p data/reports
echo "✅ Directories created"
echo ""

# Build and start services
echo "🐳 Building Docker containers..."
docker-compose build

echo ""
echo "🚀 Starting services..."
docker-compose up -d

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check service health
echo ""
echo "🔍 Checking service health..."

# Check PostgreSQL
if docker-compose exec -T postgres pg_isready -U postgres &> /dev/null; then
    echo "✅ PostgreSQL is ready"
else
    echo "⚠️  PostgreSQL is not ready yet"
fi

# Check Redis
if docker-compose exec -T redis redis-cli ping &> /dev/null; then
    echo "✅ Redis is ready"
else
    echo "⚠️  Redis is not ready yet"
fi

# Check Backend API
if curl -s http://localhost:5000/api/health &> /dev/null; then
    echo "✅ Backend API is ready"
else
    echo "⚠️  Backend API is not ready yet"
fi

# Check Frontend
if curl -s http://localhost:8080 &> /dev/null; then
    echo "✅ Frontend is ready"
else
    echo "⚠️  Frontend is not ready yet"
fi

echo ""
echo "================================================"
echo "  TOR-Unveil Setup Complete!"
echo "================================================"
echo ""
echo "🌐 Access the dashboard at: http://localhost:8080"
echo "📡 API endpoint: http://localhost:5000/api"
echo ""
echo "📖 Quick Start Commands:"
echo "  - View logs: docker-compose logs -f"
echo "  - Stop services: docker-compose down"
echo "  - Restart: docker-compose restart"
echo ""
echo "🧪 Test the system:"
echo "  curl http://localhost:5000/api/health"
echo ""
