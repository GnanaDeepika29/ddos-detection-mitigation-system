#!/bin/bash
# Build and start the full stack (from repo root).
set -eu

# Get the script directory and change to repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "Working directory: $(pwd)"

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is not running"
    exit 1
fi

# Check prerequisites
if ! command -v docker &>/dev/null; then
    echo "Error: Docker not found. Install from https://docker.com"
    exit 1
fi

# Create .env if missing
if [ ! -f ".env" ]; then
    echo "Creating .env with secure defaults..."
    # Simplified generation (manual openssl or use generate_secrets.py)
    cat > .env << 'EOF'
GRAFANA_PASSWORD=securegrafana123
INFLUXDB_PASSWORD=secureinflux123
INFLUXDB_TOKEN=securetoken123
ELASTICSEARCH_PASSWORD=secureelastic123
API_API_KEY=secureapikey123
EOF
fi

# Check if docker-compose.yml exists
if [ ! -f "docker-compose.yml" ]; then
    echo "Error: docker-compose.yml not found"
    exit 1
fi

# Build and start services
echo "Starting Docker Compose..."
docker compose up -d --build

# Show status
docker compose ps

echo ""
echo "Services started:"
echo "  API: http://localhost:8000"
echo "  Grafana: http://localhost:3000 (admin/admin)"
echo "  Prometheus: http://localhost:9090"
echo "  Alertmanager: http://localhost:9094"
echo ""
echo "To view logs: docker compose logs -f"
echo "To stop: docker compose down"
