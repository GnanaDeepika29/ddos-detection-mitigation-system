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
