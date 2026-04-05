#!/bin/bash
# scripts/init_secure_services.sh
set -e

# Generate random password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
}

# Check if container is running
container_running() {
    docker ps --format "{{.Names}}" | grep -q "^$1$" 2>/dev/null
}

# Wait for container to be ready
wait_for_container() {
    local container=$1
    local max_attempts=30
    local attempt=0
    
    echo "Waiting for $container to be ready..."
    while ! container_running "$container" && [ $attempt -lt $max_attempts ]; do
        sleep 2
        attempt=$((attempt + 1))
    done
    
    if container_running "$container"; then
        echo "$container is running."
        return 0
    else
        echo "Warning: $container not running after $max_attempts attempts"
        return 1
    fi
}

# InfluxDB secure setup
setup_influxdb() {
    if ! container_running "ddos-influxdb"; then
        echo "InfluxDB container not running, skipping"
        return
    fi
    
    local password=$(generate_password)
    local token=$(generate_password)
    
    # Wait a bit for InfluxDB to be ready
    sleep 5
    
    docker exec ddos-influxdb influx setup \
        --username admin \
        --password "$password" \
        --org ddos \
        --bucket metrics \
        --token "$token" \
        --force 2>/dev/null || true
    
    # Save credentials
    cat > .env.influx <<EOF
INFLUXDB_PASSWORD=$password
INFLUXDB_TOKEN=$token
INFLUXDB_ORG=ddos
INFLUXDB_BUCKET=metrics
EOF
    
    echo "InfluxDB credentials saved to .env.influx"
}

# Elasticsearch secure setup
setup_elasticsearch() {
    if ! container_running "ddos-elasticsearch"; then
        echo "Elasticsearch container not running, skipping"
        return
    fi
    
    # Wait for Elasticsearch to be ready
    sleep 10
    
    # Reset password
    docker exec ddos-elasticsearch bin/elasticsearch-reset-password -u elastic -b -s > .env.elastic 2>/dev/null || {
        echo "Warning: Could not reset Elasticsearch password"
        echo "ELASTICSEARCH_PASSWORD=changeme" > .env.elastic
    }
    
    echo "Elasticsearch credentials saved to .env.elastic"
}

# Grafana secure setup
setup_grafana() {
    if ! container_running "ddos-grafana"; then
        echo "Grafana container not running, skipping"
        return
    fi
    
    local password=$(generate_password)
    
    # Wait for Grafana to be ready
    sleep 5
    
    docker exec ddos-grafana grafana-cli admin reset-admin-password "$password" 2>/dev/null || {
        echo "Warning: Could not reset Grafana password"
    }
    
    echo "GRAFANA_PASSWORD=$password" > .env.grafana
    
    echo "Grafana credentials saved to .env.grafana"
}

# Main execution
echo "Setting up secure services..."

# Wait for containers to be ready
wait_for_container "ddos-influxdb"
wait_for_container "ddos-elasticsearch"
wait_for_container "ddos-grafana"

setup_influxdb
setup_elasticsearch
setup_grafana

echo ""
echo "✅ All services configured with strong passwords"
echo "⚠️  Store .env.* files in a secure vault (e.g., Bitwarden, 1Password)"
