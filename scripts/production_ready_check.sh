#!/bin/bash
# scripts/production_ready_check.sh
set -e

echo "Running production readiness checks..."

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Check if .env exists
if [ ! -f .env ]; then
    echo ".env file not found. Copy .env.example to .env first."
    exit 1
fi

# Security checks
echo "Running security audit..."
python3 scripts/security_audit.py

# Generate TLS certs if not exists
if [ ! -f certs/ca.crt ]; then
    echo "Generating TLS certificates..."
    ./scripts/generate_tls_certs.sh
else
    echo "TLS certificates exist"
fi

# Generate secure credentials if needed
if grep -q "changeme" .env 2>/dev/null; then
    echo "Default credentials found. Consider running: python3 scripts/generate_secrets.py --force"
fi

# Verify no default passwords
if grep -i "changeme\|admin\|password" .env | grep -v "^#" > /dev/null 2>&1; then
    echo "Default passwords found in .env."
    echo "Please update: API_JWT_SECRET_KEY, API_API_KEY, REDIS_PASSWORD, POSTGRES_PASSWORD"
    exit 1
else
    echo "No default passwords found"
fi

# Check TLS configuration
if [ -f docker-compose.tls.yml ]; then
    if command -v docker-compose &>/dev/null; then
        docker-compose -f docker-compose.tls.yml config --quiet >/dev/null 2>&1 && echo "TLS configured" || echo "TLS configuration has issues"
    elif command -v docker &>/dev/null; then
        docker compose -f docker-compose.tls.yml config --quiet >/dev/null 2>&1 && echo "TLS configured" || echo "TLS configuration has issues"
    else
        echo "Docker not installed; skipping TLS compose validation"
    fi
fi

# Validate retention policy
if grep -q "DATA_RETENTION_DAYS" .env; then
    RETENTION=$(grep "DATA_RETENTION_DAYS" .env | cut -d'=' -f2 | tr -d ' ')
    if [[ "$RETENTION" =~ ^[0-9]+$ ]]; then
        echo "Retention policy set to $RETENTION days"
    else
        echo "DATA_RETENTION_DAYS is not a valid number"
    fi
else
    echo "DATA_RETENTION_DAYS not set"
fi

# Enable audit logging if not set
if ! grep -q "AUDIT_LOG_ENABLED=true" .env; then
    echo "AUDIT_LOG_ENABLED=true" >> .env
    echo "Audit logging enabled"
fi

# Check Kafka connectivity
if command -v nc &>/dev/null; then
    KAFKA_BOOTSTRAP_RAW=$(grep -E '^KAFKA_BOOTSTRAP_SERVERS=' .env 2>/dev/null | tail -n1 | cut -d'=' -f2- | tr -d ' "')
    KAFKA_BOOTSTRAP_RAW=${KAFKA_BOOTSTRAP_RAW:-${KAFKA_BOOTSTRAP_SERVERS:-localhost:9092}}
    KAFKA_ENDPOINT=${KAFKA_BOOTSTRAP_RAW%%,*}
    KAFKA_HOST=${KAFKA_ENDPOINT%%:*}
    KAFKA_PORT=${KAFKA_ENDPOINT##*:}
    if nc -z "$KAFKA_HOST" "${KAFKA_PORT:-9092}" 2>/dev/null; then
        echo "Kafka is reachable"
    else
        echo "Kafka not reachable at $KAFKA_HOST:${KAFKA_PORT:-9092}"
    fi
fi

echo ""
echo "Ready for production deployment checks to continue"
