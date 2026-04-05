#!/bin/bash
# ============================================
# Kafka Deployment Script for DDoS Detection System
# ============================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Apache Kafka version (for binary/local installs)
KAFKA_VERSION="3.5.0"
CONFLUENT_VERSION="7.5.0"

SCALA_VERSION="2.13"
DEPLOYMENT_TYPE="docker"
KAFKA_HOME="/opt/kafka"
DATA_DIR="/var/lib/kafka/data"
LOG_DIR="/var/log/kafka"
ZOOKEEPER_HOSTS="localhost:2181"
BROKER_ID=1
BROKER_PORT=9092
NUM_PARTITIONS=6
REPLICATION_FACTOR=2
TOPICS=("network_flows" "ddos_alerts" "detection_metrics" "mitigation_events")

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy Kafka for DDoS Detection System

Options:
    -t, --type TYPE      Deployment type (docker, local, kubernetes) [default: docker]
    -v, --version VER    Kafka version [default: 3.5.0]
    -b, --broker-id ID   Broker ID [default: 1]
    -p, --port PORT      Broker port [default: 9092]
    -z, --zookeeper HOST Zookeeper hosts [default: localhost:2181]
    -n, --num-partitions N Number of partitions [default: 6]
    -r, --replication N   Replication factor [default: 2]
    --help               Show this help message
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--type)          DEPLOYMENT_TYPE="$2"; shift 2 ;;
            -v|--version)       KAFKA_VERSION="$2";   shift 2 ;;
            -b|--broker-id)     BROKER_ID="$2";       shift 2 ;;
            -p|--port)          BROKER_PORT="$2";     shift 2 ;;
            -z|--zookeeper)     ZOOKEEPER_HOSTS="$2"; shift 2 ;;
            -n|--num-partitions) NUM_PARTITIONS="$2"; shift 2 ;;
            -r|--replication)   REPLICATION_FACTOR="$2"; shift 2 ;;
            --help)             show_help; exit 0 ;;
            *) log_error "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    case $DEPLOYMENT_TYPE in
        docker)
            command -v docker &>/dev/null || { log_error "Docker not installed"; exit 1; }
            command -v docker-compose &>/dev/null || log_warning "docker-compose not found, using docker compose"
            ;;
        local)
            command -v java &>/dev/null || { log_error "Java not installed"; exit 1; }
            JAVA_VERSION=$(java -version 2>&1 | head -1 | cut -d'"' -f2 | sed 's/^1\.//' | cut -d'.' -f1)
            if [[ "$JAVA_VERSION" -lt 8 ]]; then
                log_error "Java 8+ required"
                exit 1
            fi
            ;;
        kubernetes)
            command -v kubectl &>/dev/null || { log_error "kubectl not installed"; exit 1; }
            command -v helm &>/dev/null || log_warning "helm not found, using raw kubectl"
            ;;
        *) log_error "Unknown deployment type: $DEPLOYMENT_TYPE"; exit 1 ;;
    esac

    log_success "Prerequisites check passed"
}

deploy_docker() {
    log_info "Deploying Kafka with Docker..."

    cat > docker-compose.kafka.yaml << 'EOF'
version: '3.8'

services:
  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    container_name: ddos-zookeeper
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    ports:
      - "2181:2181"
    volumes:
      - zookeeper-data:/var/lib/zookeeper/data
    networks:
      - kafka-network
    restart: unless-stopped

  kafka:
    image: confluentinc/cp-kafka:7.5.0
    container_name: ddos-kafka
    depends_on:
      - zookeeper
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092,PLAINTEXT_INTERNAL://kafka:9092
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092,PLAINTEXT_INTERNAL://0.0.0.0:9092
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_INTERNAL:PLAINTEXT
      KAFKA_INTER_BROKER_LISTENER_NAME: PLAINTEXT_INTERNAL
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"
      KAFKA_DELETE_TOPIC_ENABLE: "true"
      KAFKA_LOG_RETENTION_HOURS: 168
      KAFKA_LOG_SEGMENT_BYTES: 1073741824
      KAFKA_NUM_PARTITIONS: 6
    ports:
      - "9092:9092"
    volumes:
      - kafka-data:/var/lib/kafka/data
    networks:
      - kafka-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "kafka-topics", "--bootstrap-server", "localhost:9092", "--list"]
      interval: 30s
      timeout: 10s
      retries: 5

  kafka-ui:
    image: provectuslabs/kafka-ui:latest
    container_name: ddos-kafka-ui
    depends_on:
      - kafka
    environment:
      KAFKA_CLUSTERS_0_NAME: local
      KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS: kafka:9092
      KAFKA_CLUSTERS_0_ZOOKEEPER: zookeeper:2181
    ports:
      - "8080:8080"
    networks:
      - kafka-network
    restart: unless-stopped

networks:
  kafka-network:
    driver: bridge

volumes:
  zookeeper-data:
  kafka-data:
EOF

    if command -v docker-compose &>/dev/null; then
        docker-compose -f docker-compose.kafka.yaml up -d
    else
        docker compose -f docker-compose.kafka.yaml up -d
    fi

    log_info "Waiting for Kafka to be ready..."
    sleep 15

    create_topics
    log_success "Kafka deployed successfully with Docker"
    log_info "Kafka UI available at: http://localhost:8080"
}

deploy_local() {
    log_info "Deploying Kafka locally..."

    KAFKA_TGZ="kafka_${SCALA_VERSION}-${KAFKA_VERSION}.tgz"
    KAFKA_URL="https://downloads.apache.org/kafka/${KAFKA_VERSION}/${KAFKA_TGZ}"

    if [ ! -f "/tmp/${KAFKA_TGZ}" ]; then
        log_info "Downloading Kafka from ${KAFKA_URL}..."
        wget -O "/tmp/${KAFKA_TGZ}" "${KAFKA_URL}" || curl -L -o "/tmp/${KAFKA_TGZ}" "${KAFKA_URL}"
        
        log_success "Download complete"
    fi

    sudo mkdir -p "${KAFKA_HOME}"
    sudo tar -xzf "/tmp/${KAFKA_TGZ}" -C "${KAFKA_HOME}" --strip-components=1
    sudo mkdir -p "${DATA_DIR}" "${LOG_DIR}"
    sudo chown -R "$(whoami):$(whoami)" "${DATA_DIR}" "${LOG_DIR}"

    cat > "${KAFKA_HOME}/config/zookeeper.properties" << EOF
dataDir=${DATA_DIR}/zookeeper
clientPort=2181
maxClientCnxns=0
admin.enableServer=false
tickTime=2000
initLimit=10
syncLimit=5
EOF

    cat > "${KAFKA_HOME}/config/server.properties" << EOF
broker.id=${BROKER_ID}
listeners=PLAINTEXT://0.0.0.0:${BROKER_PORT}
advertised.listeners=PLAINTEXT://localhost:${BROKER_PORT}
log.dirs=${DATA_DIR}/kafka
zookeeper.connect=${ZOOKEEPER_HOSTS}
num.partitions=${NUM_PARTITIONS}
default.replication.factor=${REPLICATION_FACTOR}
offsets.topic.replication.factor=${REPLICATION_FACTOR}
transaction.state.log.replication.factor=${REPLICATION_FACTOR}
transaction.state.log.min.isr=1
log.retention.hours=168
log.segment.bytes=1073741824
log.retention.check.interval.ms=300000
zookeeper.connection.timeout.ms=18000
group.initial.rebalance.delay.ms=0
EOF

    sudo tee /etc/systemd/system/kafka-zookeeper.service > /dev/null << EOF
[Unit]
Description=Apache Zookeeper
After=network.target

[Service]
Type=simple
User=$(whoami)
ExecStart=${KAFKA_HOME}/bin/zookeeper-server-start.sh ${KAFKA_HOME}/config/zookeeper.properties
ExecStop=${KAFKA_HOME}/bin/zookeeper-server-stop.sh
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/kafka-broker.service > /dev/null << EOF
[Unit]
Description=Apache Kafka Broker
After=network.target kafka-zookeeper.service
Requires=kafka-zookeeper.service

[Service]
Type=simple
User=$(whoami)
ExecStart=${KAFKA_HOME}/bin/kafka-server-start.sh ${KAFKA_HOME}/config/server.properties
ExecStop=${KAFKA_HOME}/bin/kafka-server-stop.sh
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl start kafka-zookeeper
    sudo systemctl start kafka-broker
    sudo systemctl enable kafka-zookeeper
    sudo systemctl enable kafka-broker

    sleep 15
    create_topics
    log_success "Kafka deployed successfully locally"
}

deploy_kubernetes() {
    log_info "Deploying Kafka with Kubernetes..."

    kubectl create namespace ddos-system --dry-run=client -o yaml | kubectl apply -f -

    if command -v helm &>/dev/null; then
        helm repo add bitnami https://charts.bitnami.com/bitnami
        helm repo update

        helm upgrade --install kafka bitnami/kafka \
            --namespace ddos-system \
            --set replicaCount=3 \
            --set listeners.client.protocol=PLAINTEXT \
            --set listeners.client.port=9092 \
            --set persistence.enabled=true \
            --set persistence.size=10Gi \
            --set zookeeper.replicaCount=3 \
            --set zookeeper.persistence.enabled=true \
            --set zookeeper.persistence.size=8Gi
    else
        cat << 'EOF' | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: kafka
  namespace: ddos-system
spec:
  ports:
  - port: 9092
    name: kafka
  clusterIP: None
  selector:
    app: kafka
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: kafka
  namespace: ddos-system
spec:
  serviceName: kafka
  replicas: 3
  selector:
    matchLabels:
      app: kafka
  template:
    metadata:
      labels:
        app: kafka
    spec:
      containers:
      - name: kafka
        image: confluentinc/cp-kafka:7.5.0
        ports:
        - containerPort: 9092
        env:
        - name: KAFKA_BROKER_ID
          value: "1"
        - name: KAFKA_ZOOKEEPER_CONNECT
          value: "zookeeper:2181"
        - name: KAFKA_ADVERTISED_LISTENERS
          value: "PLAINTEXT://$(hostname -f):9092"
        volumeMounts:
        - name: data
          mountPath: /var/lib/kafka/data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
EOF
    fi

    log_info "Waiting for Kafka pods to be ready..."
    kubectl wait --for=condition=ready pod -l app=kafka -n ddos-system --timeout=300s 2>/dev/null || true

    create_topics_kubernetes
    log_success "Kafka deployed successfully on Kubernetes"
}

create_topics() {
    log_info "Creating Kafka topics..."

    for topic in "${TOPICS[@]}"; do
        log_info "Creating topic: $topic"

        case $DEPLOYMENT_TYPE in
            docker)
                docker exec ddos-kafka kafka-topics --create \
                    --bootstrap-server localhost:9092 \
                    --topic "$topic" \
                    --partitions "$NUM_PARTITIONS" \
                    --replication-factor 1 2>/dev/null || true
                ;;
            local)
                "${KAFKA_HOME}/bin/kafka-topics.sh" --create \
                    --bootstrap-server "localhost:${BROKER_PORT}" \
                    --topic "$topic" \
                    --partitions "$NUM_PARTITIONS" \
                    --replication-factor "${REPLICATION_FACTOR}" 2>/dev/null || true
                ;;
        esac
    done

    log_success "Topics created successfully"
}

create_topics_kubernetes() {
    log_info "Creating topics on Kubernetes..."

    for topic in "${TOPICS[@]}"; do
        kubectl run kafka-topic-creator --image="confluentinc/cp-kafka:${CONFLUENT_VERSION}" \
            --namespace ddos-system --rm -it --restart=Never -- \
            kafka-topics --create --bootstrap-server kafka:9092 \
            --topic "$topic" --partitions "$NUM_PARTITIONS" --replication-factor 1 2>/dev/null || true
    done
}

verify_deployment() {
    log_info "Verifying Kafka deployment..."

    case $DEPLOYMENT_TYPE in
        docker)
            if docker exec ddos-kafka kafka-topics --bootstrap-server localhost:9092 --list &>/dev/null; then
                log_success "Kafka is running and accessible"
                docker exec ddos-kafka kafka-topics --bootstrap-server localhost:9092 --list
            else
                log_error "Kafka verification failed"
                exit 1
            fi
            ;;
        local)
            if "${KAFKA_HOME}/bin/kafka-topics.sh" --bootstrap-server "localhost:${BROKER_PORT}" --list &>/dev/null; then
                log_success "Kafka is running and accessible"
                "${KAFKA_HOME}/bin/kafka-topics.sh" --bootstrap-server "localhost:${BROKER_PORT}" --list
            else
                log_error "Kafka verification failed"
                exit 1
            fi
            ;;
        kubernetes)
            if kubectl exec -n ddos-system kafka-0 -- kafka-topics --bootstrap-server kafka:9092 --list &>/dev/null; then
                log_success "Kafka is running and accessible"
            else
                log_error "Kafka verification failed"
                exit 1
            fi
            ;;
    esac
}

show_status() {
    log_info "Kafka Deployment Status:"
    echo "================================"
    case $DEPLOYMENT_TYPE in
        docker)
            docker ps --filter "name=ddos-kafka" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
            ;;
        local)
            sudo systemctl status kafka-broker --no-pager || true
            ;;
        kubernetes)
            kubectl get pods -n ddos-system -l app=kafka 2>/dev/null || true
            kubectl get svc -n ddos-system kafka 2>/dev/null || true
            ;;
    esac
}

main() {
    log_info "Starting Kafka deployment for DDoS Detection System"

    parse_args "$@"
    log_info "Deployment type: $DEPLOYMENT_TYPE"
    check_prerequisites

    case $DEPLOYMENT_TYPE in
        docker)     deploy_docker     ;;
        local)      deploy_local      ;;
        kubernetes) deploy_kubernetes ;;
    esac

    verify_deployment
    show_status
    log_success "Kafka deployment completed successfully!"
}

main "$@"