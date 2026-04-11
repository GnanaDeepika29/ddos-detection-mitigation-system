# DDoS Detection & Mitigation System - Deployment Guide

## Overview
This guide covers deploying the complete DDoS Detection and Mitigation System to cloud environments. The system is designed for horizontal scaling, high availability, and production readiness.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Cloud Load Balancer                      │
│              (AWS Shield / Azure DDoS)                  │
└──────────────────────┬──────────────────────────────────┘
                       │
        ┌───────────────┴───────────────┐
        │                           │
┌───────▼───────┐      ┌────────▼────────┐
│  Collector    │      │    API         │
│  Service     │      │  Service      │
│  (:9092)     │      │  (:8000)      │
└───────┬───────┘      └───────┬────────┘
        │                    │
        │         ┌──────────┴──────────┐
        │         │                    │
        │    ┌───▼────┐        ┌──▼─────┐
        │    │Redis   │        │Kafka   │
        │    │:6379  │        │:9092  │
        │    └───────┘        └───────┘
        │                       │
        │              ┌──────▼───────┐
        │              │  Detector   │
        │              │  Service   │
        │              └──────┬───────┘
        │                     │
        │              ┌──────▼───────┐
        │              │ Mitigation │
        │              │ Service   │
        │              └───────────┘
        │
   ┌──────▼───────┐
   │  Prometheus │
   │  (:9090)   │
   └──────┬───────┘
          │
   ┌──────▼───────┐
   │   Grafana   │
   │   (:3000)   │
   └────────────┘
```

## Prerequisites

- Kubernetes 1.25+
- Helm 3.10+
- kubectl configured
- Docker (for building images)
- Cloud provider CLI (AWS/Azure/GCP)

## Quick Start (Local Development)

```bash
# Clone and setup
git clone https://github.com/yourorg/ddos-detection-mitigation-system.git
cd ddos-detection-mitigation-system

# Start local stack
docker-compose -f docker-compose.yml up -d

# Access services
# API: http://localhost:8000
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)
# Kafka: localhost:9092
```

## Production Deployment

### 1. Build Container Images

```bash
# Build all services
./scripts/build_k8s_images.sh

# Or with Make
make build-images
```

### 2. Deploy to Kubernetes (Helm)

```bash
# Add Helm repository
helm repo add ddos-system https://yourrepo.github.io/ddos-system
helm repo update

# Deploy to Kubernetes
helm install ddos-release ddos-system/ddos-system \
  --version 1.0.0 \
  --namespace ddos-system \
  --create-namespace \
  -f deployment/helm/ddos-system/values.yaml
```

### 3. Verify Deployment

```bash
# Check pods
kubectl get pods -n ddos-system

# Check services
kubectl get svc -n ddos-system

# Check metrics
curl http://ddos-detector:9091/metrics
```

## Cloud Deployment (AWS)

### Using Terraform

```bash
cd deployment/terraform

# Initialize
terraform init

# Plan
terraform plan -var-file=terraform.tfvars

# Apply
terraform apply -var-file=terraform.tfvars
```

### AWS Resources Created
- EKS Cluster
- RDS (optional)
- ElastiCache Redis
- MSK Kafka
- VPC with private subnets

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| KAFKA_BOOTSTRAP_SERVERS | Kafka brokers | localhost:9092 |
| REDIS_HOST | Redis host | localhost |
| REDIS_PORT | Redis port | 6379 |
| DETECTION_THRESHOLD_PPS | Packets/sec threshold | 50000 |
| AUTO_MITIGATE | Enable auto-mitigation | false |
| CLOUD_PROVIDER | Cloud provider | none |
| LOG_LEVEL | Logging level | INFO |

### Helm Values

```yaml
# Custom values file
global:
  replicas: 3
  imagePullSecrets: docker-registry

collector:
  replicas: 2
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi

detector:
  replicas: 3
  resources:
    limits:
      cpu: 2000m
      memory: 2Gi

mitigation:
  replicas: 2

kafka:
  enabled: true

redis:
  enabled: true

prometheus:
  enabled: true

grafana:
  enabled: true
```

## Scaling

### Horizontal Pod Autoscaling

```bash
# Apply HPA
kubectl apply -f deployment/kubernetes/overlays/prod/hpa.yaml

# View HPA
kubectl get hpa -n ddos-system
```

## Monitoring & Alerting

### Access Dashboards

```bash
# Port forward Grafana
kubectl port-forward -n ddos-system svc/ddos-grafana 3000:3000

# Default credentials
# Username: admin
# Password: admin (change in production)
```

### Prometheus Alerts

- DDoSAttackDetected: Attack detected
- HighDetectionLatency: Detection > 100ms
- MitigationActionsHigh: High mitigation rate
- ServiceDown: Any service down

## Security

### TLS Configuration

```yaml
# Enable TLS
tls:
  enabled: true
  secretName: ddos-tls-cert
```

### API Authentication

```bash
# Set API key
export API_KEY=$(openssl rand -hex 32)
kubectl create secret generic ddos-api-key \
  --from-literal=api-key=$API_KEY \
  -n ddos-system
```

### Network Policies

Network policies are enforced by default in the Helm chart.

## Testing

### Run Tests

```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# All tests
pytest
```

### Load Testing

```bash
# Run load test
python scripts/simulate_traffic.py \
  --target-url http://localhost:8000 \
  --attack-rate 10000 \
  --duration 60
```

### Chaos Testing

```bash
# Install chaos mesh
helm repo add chaos-mesh https://charts.chaos-mesh.org
helm install chaos-mesh chaos-mesh/chaos-mesh -n chaos-mesh --create-namespace

# Run experiments
kubectl apply -f chaos/
```

## Backup & Recovery

### Backup Redis

```bash
# Save Redis data
redis-cli SAVE
kubectl cp ddos-redis-0:/data/dump.rdb ./backup.rdb
```

### Backup Kafka

```bash
# Topic configuration backup
kubectl exec -it ddos-kafka-0 -- \
  kafka-topics --describe \
  --bootstrap-server localhost:9092
```

## Troubleshooting

### Check Logs

```bash
# All services
kubectl logs -n ddos-system -l app=ddos --tail=100

# Specific service
kubectl logs -n ddos-system ddos-detector-0 --tail=100
```

### Common Issues

| Issue | Solution |
|-------|---------|
| High latency | Increase detector replicas |
| Memory issues | Adjust memory limits |
| Kafka lag | Check consumer lag |
| Detection missed | Verify threshold settings |

## Cleanup

```bash
# Uninstall Helm
helm uninstall ddos-release -n ddos-system

# Delete namespace
kubectl delete namespace ddos-system

# Delete persistent volumes
kubectl delete pvc -n ddos-system --all
```

## Support

- Documentation: docs/
- Issues: GitHub Issues
- Email: security@example.com