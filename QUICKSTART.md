# DDoS Detection & Mitigation System - Step by Step

## Prerequisites
- Docker & Docker Compose installed
- Python 3.9+ installed
- 4GB+ RAM available
- 10GB+ disk space

---

## Step 1: Clone & Setup

```bash
# Clone or navigate to project
cd ddos-detection-mitigation-system

# Copy environment file
cp .env.example .env

# Create required directories
mkdir -p logs models data
```

---

## Step 2: Start Infrastructure (Kafka, Redis, Prometheus)

```bash
# Start all infrastructure services
docker-compose up -d zookeeper kafka redis prometheus grafana

# Verify services are running
docker-compose ps

# Check logs
docker-compose logs -f kafka
```

**Wait for:** Kafka to be ready (~30 seconds)

---

## Step 3: Build Docker Images

```bash
# Build all service images
docker-compose build

# Or use the build script
./scripts/build_k8s_images.sh
```

---

## Step 4: Start All Services

```bash
# Method 1: Using docker-compose (recommended)
docker-compose up -d

# Method 2: Using run script
./scripts/run-local.sh

# Method 3: Start services individually
docker-compose up -d collector
docker-compose up -d detector  
docker-compose up -d mitigation
docker-compose up -d api
```

---

## Step 5: Verify Services

```bash
# Check all containers
docker-compose ps

# Test API health
curl http://localhost:8000/health

# Test Prometheus
curl http://localhost:9090/-/healthy

# Test Grafana
curl http://localhost:3000/api/health

# Test Kafka
docker exec ddos-kafka kafka-topics --bootstrap-server localhost:9092 --list
```

---

## Step 6: Start Individual Services (Manual)

### Terminal 1: Collector
```bash
# Activate virtual environment
source venv/Scripts/activate  # Windows
source venv/bin/activate   # Linux/Mac

# Run collector
python scripts/run_collector.py --synthetic
```

### Terminal 2: Detector
```bash
source venv/Scripts/activate

# Run detector
python scripts/run_detector.py
```

### Terminal 3: Mitigation
```bash
source venv/Scripts/activate

# Run mitigation
python scripts/run_mitigation.py
```

---

## Step 7: Access Dashboards

| Service | URL | Credentials |
|---------|-----|--------------|
| API | http://localhost:8000 | API_KEY from .env |
| Grafana | http://localhost:3000 | admin/admin |
| Prometheus | http://localhost:9090 | - |
| Kafka UI | http://localhost:8080 | - |

---

## Step 8: Test Attack Simulation

```bash
# Run traffic simulator
python scripts/simulate_traffic.py \
  --target-ip 10.0.0.1 \
  --attack-type syn_flood \
  --duration 60

# Or use load tester
python scripts/load_test.py \
  --attack-type syn \
  --attack-rate 5000 \
  --duration 30
```

---

## Step 9: Monitor in Real-Time

```bash
# Watch detection alerts
docker-compose logs -f detector | grep ATTACK

# Watch mitigation actions
docker-compose logs -f mitigation

# Check API alerts
curl http://localhost:8000/alerts

# Check metrics
curl http://localhost:9091/metrics
```

---

## Step 10: Kubernetes Deployment (Production)

```bash
# Deploy to Kubernetes
kubectl apply -f deployment/kubernetes/

# Or use Helm
helm install ddos-system deployment/helm/ddos-system/

# Check pods
kubectl get pods -n ddos-system

# View logs
kubectl logs -n ddos-system -l app=ddos-detector
```

---

## Quick Start (One Command)

```bash
# Start everything at once
docker-compose up -d && sleep 30 && docker-compose logs -f
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Kafka not starting | Check Docker resources |
| Port conflicts | Stop other services on ports 8000, 9090, 3000 |
| Memory errors | Increase Docker memory to 4GB+ |
| Connection refused | Wait 30s for Kafka to initialize |

---

## Service Order

```
1. zookeeper      (first)
2. kafka          
3. redis         
4. prometheus    (depends on kafka)
5. grafana       (depends on prometheus)
6. collector     (depends on kafka)
7. detector      (depends on kafka, redis)
8. mitigation    (depends on kafka, redis)
9. api          (depends on all)
```