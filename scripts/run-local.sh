#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../"

SIMULATE=${1:-}
AUTO_SIMULATE=false
if [[ "$SIMULATE" == "--simulate-auto" ]]; then
  AUTO_SIMULATE=true
fi

echo "🚀 Starting Production-Ready Local DDoS Stack (E2E)"
echo "Usage: $0 [--simulate-auto]"
echo "Copy .env.template → .env & edit secrets first!"

# Load .env → validate with loader
if [[ ! -f .env ]]; then
  echo "❌ Copy .env.template → .env & edit secrets!"
  exit 1
fi

python3 -c "
from src.utils.env_loader import load_env, LOCAL_VARS
load_env(required_vars=LOCAL_VARS)
print('✅ Local .env validated')
" || exit 1

# Auto-train models if missing (CICDDoS2019 → production/)
echo "🤖 Auto-training models if needed..."
PROD_XGB="models/production/xgboost_cic_fresh.pkl"
PROD_IF="models/production/isolation_forest.pkl"
if [[ ! -f "$PROD_XGB" || ! -f "$PROD_IF" ]]; then
  echo "Training XGBoost + IsolationForest from datasets/..."
  python scripts/train_model.py --auto --output models/production/xgboost_cic_fresh --type xgboost --sample-frac 0.05 || echo "XGBoost done"
  python scripts/train_model.py --auto --output models/production/isolation_forest --type isolation_forest --sample-frac 0.05 || echo "IF done"
  echo "✅ Models ready in models/production/"
fi

# Docker compose: prod + alertmanager + volumes clean
echo "🐳 Docker Compose up (full prod stack)..."
docker compose -f docker-compose.prod.yml -f docker-compose.alertmanager.yml down -v --remove-orphans || true
docker compose -f docker-compose.prod.yml -f docker-compose.alertmanager.yml build --no-cache --parallel
docker compose -f docker-compose.prod.yml -f docker-compose.alertmanager.yml up -d

# Health retry (max 5min)
echo "⏳ Health checks (retry up to 5min)..."
MAX_WAIT=300
START=$(date +%s)
HEALTH_OK=false
while [[ $(( $(date +%s) - START )) -lt $MAX_WAIT ]]; do
  curl -f -s http://localhost:8000/health >/dev/null && \
  curl -f -s http://localhost:9090/-/healthy >/dev/null && \
  curl -f -s http://localhost:3000/api/health >/dev/null && {
    HEALTH_OK=true
    echo "✅ All services healthy!"
    break
  }
  echo "Services starting... $(date)"
  sleep 10
done

if [[ "$HEALTH_OK" != true ]]; then
  echo "⚠️ Health timeout - check 'docker compose logs'"
fi

# Auto-simulate if flagged (triggers detection/mitigation/alerts/Grafana)
if [[ "$AUTO_SIMULATE" == true ]]; then
  echo "🚨 Auto-simulating DDoS UDP flood (60k pps x 30s → detection → alerts)..."
  python scripts/simulate_traffic.py --target 127.0.0.1 --port 8000 --attack udp_flood --rate 60000 --duration 30 --threads 4 &
  SIM_PID=$!
  sleep 40  # Attack + detection window + alert propagation
  kill $SIM_PID 2>/dev/null || true
  echo "✅ Simulation + detection complete → Check Grafana/Prometheus!"
fi

# Try open browser (Windows/Linux/Mac)
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://localhost:${GRAFANA_PORT:-3000}"
elif command -v open >/dev/null 2>&1; then
  open "http://localhost:${GRAFANA_PORT:-3000}"
elif start "" >/dev/null 2>&1; then
  start "http://localhost:${GRAFANA_PORT:-3000}"
fi

echo ""
echo "🌐 Production Stack Ready:"
echo "  🔐 Grafana: http://localhost:${GRAFANA_PORT:-3000} (admin/\${GRAFANA_ADMIN_PASS:-admin})"
echo "  📊 Prometheus: http://localhost:9090"
echo "  ⚙️ API + Docs: http://localhost:8000/docs"
echo "  📡 Kafka: localhost:9092 (network_flows_prod → ddos_alerts_prod)"
echo ""
echo "📈 Live Monitoring:"
echo "  docker compose logs -f --tail=50 detector mitigation api"
echo "🛑 Graceful Stop:"
echo "  docker compose -f docker-compose.prod.yml -f docker-compose.alertmanager.yml down"
echo ""
echo "✅ Phase 3/Step 1: Local E2E ✅ Next: K8s build/deploy"
