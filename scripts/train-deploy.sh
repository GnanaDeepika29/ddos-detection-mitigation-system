#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../"

MODE=${1:-local}
FORCE_TRAIN=false
[[ "$MODE" == "--train" || "$MODE" == "--force-train" ]] && { FORCE_TRAIN=true; MODE="local"; }
[[ "$MODE" == "--cloud" ]] && MODE="cloud"

echo "🚀 DDoS Pipeline: ${MODE^^} (train → build → deploy)"
echo "Usage: $0 [local|cloud|--train|--force-train]"

# Validate core .env
if [[ ! -f .env ]]; then
  echo "❌ Copy .env.template → .env first!"
  exit 1
fi

python3 -c "from src.utils.env_loader import load_env, CORE_VARS; load_env(required_vars=CORE_VARS); print('✅ Env OK')"

PROD_XGB="models/production/xgboost_cic_fresh.pkl"
PROD_IF="models/production/isolation_forest.pkl"

case "${MODE}" in
  "local")
    # Local: train → docker-compose
    if [[ "$FORCE_TRAIN" == true || ! -f "$PROD_XGB" ]]; then
      echo "📊 Training models..."
      python scripts/train_model.py --auto --output models/production/xgboost_cic_fresh --type xgboost --sample-frac 0.05
      python scripts/train_model.py --auto --output models/production/isolation_forest --type isolation_forest --sample-frac 0.05
    fi
    ./scripts/run-local.sh --simulate-auto
    ;;
  "cloud")
    # Cloud: train → ECR → terraform/helm
    echo "📊 Training production models..."
    python scripts/train_model.py --auto --output models/production/xgboost_cic_fresh --type xgboost --sample-frac 0.02
    python scripts/train_model.py --auto --output models/production/isolation_forest --type isolation_forest --sample-frac 0.02
    
    echo "🐳 Building/pushing ECR images..."
    ./scripts/build_k8s_images.sh --push --registry ddos-system --tag production
    
    echo "☁️ Terraform + Helm deploy..."
    ./scripts/deploy-cloud.sh deploy
    
    ./scripts/deploy-cloud.sh port-forward
    ;;
  *)
    echo "Usage: $0 {local|cloud|--train}"
    exit 1
esac

echo "✅ Pipeline complete!
Local: Grafana localhost:3000 | API:8000
Cloud: kubectl get all -n ddos-system | ./scripts/deploy-cloud.sh port-forward"

