#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../"

# Multi-platform Docker build + ECR push for K8s deployment
# Usage: ./scripts/build_k8s_images.sh [--push] [--registry REGISTRY] [--tag TAG]

PUSH=false
REGISTRY=""
TAG="ddos-system"
while [[ $# -gt 0 ]]; do
  case $1 in
    --push) PUSH=true; shift ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    *) echo "Unknown arg $1"; exit 1 ;;
  esac
done

# Load .env + validate AWS vars if push
python3 -c "
from src.utils.env_loader import load_env
vars = ['AWS_ACCOUNT_ID', 'AWS_REGION'] if '$PUSH' == 'true' else []
load_env(required_vars=vars)
print('✅ Build env ready')
"

# Use .env vars or defaults
eval $(python3 -c "from src.utils.env_loader import load_env; env=load_env(); print('AWS_ACCOUNT_ID='+repr(env.get('AWS_ACCOUNT_ID',''))); print('AWS_REGION='+repr(env.get('AWS_REGION','us-east-1')))")
VERSION="${TAG:-ddos-system}:$(git rev-parse --short HEAD || echo latest)"
PLATFORMS="linux/amd64,linux/arm64"

if [[ -n "$REGISTRY" ]]; then
  FULL_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REGISTRY}"
else
  FULL_REGISTRY=""
fi

echo "🎨 Building ${TAG}/*:${VERSION} → ${FULL_REGISTRY:+${FULL_REGISTRY}/} [${PLATFORMS}]"
echo "Push to ECR: ${PUSH:+yes} | Tag: ${VERSION}"

# Docker buildx setup
docker buildx create --use --name ddos-multiarch || true
docker buildx inspect --bootstrap

# Build all service images
declare -A IMAGES=(
  ["Dockerfile.api"]="api"
  ["Dockerfile.collector"]="collector" 
  ["Dockerfile.detector"]="detector"
  ["Dockerfile.mitigation"]="mitigation"
  ["Dockerfile.simulator"]="simulator"
)

for dockerfile in "${!IMAGES[@]}"; do
  service="${IMAGES[$dockerfile]}"
  image_tag="${FULL_REGISTRY:+$FULL_REGISTRY/}${TAG}/${service}:${VERSION}"
  
  echo "🔨 Building ${image_tag}..."
  docker buildx build \
    --platform "${PLATFORMS}" \
    -f "${dockerfile}" \
    -t "${image_tag}" \
    --metadata-binaries=false \
    --provenance=false \
    $( [[ "$PUSH" == "true" ]] && echo "--push" || echo "--load" ) \
    .

  if [[ "$PUSH" == "true" && -z "$FULL_REGISTRY" ]]; then
    echo "ℹ️ No registry - image loaded locally (docker images | grep ${TAG})"
  fi
done

# ECR login if push + AWS vars present
if [[ "$PUSH" == "true" && -n "$AWS_ACCOUNT_ID" && -n "$AWS_REGION" ]]; then
  echo "🔐 ECR login..."
  aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
  echo "✅ ECR authenticated"
fi

echo "✅ All K8s images built! 🎉"
echo "Local verify: docker images | grep '${TAG}'"
echo "Push: ./$(basename $0) --push --registry ddos-system"
echo "Helm deploy next: ./scripts/deploy-cloud.sh"
