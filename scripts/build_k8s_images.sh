#!/bin/bash
set -euo pipefail

# Build multi-platform K8s Docker images for DDoS system
# Usage: ./scripts/build_k8s_images.sh [--push]

PUSH=false
if [[ "${1:-}" == "--push" ]]; then
  PUSH=true
  shift
fi

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

TAG="${TAG:-ddos-system}"
VERSION="${VERSION:-$(git rev-parse --short HEAD)}"
PLATFORMS="linux/amd64,linux/arm64"

echo "Building ${TAG}/*:${VERSION} for ${PLATFORMS}..."
echo "Push: ${PUSH}"

# Setup buildx
docker buildx create --use --name ddos-builder || true
docker buildx inspect --bootstrap

IMAGES=(
  "Dockerfile.api:${TAG}/api:${VERSION}"
  "Dockerfile.collector:${TAG}/collector:${VERSION}"
  "Dockerfile.detector:${TAG}/detector:${VERSION}"
  "Dockerfile.mitigation:${TAG}/mitigation:${VERSION}"
  "Dockerfile.simulator:${TAG}/simulator:${VERSION}"
)

for df in "${IMAGES[@]}"; do
  dockerfile=$(echo $df | cut -d: -f1)
  image=$(echo $df | cut -d: -f2-)
  echo "Building $image..."
  docker buildx build \
    --platform ${PLATFORMS} \
    -f ${dockerfile} \
    -t ${image} \
# --load for local (${LOAD:-false} ? '--push' : '--load')
  if [[ "$PUSH" == true ]]; then
    docker push ${image}
  fi
done

echo "✅ Images built successfully!"
echo "Local: docker images | grep ${TAG}"
echo "Push next: ./$(basename $0) --push"

