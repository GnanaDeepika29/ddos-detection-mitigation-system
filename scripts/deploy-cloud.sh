#!/bin/bash
# Production cloud deployment script
set -euo pipefail

echo "🚀 DDoS System Cloud Deploy (AWS EKS + Helm)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Config
TF_DIR="deployment/terraform"
HELM_DIR="deployment/helm/ddos-system"
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
IMAGE_TAG="v$(date +%Y%m%d)-$(git rev-parse --short HEAD)"

# ECR Repo name prefix
ECR_REPO="ddos-system"

log_info() { echo -e "${GREEN}[INFO]${NC} $*" ; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*" ; }
log_err() { echo -e "${RED}[ERROR]${NC} $*" >&2 ; }

# Terraform Infra
log_info "1. Terraform Apply (EKS/MSK/ECR)"
cd "$TF_DIR"
terraform init -upgrade
terraform validate
terraform plan -var="global_aws_account_id=$AWS_ACCOUNT" -out=tfplan
terraform apply tfplan

# Get outputs
KUBECONFIG=$(terraform output -raw kubeconfig)
MSK_BROKERS=$(terraform output -raw msk_bootstrap_brokers_tls)
ECR_URL=$(terraform output -raw ecr_repository_url)
EKS_CLUSTER_NAME=$(terraform output -raw eks_cluster_name)

export KUBECONFIG KUBE_CONFIG_PATH="$KUBECONFIG"
aws eks update-kubeconfig --region "$AWS_REGION" --name "$EKS_CLUSTER_NAME"

log_info "Terraform complete ✅ EKS: $EKS_CLUSTER_NAME MSK: $MSK_BROKERS ECR: $ECR_URL"

# Docker Build & ECR Push
log_info "2. Docker Build & Push (4 services)"
cd ../..

for service in api collector detector mitigation ; do
  docker build -t "$ECR_URL/$service:$IMAGE_TAG" \
    --build-arg BUILDPLATFORM=linux/amd64 \
    -f "Dockerfile.$service" .
  docker push "$ECR_URL/$service:$IMAGE_TAG"
  docker tag "$ECR_URL/$service:$IMAGE_TAG" "$ECR_URL/$service:latest"
  docker push "$ECR_URL/$service:latest"
  log_info "Pushed $service:$IMAGE_TAG"
done

# Helm Deploy
log_info "3. Helm Deploy (ddos-system)"
cd "$HELM_DIR"

helm repo add external-secrets https://charts.external-secrets.io
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm upgrade --install --create-namespace --namespace ddos-system \
  --set global.ecrRepository="$ECR_URL" \
  --set global.imageTag="$IMAGE_TAG" \
  --set global.aws.accountId="$AWS_ACCOUNT" \
  --set global.aws.region="$AWS_REGION" \
  --set kafka.bootstrapServers="$MSK_BROKERS" \
  --wait --timeout 10m \
  ddos-system .

helm status ddos-system -n ddos-system

log_info "🚀 Deploy COMPLETE!"
log_info "API: kubectl port-forward svc/ddos-api 8000:80 -n ddos-system"
log_info "Grafana: kubectl port-forward svc/grafana 3000:80 -n monitoring"
log_info "Dashboard: http://localhost:3000 (admin/admin)"
log_info "Terraform destroy: cd $TF_DIR && terraform destroy -auto-approve"

kubectl get all -n ddos-system
