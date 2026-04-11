#!/bin/bash
# Production Deploy Script for AWS EKS

set -e

echo "1. Fix cache"
powershell -ExecutionPolicy Bypass -File scripts/clean_cache.ps1

echo "2. Build images"
./scripts/build_k8s_images.sh

echo "3. Create EKS cluster (if not exists)"
eksctl create cluster --name ddos-cluster --region us-east-1 --nodes 3

echo "4. Install Helm infra"
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install kafka bitnami/kafka --namespace ddos-system
helm install redis bitnami/redis --namespace ddos-system
helm install prometheus-grafana prometheus-community/kube-prometheus-stack --namespace ddos-system

echo "5. Deploy app"
kubectl apply -k deployment/kubernetes/

echo "6. Load model"
kubectl cp models/xgboost_cic.pkl ddos-system/ddos-models-pvc:/models/

echo "7. Port-forward API/Grafana"
kubectl port-forward svc/ddos-api-service 8000:80 &
kubectl port-forward svc/grafana 3000:3000 &

echo "Deploy complete! API: localhost:8000/health, Grafana: localhost:3000"
