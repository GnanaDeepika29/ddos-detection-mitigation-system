# Cloud Deployment Guide - Step by Step

## Prerequisites (All Clouds)
```bash
# Install Terraform
brew install terraform              # macOS
# or: wget https://releases.hashicorp.com/terraform/1.5.0/terraform_1.5.0_linux_amd64.zip

# Verify
terraform version
```

---

## AWS Deployment

### Step 1: Configure AWS CLI
```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o /tmp/AWSCLV2.pkg
sudo installer -pkg /tmp/AWSCLV2.pkg -target /

# Configure
aws configure
aws configure set region us-east-1

# Verify
aws sts get-caller-identity
```

### Step 2: Create terraform.tfvars
```bash
cd deployment/terraform

cat > terraform.tfvars << 'EOF'
cloud_provider = "aws"
environment = "production"
cluster_name = "ddos-protection"
aws_region = "us-east-1"
vpc_cidr = "10.0.0.0/16"
eks_version = "1.29"
msk_kafka_version = "3.5.1"
eks_node_instance_types = ["m5.large"]
eks_node_min_size = 2
eks_node_max_size = 10
project_name = "ddos-protection"
EOF
```

### Step 3: Deploy
```bash
# Initialize
terraform init

# Plan
terraform plan -var-file=terraform.tfvars

# Apply (takes 15-20 minutes)
terraform apply -var-file=terraform.tfvars
```

### Step 4: Get Outputs
```bash
# EKS endpoint
terraform output eks_cluster_endpoint

# Kafka bootstrap
terraform output msk_bootstrap_tls

# Redis endpoint
terraform output redis_endpoint
```

### Step 5: Configure Kubectl
```bash
# Update kubeconfig
aws eks update-kubeconfig --name ddos-protection

# Test
kubectl get nodes
kubectl get pods -n ddos-system
```

---

## GCP Deployment

### Step 1: Configure Google Cloud
```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Authenticate
gcloud auth login
gcloud auth application-default login

# Set project
gcloud projects create ddos-protection --name="DDoS Protection"
gcloud config set project ddos-protection

# Enable APIs
gcloud services enable container.googleapis.com compute.googleapis.com sqladmin.googleapis.com pubsub.googleapis.com
```

### Step 2: Create terraform.tfvars
```bash
cd deployment/terraform

cat > terraform.tfvars << 'EOF'
cloud_provider = "gcp"
gcp_project_id = "ddos-protection"
gcp_region = "us-central1"
environment = "production"
cluster_name = "ddos-protection"
EOF
```

### Step 3: Deploy
```bash
terraform init
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

### Step 4: Get Outputs
```bash
terraform output gke_endpoint
terraform output redis_host
terraform output pubsub_endpoint
```

### Step 5: Configure Kubectl
```bash
gcloud container clusters get-credentials ddos-cluster --region us-central1

kubectl get nodes
```

---

## Azure Deployment

### Step 1: Configure Azure CLI
```bash
# Install Azure CLI
curl -L https://aka.ms/InstallAzureCLIDeb | bash

# Login
az login

# Set subscription
az account list -o table
az account set -s "YOUR_SUBSCRIPTION_ID"

# Register providers
az provider register --namespace Microsoft.ContainerService
az provider register --namespace Microsoft.Compute
az provider register --namespace Microsoft.Storage
```

### Step 2: Create terraform.tfvars
```bash
cd deployment/terraform

cat > terraform.tfvars << 'EOF'
cloud_provider = "azure"
azure_subscription_id = "YOUR_SUBSCRIPTION_ID"
azure_tenant_id = "YOUR_TENANT_ID"
azure_location = "eastus"
cluster_name = "ddos-protection"
environment = "production"
EOF
```

### Step 3: Deploy
```bash
terraform init
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

### Step 4: Get Outputs
```bash
terraform output aks_endpoint
terraform output redis_hostname
terraform output eventhub_namespace
```

### Step 5: Configure Kubectl
```bash
az aks get-credentials --resource-group ddos-protection-rg --name ddos-cluster

kubectl get nodes
```

---

## Deploy DDoS Services to Cloud K8s

### After Cloud Cluster is Ready

```bash
# Apply Kubernetes manifests
kubectl apply -f deployment/kubernetes/

# Or use Helm
helm install ddos-system deployment/helm/ddos-system/

# Check pods
kubectl get pods -n ddos-system

# Check services
kubectl get svc -n ddos-system

# View logs
kubectl logs -n ddos-system -l app=ddos-detector
```

---

## Verify Deployment

| Check | Command |
|-------|---------|
| All pods running | `kubectl get pods -n ddos-system` |
| API health | `curl http://<EXTERNAL_IP>/health` |
| Prometheus | `curl http://<PROMETHEUS_IP>:9090/-/healthy` |
| Grafana | `http://<GRAFANA_IP>:3000` |

---

## Destroy (Cleanup)

```bash
# Destroy all resources
terraform destroy -var-file=terraform.tfvars

# Or just specific resources
terraform destroy -target module.eks
terraform destroy -target module.msk
terraform destroy -target module.vpc
```

---

## Cost Estimates (Monthly)

| Cloud | Services | Estimated Cost |
|-------|----------|----------------|
| AWS | EKS (2x m5.large) + MSK + ElastiCache | $1,500-2,500 |
| GCP | GKE (3x e2-standard-4) + Cloud SQL + Pub/Sub | $1,200-2,000 |
| Azure | AKS (3x D2s_v3) + Redis + Event Hubs | $1,000-1,800 |