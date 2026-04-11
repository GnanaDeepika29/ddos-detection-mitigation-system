# ============================================
# Terraform Variables - All Cloud
# ============================================

# AWS Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "Cluster/Project name"
  type        = string
  default     = "ddos-protection"
}

variable "eks_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.29"
}

variable "node_instance_type" {
  description = "EC2/VM instance type"
  type        = string
  default     = "m5.large"
}

variable "node_min_size" {
  description = "Minimum nodes"
  type        = number
  default     = 2
}

variable "node_max_size" {
  description = "Maximum nodes"
  type        = number
  default     = 10
}

# GCP Variables
variable "gcp_project_id" {
  description = "GCP Project ID"
  type        = string
  default     = "ddos-protection-project"
}

variable "gcp_region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

# Azure Variables
variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
  default     = ""
}

variable "tenant_id" {
  description = "Azure Tenant ID"
  type        = string
  default     = ""
}

variable "location" {
  description = "Azure Location"
  type        = string
  default     = "eastus"
}

# Common Outputs
output "all_deploy_commands" {
  value = <<COMMANDS

# =====================================================
# AWS Deployment Commands
# =====================================================
cd deployment/terraform
terraform init
terraform plan -var-file=aws.tfvars
terraform apply -var-file=aws.tfvars

# Get kubeconfig
aws eks update-kubeconfig --name ddos-protection

# =====================================================
# GCP Deployment Commands  
# =====================================================
gcloud auth login
gcloud projects create ddos-protection-project
gcloud services enable container.googleapis.com compute.googleapis.com
cd deployment/terraform
terraform init
terraform plan -var-file=gcp.tfvars
terraform apply -var-file=gcp.tfvars

# Get kubeconfig
gcloud container clusters get-credentials ddos-protection --region us-central1

# =====================================================
# Azure Deployment Commands
# =====================================================
az login
az account set -s YOUR_SUBSCRIPTION_ID
cd deployment/terraform
terraform init
terraform plan -var-file=azure.tfvars
terraform apply -var-file=azure.tfvars

# Get kubeconfig
az aks get-credentials --resource-group ddos-protection-rg --name ddos-protection

COMMANDS
}