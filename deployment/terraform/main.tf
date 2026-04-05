# ============================================
# Terraform Configuration for DDoS Protection System
# ============================================

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.10"
    }
  }

  backend "s3" {
    bucket         = "ddos-system-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Project     = "ddos-protection-system"
      ManagedBy   = "terraform"
    }
  }
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

# ============================================
# Variables
# ============================================
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "ddos-protection-cluster"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

# Restrict to known egress CIDRs (CI/CD egress IPs, VPN, bastion).
variable "allowed_mgmt_cidrs" {
  description = "CIDRs allowed to reach the EKS public endpoint (VPN, CI/CD egress IPs)"
  type        = list(string)
  default     = []  # override in tfvars — leaving empty disables public access effectively
}

# ============================================
# VPC Module
# ============================================
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.cluster_name}-vpc"
  cidr = var.vpc_cidr

  azs             = var.availability_zones
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway   = true
  enable_vpn_gateway   = false
  single_nat_gateway   = false
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}

# ============================================
# EKS Cluster Module
# ============================================
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.28"

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  # Any credential compromise allows direct API server access from the internet.
  # Restrict to known management CIDRs (VPN egress, CI/CD runners).
  cluster_endpoint_public_access_cidrs = var.allowed_mgmt_cidrs

  cluster_addons = {
    coredns    = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni    = { most_recent = true }
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    main = {
      name           = "main-node-group"
      instance_types = ["m5.large", "m5.xlarge"]
      min_size       = 3
      max_size       = 10
      desired_size   = 3
      capacity_type  = "ON_DEMAND"
      tags = {
        Environment = var.environment
        NodeGroup   = "main"
      }
    }

    network = {
      name           = "network-node-group"
      instance_types = ["c5.large", "c5.xlarge"]
      min_size       = 2
      max_size       = 5
      desired_size   = 2
      capacity_type  = "ON_DEMAND"
      taints = [
        { key = "node-type", value = "network", effect = "NO_SCHEDULE" }
      ]
      tags = {
        Environment = var.environment
        NodeGroup   = "network"
      }
    }

    mitigation = {
      name           = "mitigation-node-group"
      instance_types = ["c5.xlarge", "c5.2xlarge"]
      min_size       = 2
      max_size       = 4
      desired_size   = 2
      capacity_type  = "ON_DEMAND"
      taints = [
        { key = "node-type", value = "mitigation", effect = "NO_SCHEDULE" }
      ]
      tags = {
        Environment = var.environment
        NodeGroup   = "mitigation"
      }
    }
  }

  tags = { Environment = var.environment }
}

# ============================================
# MSK (Managed Kafka) Module
# ============================================
module "msk" {
  source  = "terraform-aws-modules/msk/aws"
  version = "~> 2.0"

  cluster_name              = "ddos-msk-cluster"
  kafka_version             = "2.8.1"
  number_of_broker_nodes    = 3
  broker_node_instance_type = "kafka.m5.large"
  broker_az_distribution    = "DEFAULT"

  client_authentication = {
    unauthenticated = false
    sasl            = { iam = true }
  }

  encryption_in_transit = {
    client_broker = "TLS"
    in_cluster    = true
  }

  storage_info = {
    ebs_storage_info = { volume_size = 100 }
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  security_group_rules = {
    ingress_internal = {
      description = "Internal access"
      cidr_blocks = [module.vpc.vpc_cidr_block]
    }
  }

  tags = { Environment = var.environment }
}

# ============================================
# ElastiCache for Redis Module
# ============================================
module "redis" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "~> 3.0"

  cluster_id           = "ddos-redis-cluster"
  engine               = "redis"
  engine_version       = "7.0"
  node_type            = "cache.t3.medium"
  num_cache_nodes      = 3
  port                 = 6379
  subnet_ids           = module.vpc.private_subnets
  security_group_ids   = [aws_security_group.redis.id]
  parameter_group_name = "default.redis7"

  tags = { Environment = var.environment }
}

# ============================================
# Security Groups
# ============================================
resource "aws_security_group" "redis" {
  name        = "ddos-redis-sg"
  description = "Security group for Redis cluster"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Redis from EKS"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [module.eks.cluster_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ddos-redis-sg" }
}

# ============================================
# RDS PostgreSQL
# ============================================
module "postgresql" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"

  identifier             = "ddos-postgres-db"
  engine                 = "postgres"
  engine_version         = "15.3"
  instance_class         = "db.t3.large"
  allocated_storage      = 100
  storage_encrypted      = true
  storage_type           = "gp3"
  db_name                = "ddos_production"
  username               = "ddos_user"
  password               = random_password.db_password.result
  vpc_security_group_ids = [aws_security_group.postgres.id]
  backup_retention_period = 30
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  enabled_cloudwatch_logs_exports = ["postgresql"]
  deletion_protection     = true

  tags = { Environment = var.environment }
}

resource "random_password" "db_password" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Store the DB password in Secrets Manager rather than only in Terraform state.
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "ddos-system/postgres/password"
  description             = "DDoS system PostgreSQL master password"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}

resource "aws_security_group" "postgres" {
  name        = "ddos-postgres-sg"
  description = "Security group for PostgreSQL"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "PostgreSQL from EKS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.cluster_security_group_id]
  }

  tags = { Name = "ddos-postgres-sg" }
}

# ============================================
# S3 Bucket for Model Storage
# ============================================
resource "aws_s3_bucket" "models" {
  bucket = "ddos-models-${data.aws_caller_identity.current.account_id}"
  tags = {
    Name        = "DDoS Models Bucket"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "models" {
  bucket = aws_s3_bucket.models.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "models" {
  bucket = aws_s3_bucket.models.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ============================================
# IAM / IRSA
# ============================================
resource "aws_iam_role" "detector_role" {
  name = "ddos-detector-sa-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = module.eks.oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub" = "system:serviceaccount:ddos-system:ddos-detector-sa"
        }
      }
    }]
  })
}

resource "aws_iam_policy" "detector_policy" {
  name        = "ddos-detector-policy"
  description = "Policy for DDoS detector service account"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kafka:DescribeCluster", "kafka:GetBootstrapBrokers",
          "kafka:ListTopics", "kafka:DescribeTopic",
          "kafka:ListConsumerGroups", "kafka:DescribeConsumerGroup"
        ]
        Resource = module.msk.cluster_arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.models.arn, "${aws_s3_bucket.models.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "detector" {
  role       = aws_iam_role.detector_role.name
  policy_arn = aws_iam_policy.detector_policy.arn
}

# ============================================
# ECR Repositories
# ============================================
resource "aws_ecr_repository" "collector" {
  name                 = "ddos-collector"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_ecr_repository" "detector" {
  name                 = "ddos-detector"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_ecr_repository" "api" {
  name                 = "ddos-api"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_ecr_repository" "mitigation" {
  name                 = "ddos-mitigation"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

# ============================================
# Helm Deployments
# ============================================
resource "helm_release" "kafka" {
  name       = "kafka"
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "kafka"
  version    = "23.0.0"
  namespace  = "ddos-system"

  values = [<<-EOT
    replicaCount: 3
    persistence:
      enabled: true
      size: 50Gi
    resources:
      requests:
        memory: "2Gi"
        cpu: "500m"
      limits:
        memory: "4Gi"
        cpu: "2000m"
    auth:
      clientProtocol: tls
    zookeeper:
      replicaCount: 3
      persistence:
        enabled: true
        size: 10Gi
  EOT
  ]

  depends_on = [module.eks]
}

resource "kubernetes_secret" "grafana_admin" {
  metadata {
    name      = "grafana-admin-secret"
    namespace = "monitoring"
  }
  data = {
    admin-user     = "admin"
    admin-password = random_password.grafana_password.result
  }
  depends_on = [module.eks]
}

resource "helm_release" "prometheus" {
  name       = "prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = "45.0.0"
  namespace  = "monitoring"

  values = [<<-EOT
    prometheus:
      prometheusSpec:
        retention: 15d
        retentionSize: 50GB
    grafana:
      enabled: true
      admin:
        existingSecret: grafana-admin-secret
        userKey: admin-user
        passwordKey: admin-password
      persistence:
        enabled: true
        size: 10Gi
  EOT
  ]

  depends_on = [module.eks, kubernetes_secret.grafana_admin]
}

resource "random_password" "grafana_password" {
  length           = 20
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# ============================================
# Data Sources & Outputs
# ============================================
data "aws_caller_identity" "current" {}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "kafka_bootstrap_servers" {
  description = "MSK bootstrap servers"
  value       = module.msk.bootstrap_brokers_tls
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis cluster endpoint"
  value       = module.redis.primary_endpoint_address
}

output "postgres_endpoint" {
  description = "PostgreSQL endpoint"
  value       = module.postgresql.db_instance_address
}

output "ecr_repositories" {
  description = "ECR repository URLs"
  value = {
    collector  = aws_ecr_repository.collector.repository_url
    detector   = aws_ecr_repository.detector.repository_url
    api        = aws_ecr_repository.api.repository_url
    mitigation = aws_ecr_repository.mitigation.repository_url
  }
}
