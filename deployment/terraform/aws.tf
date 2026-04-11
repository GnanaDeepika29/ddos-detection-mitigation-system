# ============================================
# AWS Deployment - Production Ready
# ============================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# Provider Configuration
provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "ddos-protection-system"
      ManagedBy   = "terraform"
      Environment = "production"
    }
  }
}

# Random ID for uniqueness
resource "random_id" "suffix" {
  byte_length = 8
}

# Variables
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "Cluster name"
  type        = string
  default     = "ddos-protection"
}

# VPC Module
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.cluster_name}-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway    = false
  enable_dns_hostnames  = true
  enable_dns_support    = true

  tags = {
    Name = "${var.cluster_name}-vpc"
  }
}

# EKS Cluster
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.21"

  cluster_name    = var.cluster_name
  cluster_version = "1.29"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    ddos = {
      name           = "ddos-nodes"
      instance_types = ["m5.large"]
      min_size       = 2
      max_size       = 10
      desired_size   = 2

      labels = {
        NodeGroup = "ddos"
      }
    }
  }

  tags = {
    Name = "${var.cluster_name}-eks"
  }
}

# MSK Kafka
module "msk" {
  source  = "terraform-aws-modules/msk/aws"
  version = "~> 1.1"

  cluster_name               = "${var.cluster_name}-kafka"
  kafka_version            = "3.5.1"
  number_of_broker_nodes   = 3

  broker_node_group_info {
    instance_type  = "kafka.m5.large"
    client_subnets = module.vpc.private_subnets
    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
  }

  client_authentication {
    sasl {
      iam { enabled = true }
    }
  }

  encryption_info {
    encryption_in_transit {
      in_cluster = true
    }
  }

  vpc_id = module.vpc.vpc_id

  tags = {
    Name = "${var.cluster_name}-msk"
  }
}

# ElastiCache Redis
module "redis" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "~> 1.3"

  cluster_id      = "${var.cluster_name}-redis"
  engine        = "redis"
  engine_version = "7.1"
  node_type     = "cache.t4g.medium"
  num_cache_nodes = 3
  port         = 6379

  subnet_ids = module.vpc.private_subnets

  tags = {
    Name = "${var.cluster_name}-redis"
  }
}

# ECR Repositories
resource "aws_ecr_repository" "collector" {
  name = "ddos-collector"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "detector" {
  name = "ddos-detector"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "mitigation" {
  name = "ddos-mitigation"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "api" {
  name = "ddos-api"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

# Outputs
output "eks_endpoint" {
  description = "EKS Cluster Endpoint"
  value      = module.eks.cluster_endpoint
}

output "eks_cluster_name" {
  description = "EKS Cluster Name"
  value      = module.eks.cluster_name
}

output "kafka_bootstrap" {
  description = "MSK Kafka Bootstrap Servers"
  value      = module.msk.bootstrap_brokers_tls
  sensitive  = true
}

output "redis_endpoint" {
  description = "Redis ElastiCache Endpoint"
  value      = module.redis.redis_endpoint
}

output "ecr_urls" {
  description = "ECR Repository URLs"
  value = {
    collector  = aws_ecr_repository.collector.repository_url
    detector  = aws_ecr_repository.detector.repository_url
    mitigation = aws_ecr_repository.mitigation.repository_url
    api       = aws_ecr_repository.api.repository_url
  }
}

output "vpc_id" {
  description = "VPC ID"
  value      = module.vpc.vpc_id
}