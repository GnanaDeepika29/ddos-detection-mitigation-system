# ============================================
# Azure Deployment - Production Ready
# ============================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
}

# Provider Configuration
provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}

# Variables
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

variable "cluster_name" {
  description = "Cluster name"
  type        = string
  default     = "ddos-protection"
}

# Resource Group
resource "azurerm_resource_group" "ddos" {
  name     = "${var.cluster_name}-rg"
  location = var.location
}

# Virtual Network
resource "azurerm_virtual_network" "ddos_vnet" {
  name                = "${var.cluster_name}-vnet"
  address_space       = ["10.0.0.0/16"]
  location          = azurerm_resource_group.ddos.location
  resource_group_name = azurerm_resource_group.ddos.name
}

resource "azurerm_subnet" "aks_subnet" {
  name                 = "${var.cluster_name}-aks-subnet"
  virtual_network_name = azurerm_virtual_network.ddos_vnet.name
  address_prefixes   = ["10.0.1.0/24"]
  resource_group_name = azurerm_resource_group.ddos.name
}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "ddos_aks" {
  name                = var.cluster_name
  location          = azurerm_resource_group.ddos.location
  resource_group_name = azurerm_resource_group.ddos.name
  dns_prefix          = var.cluster_name

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size   = "Standard_D2s_v3"
    vnet_subnet_id = azurerm_subnet.aks_subnet.id
  }

  identity {
    type = "SystemAssigned"
  }
}

# Azure Cache for Redis
resource "azurerm_redis_cache" "ddos_redis" {
  name                = "${var.cluster_name}-redis"
  location          = azurerm_resource_group.ddos.location
  resource_group_name = azurerm_resource_group.ddos.name
  capacity          = 2
  family           = "P"
  sku_name         = "Standard"
}

# Event Hubs (Kafka replacement)
resource "azurerm_eventhub_namespace" "ddos_ns" {
  name                = "${var.cluster_name}-ns"
  location          = azurerm_resource_group.ddos.location
  resource_group_name = azurerm_resource_group.ddos.name
  sku               = "Standard"
  capacity          = 1
}

resource "azurerm_eventhub" "flows" {
  name                = "network-flows"
  namespace_name     = azurerm_eventhub_namespace.ddos_ns.name
  resource_group_name = azurerm_resource_group.ddos.name
  partition_count   = 4
  message_retention = 7
}

resource "azurerm_eventhub" "alerts" {
  name                = "ddos-alerts"
  namespace_name     = azurerm_eventhub_namespace.ddos_ns.name
  resource_group_name = azurerm_resource_group.ddos.name
  partition_count   = 4
  message_retention = 7
}

# Container Registry
resource "azurerm_container_registry" "ddos_acr" {
  name                = "${var.cluster_name}acr"
  location          = azurerm_resource_group.ddos.location
  resource_group_name = azurerm_resource_group.ddos.name
  sku               = "Standard"
  admin_enabled    = true
}

# Outputs
output "aks_kubeconfig" {
  value     = azurerm_kubernetes_cluster.ddos_aks.kube_config.0.raw_config
  sensitive = true
}

output "aks_endpoint" {
  value = azurerm_kubernetes_cluster.ddos_aks.fqdn
}

output "redis_hostname" {
  value = azurerm_redis_cache.ddos_redis.hostname
}

output "redis_port" {
  value = azurerm_redis_cache.ddos_redis.port
}

output "eventhub_namespace" {
  value = azurerm_eventhub_namespace.ddos_ns.name
}

output "acr_login_server" {
  value = azurerm_container_registry.ddos_acr.login_server
}

output "resource_group_name" {
  value = azurerm_resource_group.ddos.name
}