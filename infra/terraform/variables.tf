variable "project_name" {
  description = "Short lowercase project name used in DigitalOcean resource names."
  type        = string
  default     = "dirizher"
}

variable "environment" {
  description = "Environment name."
  type        = string
  default     = "pilot"
}

variable "region" {
  description = "DigitalOcean region slug."
  type        = string
  default     = "fra1"
}

variable "vpc_ip_range" {
  description = "Private CIDR range for the pilot VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "container_registry_subscription_tier_slug" {
  description = "DigitalOcean Container Registry subscription tier."
  type        = string
  default     = "basic"
}

variable "kubernetes_version" {
  description = "DOKS Kubernetes version slug. Leave empty to use DigitalOcean's current latest version."
  type        = string
  default     = ""
}

variable "kubernetes_node_size" {
  description = "DOKS worker node size slug."
  type        = string
  default     = "s-2vcpu-4gb"
}

variable "kubernetes_node_count" {
  description = "Initial number of DOKS worker nodes."
  type        = number
  default     = 2
}

variable "kubernetes_min_nodes" {
  description = "Minimum autoscaling worker node count."
  type        = number
  default     = 2
}

variable "kubernetes_max_nodes" {
  description = "Maximum autoscaling worker node count."
  type        = number
  default     = 4
}

variable "internal_inference_node_pool_enabled" {
  description = "Create the dedicated DOKS node pool for the in-cluster internal inference workload."
  type        = bool
  default     = false
}

variable "internal_inference_node_size" {
  description = "DOKS Droplet size for the dedicated internal inference node pool."
  type        = string
  default     = "s-4vcpu-16gb-amd"
}

variable "internal_inference_node_count" {
  description = "Static node count for the dedicated internal inference node pool."
  type        = number
  default     = 1
}

variable "postgres_version" {
  description = "Managed PostgreSQL major version."
  type        = string
  default     = "16"
}

variable "postgres_size" {
  description = "Managed PostgreSQL node size slug."
  type        = string
  default     = "db-s-1vcpu-1gb"
}

variable "postgres_node_count" {
  description = "Managed PostgreSQL node count. Use 1 for pilot cost control; increase for higher availability."
  type        = number
  default     = 1
}

variable "postgres_database_name" {
  description = "Initial application database name."
  type        = string
  default     = "dirizher"
}

variable "postgres_user_name" {
  description = "Initial application database user name."
  type        = string
  default     = "dirizher_app"
}

variable "postgres_firewall_extra_ips" {
  description = "Additional approved IPv4 addresses allowed to reach the managed PostgreSQL cluster."
  type        = list(string)
  default     = []
}

variable "domain_name" {
  description = "Pilot domain, for documentation and future DNS/TLS stages."
  type        = string
  default     = ""
}

variable "extra_tags" {
  description = "Additional DigitalOcean tags."
  type        = list(string)
  default     = []
}
