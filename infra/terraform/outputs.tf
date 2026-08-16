output "vpc_id" {
  description = "DigitalOcean VPC ID."
  value       = digitalocean_vpc.pilot.id
}

output "kubernetes_cluster_id" {
  description = "DOKS cluster ID."
  value       = digitalocean_kubernetes_cluster.pilot.id
}

output "kubernetes_cluster_name" {
  description = "DOKS cluster name."
  value       = digitalocean_kubernetes_cluster.pilot.name
}

output "container_registry_name" {
  description = "DigitalOcean Container Registry name."
  value       = digitalocean_container_registry.pilot.name
}

output "container_registry_endpoint" {
  description = "DigitalOcean Container Registry endpoint."
  value       = digitalocean_container_registry.pilot.endpoint
}

output "postgres_host_private" {
  description = "Private Managed PostgreSQL host."
  value       = digitalocean_database_cluster.postgres.private_host
}

output "postgres_port" {
  description = "Managed PostgreSQL port."
  value       = digitalocean_database_cluster.postgres.port
}

output "postgres_database" {
  description = "Application database name."
  value       = digitalocean_database_db.app.name
}

output "postgres_user" {
  description = "Application database user name."
  value       = digitalocean_database_user.app.name
}
