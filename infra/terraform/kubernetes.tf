resource "digitalocean_kubernetes_cluster" "pilot" {
  name     = "${local.name_prefix}-doks"
  region   = var.region
  version  = var.kubernetes_version != "" ? var.kubernetes_version : data.digitalocean_kubernetes_versions.current.latest_version
  vpc_uuid = digitalocean_vpc.pilot.id
  tags     = local.common_tags

  auto_upgrade         = true
  surge_upgrade        = true
  registry_integration = true

  node_pool {
    name       = "${local.name_prefix}-workers"
    size       = var.kubernetes_node_size
    node_count = var.kubernetes_node_count
    auto_scale = true
    min_nodes  = var.kubernetes_min_nodes
    max_nodes  = var.kubernetes_max_nodes
    tags       = local.common_tags
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    digitalocean_container_registry.pilot
  ]
}
