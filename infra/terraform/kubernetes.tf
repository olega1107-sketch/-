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

resource "digitalocean_kubernetes_node_pool" "internal_inference" {
  count = var.internal_inference_node_pool_enabled ? 1 : 0

  cluster_id = digitalocean_kubernetes_cluster.pilot.id
  name       = "${local.name_prefix}-inference"
  size       = var.internal_inference_node_size
  node_count = var.internal_inference_node_count
  tags       = concat(local.common_tags, ["dirizhor-internal-inference"])
  labels = {
    "dirizhor.io/workload" = "internal-inference"
  }

  taint {
    key    = "dirizhor.io/workload"
    value  = "internal-inference"
    effect = "NoSchedule"
  }
}
