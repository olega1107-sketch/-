resource "digitalocean_database_cluster" "postgres" {
  name                 = "${local.name_prefix}-postgres"
  engine               = "pg"
  version              = var.postgres_version
  size                 = var.postgres_size
  region               = var.region
  node_count           = var.postgres_node_count
  private_network_uuid = digitalocean_vpc.pilot.id
  tags                 = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "digitalocean_database_db" "app" {
  cluster_id = digitalocean_database_cluster.postgres.id
  name       = var.postgres_database_name
}

resource "digitalocean_database_user" "app" {
  cluster_id = digitalocean_database_cluster.postgres.id
  name       = var.postgres_user_name

  lifecycle {
    ignore_changes = [settings]
  }
}

resource "digitalocean_database_firewall" "postgres" {
  cluster_id = digitalocean_database_cluster.postgres.id

  rule {
    type  = "k8s"
    value = digitalocean_kubernetes_cluster.pilot.id
  }

  dynamic "rule" {
    for_each = toset(var.postgres_firewall_extra_ips)

    content {
      type  = "ip_addr"
      value = rule.value
    }
  }
}
