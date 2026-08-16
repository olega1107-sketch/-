resource "digitalocean_vpc" "pilot" {
  name     = "${local.name_prefix}-vpc"
  region   = var.region
  ip_range = var.vpc_ip_range

  lifecycle {
    prevent_destroy = true
  }
}
