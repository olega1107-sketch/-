resource "digitalocean_container_registry" "pilot" {
  name                   = replace("${local.name_prefix}-registry", "-", "")
  subscription_tier_slug = var.container_registry_subscription_tier_slug
  region                 = var.region

  lifecycle {
    prevent_destroy = true
  }
}
