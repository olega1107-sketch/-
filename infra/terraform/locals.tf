locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = concat(
    [
      "project:${var.project_name}",
      "environment:${var.environment}",
      "managed-by:terraform"
    ],
    var.extra_tags
  )
}
