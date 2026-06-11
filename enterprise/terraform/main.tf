# Root module — composes the per-concern modules under ./modules.
#
# Phase 0 establishes the provider, default tags, and shared locals. Module
# calls are added as each module is implemented (see enterprise/PLAN.md §6):
#   Phase 1 — network, storage, database, cache
#   Phase 2 — batch
#   Phase 3 — backend, frontend, auth
#
# Wiring is intentionally absent here until the referenced modules contain
# resources, so `terraform validate` passes on the Phase 0 skeleton.

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        Project     = "wairz"
        Environment = var.environment
        ManagedBy   = "terraform"
      },
      var.tags,
    )
  }
}

locals {
  # Canonical name prefix for all resources, e.g. "wairz-prod".
  name = "${var.name_prefix}-${var.environment}"
}

# ---------------------------------------------------------------------------
# Module wiring. Phase 1 modules (network, storage, database, cache) are live;
# later-phase modules stay commented until they land (PLAN.md §6).
# ---------------------------------------------------------------------------

module "network" {
  source             = "./modules/network"
  name               = local.name
  aws_region         = var.aws_region
  vpc_cidr           = var.vpc_cidr
  create_nat_gateway = var.create_nat_gateway
}

module "storage" {
  source             = "./modules/storage"
  name               = local.name
  vpc_id             = module.network.vpc_id
  vpc_cidr           = module.network.vpc_cidr
  private_subnet_ids = module.network.private_subnet_ids
}

module "database" {
  source             = "./modules/database"
  name               = local.name
  vpc_id             = module.network.vpc_id
  vpc_cidr           = module.network.vpc_cidr
  private_subnet_ids = module.network.private_subnet_ids
  min_capacity       = var.aurora_min_capacity
  max_capacity       = var.aurora_max_capacity
}

module "cache" {
  source             = "./modules/cache"
  name               = local.name
  vpc_id             = module.network.vpc_id
  vpc_cidr           = module.network.vpc_cidr
  private_subnet_ids = module.network.private_subnet_ids
  node_type          = var.redis_node_type
}

module "batch" {
  source     = "./modules/batch"
  name       = local.name
  aws_region = var.aws_region
  vpc_id     = module.network.vpc_id
  image_tag  = local.image_tag

  private_subnet_ids = module.network.private_subnet_ids
  max_vcpus          = var.batch_max_vcpus
  use_spot           = var.batch_use_spot

  efs_id                              = module.storage.efs_id
  efs_firmware_access_point_id        = module.storage.efs_firmware_access_point_id
  efs_ghidra_projects_access_point_id = module.storage.efs_ghidra_projects_access_point_id
  redis_url                           = module.cache.redis_url
  database_url_secret_arn             = module.database.database_url_secret_arn
  secret_arns                         = [module.database.database_url_secret_arn]
}

module "backend" {
  source     = "./modules/backend"
  name       = local.name
  aws_region = var.aws_region
  vpc_id     = module.network.vpc_id
  image_tag  = local.image_tag

  public_subnet_ids  = module.network.public_subnet_ids
  private_subnet_ids = module.network.private_subnet_ids

  efs_id                              = module.storage.efs_id
  efs_firmware_access_point_id        = module.storage.efs_firmware_access_point_id
  efs_ghidra_projects_access_point_id = module.storage.efs_ghidra_projects_access_point_id
  redis_url                           = module.cache.redis_url
  database_url_secret_arn             = module.database.database_url_secret_arn
  secret_arns                         = [module.database.database_url_secret_arn]

  batch_job_queue           = module.batch.job_queue_arn
  batch_job_definition_arn  = module.batch.import_job_definition_arn
  batch_job_definition_name = module.batch.import_job_definition_name

  max_upload_size_mb          = var.max_upload_size_mb
  certificate_arn             = var.alb_certificate_arn
  batch_max_jobs_per_firmware = var.batch_max_jobs_per_firmware
}

module "frontend" {
  source = "./modules/frontend"
  name   = local.name

  spa_bucket                      = module.storage.spa_bucket
  spa_bucket_arn                  = module.storage.spa_bucket_arn
  spa_bucket_regional_domain_name = module.storage.spa_bucket_regional_domain_name
  alb_dns_name                    = module.backend.alb_dns_name
}

module "auth" {
  source        = "./modules/auth"
  name          = local.name
  domain_suffix = var.cognito_domain_suffix
  callback_urls = ["https://${module.frontend.cloudfront_domain}/oauth2/idpresponse"]
  logout_urls   = ["https://${module.frontend.cloudfront_domain}/"]
}
