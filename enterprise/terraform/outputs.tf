# Root outputs. Populated as modules land (see PLAN.md §6).

# --- Phase 1: state backbone ------------------------------------------------
output "vpc_id" {
  description = "VPC id."
  value       = module.network.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet ids (EFS/DB/cache/Batch live here)."
  value       = module.network.private_subnet_ids
}

output "efs_id" {
  description = "Shared EFS filesystem id."
  value       = module.storage.efs_id
}

output "database_url_secret_arn" {
  description = "Secrets Manager ARN holding the asyncpg DATABASE_URL."
  value       = module.database.database_url_secret_arn
}

output "redis_url" {
  description = "Redis URL for the backend REDIS_URL setting."
  value       = module.cache.redis_url
}

output "spa_bucket" {
  description = "S3 bucket serving the SPA (CloudFront origin, Phase 3)."
  value       = module.storage.spa_bucket
}

# --- Later phases (uncomment as modules land) -------------------------------

# output "app_url" {
#   description = "CloudFront URL serving the Wairz SPA."
#   value       = module.frontend.cloudfront_domain
# }

# output "alb_dns_name" {
#   description = "ALB DNS name (backend origin)."
#   value       = module.backend.alb_dns_name
# }

# output "batch_job_queue" {
#   description = "AWS Batch job queue for Ghidra jobs."
#   value       = module.batch.job_queue_arn
# }
