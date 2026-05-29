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

# --- Phase 2b: Ghidra on Batch ----------------------------------------------
output "batch_job_queue" {
  description = "AWS Batch job queue for Ghidra jobs (BATCH_JOB_QUEUE)."
  value       = module.batch.job_queue_arn
}

output "batch_import_job_definition" {
  description = "Batch job definition for heavy Ghidra imports (BATCH_JOB_DEFINITION)."
  value       = module.batch.import_job_definition_name
}

output "ghidra_ecr_repository_url" {
  description = "Push the Ghidra worker image here before first analysis."
  value       = module.batch.ecr_repository_url
}

# --- Phase 3: serving layer -------------------------------------------------
output "app_url" {
  description = "CloudFront URL serving the Wairz SPA + API."
  value       = "https://${module.frontend.cloudfront_domain}"
}

output "alb_dns_name" {
  description = "Backend ALB DNS name (CloudFront API origin)."
  value       = module.backend.alb_dns_name
}

output "backend_ecr_repository_url" {
  description = "Push the backend image here (also reused as the Batch Ghidra image)."
  value       = module.backend.ecr_repository_url
}

output "cognito_user_pool_id" {
  value = module.auth.user_pool_id
}

output "cognito_hosted_ui_domain" {
  value = module.auth.hosted_ui_domain
}

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
