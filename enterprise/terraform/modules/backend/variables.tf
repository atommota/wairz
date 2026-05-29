variable "name" {
  description = "Name prefix for backend resources."
  type        = string
}

variable "aws_region" {
  description = "AWS region (log/env config)."
  type        = string
}

variable "vpc_id" {
  type        = string
  description = "VPC id."
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnets for the ALB."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets for the Fargate tasks."
}

variable "container_port" {
  type        = number
  default     = 8000
  description = "Backend listen port."
}

variable "health_check_path" {
  type        = string
  default     = "/health"
  description = "ALB target-group health check path."
}

variable "task_cpu" {
  type        = number
  default     = 512
  description = "Fargate task CPU units (512 = 0.5 vCPU). Stays small — heavy work is on Batch."
}

variable "task_memory" {
  type        = number
  default     = 1024
  description = "Fargate task memory (MiB)."
}

variable "desired_count" {
  type        = number
  default     = 1
  description = "Baseline / minimum task count (also the autoscaling floor)."
}

variable "max_count" {
  type        = number
  default     = 4
  description = "Autoscaling ceiling."
}

variable "cpu_target_percent" {
  type        = number
  default     = 60
  description = "Target average CPU % for autoscaling."
}

variable "image_tag" {
  type        = string
  default     = "latest"
  description = "Backend image tag in the module's ECR repo."
}

variable "max_upload_size_mb" {
  type        = number
  default     = 500
  description = "Max upload size (plumbs to the app + should match ALB/CloudFront)."
}

variable "certificate_arn" {
  type        = string
  default     = ""
  description = "ACM cert ARN to enable an HTTPS listener (required for ALB-level Cognito auth). Empty = HTTP only (fine behind CloudFront)."
}

variable "log_retention_days" {
  type    = number
  default = 30
}

# --- Wired from other modules ----------------------------------------------
variable "efs_id" {
  type = string
}

variable "efs_firmware_access_point_id" {
  type = string
}

variable "efs_ghidra_projects_access_point_id" {
  type = string
}

variable "redis_url" {
  type = string
}

variable "database_url_secret_arn" {
  type = string
}

variable "secret_arns" {
  type        = list(string)
  default     = []
  description = "Secret ARNs the execution role must read."
}

variable "batch_job_queue" {
  type        = string
  description = "Batch job queue ARN (for SubmitJob + env)."
}

variable "batch_job_definition_arn" {
  type        = string
  description = "Batch import job definition ARN (for IAM scoping)."
}

variable "batch_job_definition_name" {
  type        = string
  description = "Batch import job definition name (for the BATCH_JOB_DEFINITION env)."
}
