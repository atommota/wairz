# Core variables for the Wairz enterprise deployment.
# Phase 0 defines the cross-cutting inputs (naming, region, sizing knobs).
# Module-specific variables are added as each module lands (Phases 1-3).
# See terraform.tfvars.example for the operator-facing contract.

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix applied to all resource names."
  type        = string
  default     = "wairz"
}

variable "environment" {
  description = "Deployment environment (prod, staging, ...). Tagged on every resource."
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "Additional tags merged into the provider default_tags."
  type        = map(string)
  default     = {}
}

# --- Network (network module, Phase 1) -------------------------------------

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "create_nat_gateway" {
  description = "Use a NAT gateway for private egress instead of VPC endpoints. NAT ~$32/mo; endpoints cheaper at rest. See PLAN.md open decision #3."
  type        = bool
  default     = false
}

# --- Cache (cache module, Phase 1) ------------------------------------------

variable "redis_node_type" {
  description = "ElastiCache Redis node type."
  type        = string
  default     = "cache.t4g.micro"
}

# --- Serving layer (backend / frontend / auth modules, Phase 3) -------------

variable "alb_certificate_arn" {
  description = "ACM cert ARN to enable an HTTPS listener on the ALB (needed for ALB-level Cognito auth). Empty = HTTP only (fine behind CloudFront, which terminates TLS at the edge)."
  type        = string
  default     = ""
}

variable "cognito_domain_suffix" {
  description = "Suffix for the Cognito hosted-UI domain; the full prefix must be globally unique."
  type        = string
  default     = "auth"
}

# --- Application sizing / behavior knobs ------------------------------------

variable "max_upload_size_mb" {
  description = "Max firmware upload size (MB). Plumbs to the backend, ALB, and CloudFront body limits."
  type        = number
  default     = 500
}

# --- Aurora Serverless v2 (database module, Phase 1) ------------------------

variable "aurora_min_capacity" {
  description = "Aurora Serverless v2 minimum ACUs. 0.5 = always-warm; 0 = auto-pause (cheaper at rest, ~15s cold resume). See PLAN.md open decision #1."
  type        = number
  default     = 0.5
}

variable "aurora_max_capacity" {
  description = "Aurora Serverless v2 maximum ACUs (burst ceiling)."
  type        = number
  default     = 4
}

# --- AWS Batch (batch module, Phase 2) --------------------------------------

variable "batch_max_vcpus" {
  description = "Ceiling on Batch compute env vCPUs. Cost guardrail against runaway decompile fan-out."
  type        = number
  default     = 16
}

variable "batch_use_spot" {
  description = "Run Ghidra Batch jobs on Spot (cheaper; jobs are idempotent so interruptions are safe)."
  type        = bool
  default     = true
}
