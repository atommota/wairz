output "alb_dns_name" {
  description = "ALB DNS name (CloudFront API origin)."
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  value = aws_lb.this.zone_id
}

output "ecr_repository_url" {
  description = "Push the backend image here (also reused as the Batch Ghidra image)."
  value       = aws_ecr_repository.backend.repository_url
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "service_name" {
  value = aws_ecs_service.this.name
}

output "service_security_group_id" {
  value = aws_security_group.service.id
}
