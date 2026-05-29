output "primary_endpoint" {
  description = "Redis primary endpoint host."
  value       = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "redis_url" {
  description = "redis:// URL for the backend REDIS_URL setting."
  value       = "redis://${aws_elasticache_replication_group.this.primary_endpoint_address}:6379/0"
}

output "security_group_id" {
  value = aws_security_group.redis.id
}
