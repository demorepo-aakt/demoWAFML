output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.demo_alb.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.demo_alb.zone_id
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.demo_alb.arn
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.demo_waf.arn
}

output "waf_web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.demo_waf.id
}

output "waf_log_group_name" {
  description = "Name of the WAF CloudWatch Log Group"
  value       = aws_cloudwatch_log_group.waf_log_group.name
}

output "alb_logs_bucket" {
  description = "S3 bucket for ALB access logs"
  value       = aws_s3_bucket.alb_logs.id
}

output "ml_artifacts_bucket" {
  description = "S3 bucket for ML model artifacts"
  value       = aws_s3_bucket.ml_artifacts.id
}

output "waf_logs_bucket" {
  description = "S3 bucket for WAF logs"
  value       = aws_s3_bucket.waf_logs.id
}

output "target_url" {
  description = "URL to send traffic to"
  value       = "http://${aws_lb.demo_alb.dns_name}"
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "subnet_ids" {
  description = "IDs of the subnets"
  value       = module.vpc.private_subnets
}
