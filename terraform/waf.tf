# CloudWatch Log Group for WAF
resource "aws_cloudwatch_log_group" "waf_log_group" {
  name              = "/aws/wafv2/${var.project_name}-v2"
  retention_in_days = 14

  tags = {
    Name = "WAF Log Group"
  }
}

# WAF Web ACL
resource "aws_wafv2_web_acl" "demo_waf" {
  name  = "${var.project_name}-waf-v2"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rate limiting rule - baseline protection with X-Forwarded-For support
  rule {
    name     = "RateLimitRule"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "FORWARDED_IP"
        evaluation_window_sec = 300
        
        forwarded_ip_config {
          header_name       = "X-Forwarded-For"
          fallback_behavior = "MATCH"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "RateLimitRule"
      sampled_requests_enabled    = true
    }
  }

  # AWS Managed Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "CommonRuleSetMetric"
      sampled_requests_enabled    = true
    }
  }

  # Known bad inputs rule set
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "KnownBadInputsRuleSetMetric"
      sampled_requests_enabled    = true
    }
  }



  # Dynamic blocking rule - this will be updated by our ML pipeline (HIGHEST PRIORITY)
  rule {
    name     = "MLGeneratedBlocking"
    priority = 0

    action {
      block {
        custom_response {
          response_code = 418
          custom_response_body_key = "teapot"
          response_header {
            name  = "X-Blocked-By"
            value = "ML-WAF"
          }
          response_header {
            name  = "Retry-After"
            value = "600"
          }
        }
      }
    }

    statement {
      or_statement {
        # Block common bot user-agents seen in logs
        statement {
          byte_match_statement {
            search_string = "python-requests"
            field_to_match {
              single_header {
                name = "user-agent"
              }
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        # Block automation cookies used by attack generator
        statement {
          byte_match_statement {
            search_string = "automation_tool"
            field_to_match {
              single_header {
                name = "cookie"
              }
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string = "bot_session"
            field_to_match {
              single_header {
                name = "cookie"
              }
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string = "injection_test"
            field_to_match {
              single_header {
                name = "cookie"
              }
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                 = "MLGeneratedBlocking"
      sampled_requests_enabled    = true
    }
  }

  tags = {
    Name = "${var.project_name}-waf"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                 = "${var.project_name}WebAcl"
    sampled_requests_enabled    = true
  }

  # Custom response bodies for ML-generated blocks
  custom_response_body {
    key          = "teapot"
    content      = "I'm a teapot. Your request was identified as automated by ML."
    content_type = "TEXT_PLAIN"
  }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "demo_waf_association" {
  resource_arn = aws_lb.demo_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.demo_waf.arn
}

# Kinesis Data Firehose for WAF logs - MUST start with "aws-waf-logs-"
resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {
  name        = "aws-waf-logs-${var.project_name}-v2"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn           = aws_iam_role.firehose_role.arn
    bucket_arn         = aws_s3_bucket.waf_logs.arn
    buffering_interval = 300
    buffering_size     = 5
    compression_format = "GZIP"
  }
}

# S3 bucket for WAF logs
resource "aws_s3_bucket" "waf_logs" {
  bucket        = "${var.project_name}-waf-logs-v3-${random_string.bucket_suffix.result}"
  force_destroy = true
  
  tags = {
    Name = "WAF Logs"
  }
}

resource "aws_s3_bucket_versioning" "waf_logs_versioning" {
  bucket = aws_s3_bucket.waf_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# IAM role for Firehose
resource "aws_iam_role" "firehose_role" {
  name = "${var.project_name}-firehose-role-v2"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "firehose_policy" {
  name = "${var.project_name}-firehose-policy-v2"
  role = aws_iam_role.firehose_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.waf_logs.arn,
          "${aws_s3_bucket.waf_logs.arn}/*"
        ]
      }
    ]
  })
}

# WAF Logging Configuration - CRITICAL for ML model
resource "aws_wafv2_web_acl_logging_configuration" "demo_waf_logging" {
  resource_arn            = aws_wafv2_web_acl.demo_waf.arn
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf_logs.arn]

  # Capture ALL headers and cookies for ML analysis - no redaction
}

# Data sources for ARN construction
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# S3 bucket for ML model artifacts
resource "aws_s3_bucket" "ml_artifacts" {
  bucket        = "${var.project_name}-ml-artifacts-v3-${random_string.bucket_suffix.result}"
  force_destroy = true

  tags = {
    Name = "ML Model Artifacts"
  }
}

resource "aws_s3_bucket_versioning" "ml_artifacts_versioning" {
  bucket = aws_s3_bucket.ml_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}
