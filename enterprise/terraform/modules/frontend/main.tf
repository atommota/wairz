# Frontend module — CloudFront serving the SPA from S3 (private, via OAC) with
# /api/* and websockets routed to the backend ALB. Reproduces the nginx reverse
# proxy from frontend/nginx.conf.template (static + /api/ proxy) at the edge.

data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewer"
}

resource "aws_cloudfront_origin_access_control" "spa" {
  name                              = "${var.name}-spa"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Baseline security response headers for the SPA: HSTS + clickjacking/MIME
# hardening. A strict Content-Security-Policy is intentionally omitted (the SPA
# uses Monaco/blob web workers + Cognito redirects, which need a carefully tuned
# policy) — see the security review follow-ups.
resource "aws_cloudfront_response_headers_policy" "security" {
  name = "${var.name}-security-headers"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
  }
}

locals {
  s3_origin_id  = "spa-s3"
  alb_origin_id = "backend-alb"
}

resource "aws_cloudfront_distribution" "this" {
  enabled             = true
  default_root_object = "index.html"
  comment             = "${var.name} Wairz SPA + API"
  price_class         = var.price_class
  aliases             = var.aliases

  origin {
    origin_id                = local.s3_origin_id
    domain_name              = var.spa_bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.spa.id
  }

  origin {
    origin_id   = local.alb_origin_id
    domain_name = var.alb_dns_name
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only" # ALB listener is HTTP; TLS terminates at CloudFront
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # SPA static assets (default).
  default_cache_behavior {
    target_origin_id           = local.s3_origin_id
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = data.aws_cloudfront_cache_policy.optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    compress                   = true
  }

  # API + websockets → ALB, uncached, forward everything.
  ordered_cache_behavior {
    path_pattern             = "/api/*"
    target_origin_id         = local.alb_origin_id
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer.id
    compress                 = true
  }

  # Remote MCP (Phase 5) → ALB, uncached, all methods. compress=false so the
  # Streamable HTTP SSE responses pass through unbuffered.
  dynamic "ordered_cache_behavior" {
    for_each = var.mcp_enabled ? [1] : []
    content {
      path_pattern             = "/mcp*"
      target_origin_id         = local.alb_origin_id
      viewer_protocol_policy   = "redirect-to-https"
      allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
      cached_methods           = ["GET", "HEAD"]
      cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
      origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer.id
      compress                 = false
    }
  }

  # SPA client-side routing: serve index.html for unknown paths.
  custom_error_response {
    error_code            = 403
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 10
  }
  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 10
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = var.acm_certificate_arn == ""
    acm_certificate_arn            = var.acm_certificate_arn == "" ? null : var.acm_certificate_arn
    ssl_support_method             = var.acm_certificate_arn == "" ? null : "sni-only"
    minimum_protocol_version       = var.acm_certificate_arn == "" ? "TLSv1" : "TLSv1.2_2021"
  }
}

# Let CloudFront (via OAC) read the private SPA bucket.
data "aws_iam_policy_document" "spa_bucket" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${var.spa_bucket_arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.this.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "spa" {
  bucket = var.spa_bucket
  policy = data.aws_iam_policy_document.spa_bucket.json
}
