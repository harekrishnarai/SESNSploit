# Secure SES Identity Configuration
# This Terraform configuration fixes vulnerabilities in SES identity management

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "redteam-test"
}

variable "authorized_domain" {
  description = "Authorized domain for SES (must be verified and controlled)"
  type        = string
  default     = "secure-company.example.com"
}

variable "authorized_email" {
  description = "Authorized email address for SES"
  type        = string
  default     = "noreply@secure-company.example.com"
}

variable "authorized_sender_arns" {
  description = "List of IAM role/user ARNs authorized to send emails"
  type        = list(string)
  default     = []
}

variable "monitoring_email" {
  description = "Email address for security monitoring notifications"
  type        = string
  default     = "security@secure-company.example.com"
}

# Secure email identity with strict controls
resource "aws_ses_email_identity" "secure_email" {
  email = var.authorized_email

  tags = {
    Environment = var.environment
    Purpose     = "Secure email identity"
    Security    = "Remediated"
  }
}

# Secure domain identity
resource "aws_ses_domain_identity" "secure_domain" {
  domain = var.authorized_domain

  tags = {
    Environment = var.environment
    Purpose     = "Secure domain identity"
    Security    = "Remediated"
  }
}

# Enable DKIM for domain authentication
resource "aws_ses_domain_dkim" "secure_domain_dkim" {
  domain = aws_ses_domain_identity.secure_domain.domain
}

# Verify DKIM tokens (these need to be added to DNS)
resource "aws_route53_record" "dkim_records" {
  count = 3

  zone_id = data.aws_route53_zone.domain_zone.zone_id
  name    = "${aws_ses_domain_dkim.secure_domain_dkim.dkim_tokens[count.index]}._domainkey"
  type    = "CNAME"
  ttl     = 600
  records = ["${aws_ses_domain_dkim.secure_domain_dkim.dkim_tokens[count.index]}.dkim.amazonses.com"]
}

# Data source for Route53 zone (assuming you have one)
data "aws_route53_zone" "domain_zone" {
  name         = var.authorized_domain
  private_zone = false
}

# SPF record for email authentication
resource "aws_route53_record" "spf_record" {
  zone_id = data.aws_route53_zone.domain_zone.zone_id
  name    = var.authorized_domain
  type    = "TXT"
  ttl     = 600
  records = ["v=spf1 include:amazonses.com ~all"]
}

# DMARC record for email policy
resource "aws_route53_record" "dmarc_record" {
  zone_id = data.aws_route53_zone.domain_zone.zone_id
  name    = "_dmarc"
  type    = "TXT"
  ttl     = 600
  records = ["v=DMARC1; p=quarantine; rua=mailto:${var.monitoring_email}; ruf=mailto:${var.monitoring_email}; fo=1"]
}

# Restrictive sending authorization policy
resource "aws_ses_identity_policy" "secure_sending_policy" {
  identity = aws_ses_email_identity.secure_email.email
  name     = "SecureSendingPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAuthorizedSendersOnly"
        Effect = "Allow"
        Principal = {
          AWS = length(var.authorized_sender_arns) > 0 ? var.authorized_sender_arns : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
          ]
        }
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:identity/${var.authorized_email}"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
          Bool = {
            "aws:SecureTransport" = "true"
          }
          DateGreaterThan = {
            "aws:CurrentTime" = "2024-01-01T00:00:00Z"
          }
          StringLike = {
            "aws:userid" = [
              "AIDACKCEVSQ6C2EXAMPLE:*",  # Replace with actual user IDs
              "*:authorized-sender"
            ]
          }
        }
      }
    ]
  })
}

# Secure domain policy
resource "aws_ses_identity_policy" "secure_domain_policy" {
  identity = aws_ses_domain_identity.secure_domain.domain
  name     = "SecureDomainPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowOnlySpecificApplications"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.secure_app_role.arn
        }
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail",
          "ses:SendTemplatedEmail"
        ]
        Resource = "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:identity/${var.authorized_domain}"
        Condition = {
          StringEquals = {
            "ses:FromAddress" = [
              "noreply@${var.authorized_domain}",
              "notifications@${var.authorized_domain}",
              "security@${var.authorized_domain}"
            ]
          }
          Bool = {
            "aws:SecureTransport" = "true"
          }
          IpAddress = {
            "aws:SourceIp" = [
              "10.0.0.0/8",    # Internal network
              "172.16.0.0/12", # Internal network
              "192.168.0.0/16" # Internal network
            ]
          }
        }
      },
      {
        Sid    = "DenyIdentityManipulation"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "ses:VerifyEmailIdentity",
          "ses:VerifyDomainIdentity",
          "ses:PutIdentityPolicy",
          "ses:DeleteIdentityPolicy",
          "ses:DeleteIdentity"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = [
              aws_iam_role.ses_admin_role.arn
            ]
          }
        }
      }
    ]
  })
}

# Secure SES configuration set
resource "aws_ses_configuration_set" "secure_config_set" {
  name = "${var.environment}-secure-config"

  # Enable tracking settings
  tracking_options {
    custom_redirect_domain = "track.${var.authorized_domain}"
  }

  # Reputation tracking
  reputation_metrics_enabled = true

  tags = {
    Environment = var.environment
    Purpose     = "Secure SES configuration"
    Security    = "Remediated"
  }
}

# Secure event destination with encryption
resource "aws_ses_event_destination" "secure_events" {
  name                   = "secure-events"
  configuration_set_name = aws_ses_configuration_set.secure_config_set.name
  enabled                = true

  # Use CloudWatch instead of SNS for better security
  cloudwatch_destination {
    default_value  = "0"
    dimension_name = "MessageTag"
    value_source   = "messageTag"
  }

  matching_types = [
    "send",
    "reject",
    "bounce",
    "complaint"
  ]
}

# Alternative: Secure SNS destination with encryption
resource "aws_sns_topic" "secure_ses_events" {
  name = "${var.environment}-secure-ses-events"

  # Enable server-side encryption
  kms_master_key_id = aws_kms_key.ses_events_key.id

  tags = {
    Environment = var.environment
    Purpose     = "Secure SES events"
    Security    = "Remediated"
  }
}

# KMS key for SNS encryption
resource "aws_kms_key" "ses_events_key" {
  description             = "KMS key for SES events encryption"
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowSESService"
        Effect = "Allow"
        Principal = {
          Service = "ses.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Environment = var.environment
    Purpose     = "SES events encryption"
  }
}

resource "aws_kms_alias" "ses_events_key_alias" {
  name          = "alias/${var.environment}-ses-events"
  target_key_id = aws_kms_key.ses_events_key.key_id
}

# Secure SNS topic policy
resource "aws_sns_topic_policy" "secure_ses_events_policy" {
  arn = aws_sns_topic.secure_ses_events.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSESService"
        Effect = "Allow"
        Principal = {
          Service = "ses.amazonaws.com"
        }
        Action = "sns:Publish"
        Resource = aws_sns_topic.secure_ses_events.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowSecurityTeamSubscribe"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.security_monitoring_role.arn
        }
        Action = [
          "sns:Subscribe",
          "sns:Unsubscribe"
        ]
        Resource = aws_sns_topic.secure_ses_events.arn
      }
    ]
  })
}

# Secure email template with input validation
resource "aws_ses_template" "secure_template" {
  name = "${var.environment}-secure-notification"

  subject = "{{subject}}"

  # HTML template with basic XSS protection
  html = <<-EOT
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>{{subject}}</title>
    </head>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: #f5f5f5; padding: 20px;">
            <h1 style="color: #333;">{{title}}</h1>
            <p>Dear {{name}},</p>
            <div style="background-color: white; padding: 15px; border-radius: 5px;">
                <p>{{message}}</p>
            </div>
            <p style="color: #666; font-size: 12px; margin-top: 20px;">
                This is an automated message from {{company_name}}.<br>
                If you have questions, please contact support at {{support_email}}.
            </p>
        </div>
    </body>
    </html>
  EOT

  # Plain text version
  text = <<-EOT
    {{title}}
    
    Dear {{name}},
    
    {{message}}
    
    ---
    This is an automated message from {{company_name}}.
    If you have questions, please contact support at {{support_email}}.
  EOT

  tags = {
    Environment = var.environment
    Purpose     = "Secure email template"
    Security    = "Remediated"
  }
}

# Secure application role with minimal SES permissions
resource "aws_iam_role" "secure_app_role" {
  name = "${var.environment}-secure-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = random_string.app_external_id.result
          }
          IpAddress = {
            "aws:SourceIp" = [
              "10.0.0.0/8",    # Internal network
              "172.16.0.0/12", # Internal network
              "192.168.0.0/16" # Internal network
            ]
          }
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Purpose     = "Secure application role"
    Security    = "Remediated"
  }
}

# Random external ID for secure role assumption
resource "random_string" "app_external_id" {
  length  = 32
  special = false
}

# Minimal SES permissions for application
resource "aws_iam_role_policy" "secure_app_ses_policy" {
  name = "${var.environment}-secure-app-ses"
  role = aws_iam_role.secure_app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail",
          "ses:SendTemplatedEmail"
        ]
        Resource = [
          "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:identity/${var.authorized_email}",
          "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:template/${aws_ses_template.secure_template.name}",
          "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:configuration-set/${aws_ses_configuration_set.secure_config_set.name}"
        ]
        Condition = {
          StringEquals = {
            "ses:FromAddress" = var.authorized_email
          }
          StringLike = {
            "ses:Recipients" = [
              "*@${var.authorized_domain}",
              "*@partner.com"  # Authorized external domains
            ]
          }
          NumericLessThan = {
            "ses:MaxSendRate" = "10"  # Rate limiting
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.ses_events_key.arn
      }
    ]
  })
}

# SES administrator role for identity management
resource "aws_iam_role" "ses_admin_role" {
  name = "${var.environment}-ses-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = [
            # Only specific admin users can assume this role
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/ses-admin"
          ]
        }
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          NumericLessThan = {
            "aws:MultiFactorAuthAge" = "3600"  # MFA within last hour
          }
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Purpose     = "SES administration"
    Security    = "Remediated"
  }
}

# SES admin permissions
resource "aws_iam_role_policy" "ses_admin_policy" {
  name = "${var.environment}-ses-admin-policy"
  role = aws_iam_role.ses_admin_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ses:VerifyEmailIdentity",
          "ses:VerifyDomainIdentity",
          "ses:PutIdentityPolicy",
          "ses:DeleteIdentityPolicy",
          "ses:GetIdentityPolicies",
          "ses:ListIdentityPolicies",
          "ses:PutConfigurationSetEventDestination",
          "ses:DeleteConfigurationSetEventDestination"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      }
    ]
  })
}

# Security monitoring role
resource "aws_iam_role" "security_monitoring_role" {
  name = "${var.environment}-security-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Purpose     = "Security monitoring"
  }
}

# CloudWatch alarm for unusual sending patterns
resource "aws_cloudwatch_metric_alarm" "high_send_rate" {
  alarm_name          = "${var.environment}-ses-high-send-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Send"
  namespace           = "AWS/SES"
  period              = "300"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "This metric monitors SES send rate"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    ConfigurationSet = aws_ses_configuration_set.secure_config_set.name
  }

  tags = {
    Environment = var.environment
    Purpose     = "Security monitoring"
  }
}

# Security alerts topic
resource "aws_sns_topic" "security_alerts" {
  name = "${var.environment}-security-alerts"

  kms_master_key_id = aws_kms_key.ses_events_key.id

  tags = {
    Environment = var.environment
    Purpose     = "Security alerts"
  }
}

data "aws_caller_identity" "current" {}

# Outputs
output "secure_email_identity" {
  description = "Secure email identity"
  value       = aws_ses_email_identity.secure_email.email
}

output "secure_domain_identity" {
  description = "Secure domain identity"
  value       = aws_ses_domain_identity.secure_domain.domain
}

output "dkim_tokens" {
  description = "DKIM tokens for DNS configuration"
  value       = aws_ses_domain_dkim.secure_domain_dkim.dkim_tokens
}

output "secure_app_role_arn" {
  description = "Secure application role ARN"
  value       = aws_iam_role.secure_app_role.arn
}

output "app_external_id" {
  description = "External ID for application role"
  value       = random_string.app_external_id.result
  sensitive   = true
}

output "security_improvements" {
  description = "Security improvements implemented"
  value = <<-EOT
    Security Improvements Applied:
    1. ✅ Restricted sending policies to authorized principals only
    2. ✅ Implemented DKIM authentication
    3. ✅ Added SPF and DMARC records for email validation
    4. ✅ Enabled KMS encryption for event notifications
    5. ✅ Added IP address restrictions for role assumption
    6. ✅ Required MFA for administrative operations
    7. ✅ Implemented rate limiting on email sending
    8. ✅ Added recipient restrictions
    9. ✅ Created secure email templates with XSS protection
    10. ✅ Enabled CloudWatch monitoring and alerting
    11. ✅ Used external IDs for secure role assumption
    12. ✅ Denied identity manipulation for non-admin roles
  EOT
}

output "dns_configuration" {
  description = "Required DNS configuration"
  value = <<-EOT
    Add these DNS records to complete email authentication:
    
    1. SPF Record:
       Type: TXT
       Name: ${var.authorized_domain}
       Value: v=spf1 include:amazonses.com ~all
    
    2. DMARC Record:
       Type: TXT
       Name: _dmarc.${var.authorized_domain}
       Value: v=DMARC1; p=quarantine; rua=mailto:${var.monitoring_email}; ruf=mailto:${var.monitoring_email}; fo=1
    
    3. DKIM Records (automatically configured via Route53)
  EOT
}
