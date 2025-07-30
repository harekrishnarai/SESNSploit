# SESNSploit Test Data Infrastructure
# This Terraform configuration creates test data and resources for SESNSploit tool testing

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}

provider "aws" {
  region = var.primary_region
}

# Configure additional providers for multi-region testing
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"
}

provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"
}

variable "primary_region" {
  description = "Primary AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name for resource tagging"
  type        = string
  default     = "sesnsloit-test"
}

variable "test_email_domain" {
  description = "Domain for test email identities (must be a domain you control)"
  type        = string
  default     = "test.example.com"
}

variable "create_cross_region_resources" {
  description = "Whether to create resources in multiple regions"
  type        = bool
  default     = true
}

variable "create_vulnerable_configs" {
  description = "Whether to create vulnerable configurations for testing"
  type        = bool
  default     = true
}

# Random suffix for unique resource names
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

locals {
  resource_suffix = random_string.suffix.result
  test_regions = var.create_cross_region_resources ? [
    "us-east-1",
    "us-west-2",
    "eu-west-1"
  ] : [var.primary_region]
}

# ===== SNS TEST DATA =====

# Create SNS topics in primary region
resource "aws_sns_topic" "test_notifications" {
  name = "${var.environment}-notifications-${local.resource_suffix}"

  tags = {
    Environment = var.environment
    Purpose     = "SESNSploit testing"
    Type        = "test-data"
  }
}

resource "aws_sns_topic" "test_alerts" {
  name = "${var.environment}-alerts-${local.resource_suffix}"

  tags = {
    Environment = var.environment
    Purpose     = "Alert notifications"
    Type        = "test-data"
  }
}

resource "aws_sns_topic" "test_admin" {
  name = "${var.environment}-admin-${local.resource_suffix}"

  tags = {
    Environment = var.environment
    Purpose     = "Admin notifications"
    Type        = "test-data"
    Sensitive   = "true"
  }
}

# Create topics with different policy configurations
resource "aws_sns_topic" "test_public" {
  count = var.create_vulnerable_configs ? 1 : 0
  name  = "${var.environment}-public-${local.resource_suffix}"

  tags = {
    Environment = var.environment
    Purpose     = "Public notifications"
    Type        = "test-data"
    Security    = "vulnerable"
  }
}

# Overly permissive policy for testing
resource "aws_sns_topic_policy" "test_public_policy" {
  count = var.create_vulnerable_configs ? 1 : 0
  arn   = aws_sns_topic.test_public[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPublicAccess"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "sns:Subscribe",
          "sns:Publish",
          "sns:Receive"
        ]
        Resource = aws_sns_topic.test_public[0].arn
      }
    ]
  })
}

# Secure topic with restricted access
resource "aws_sns_topic_policy" "test_notifications_policy" {
  arn = aws_sns_topic.test_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "sns:Subscribe",
          "sns:Publish",
          "sns:Receive"
        ]
        Resource = aws_sns_topic.test_notifications.arn
      },
      {
        Sid    = "AllowSESPublish"
        Effect = "Allow"
        Principal = {
          Service = "ses.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.test_notifications.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Create SNS topics in additional regions
resource "aws_sns_topic" "test_regional_us_west" {
  count    = var.create_cross_region_resources ? 1 : 0
  provider = aws.us_west_2
  name     = "${var.environment}-west-${local.resource_suffix}"

  tags = {
    Environment = var.environment
    Purpose     = "Regional testing - US West"
    Type        = "test-data"
    Region      = "us-west-2"
  }
}

resource "aws_sns_topic" "test_regional_eu" {
  count    = var.create_cross_region_resources ? 1 : 0
  provider = aws.eu_west_1
  name     = "${var.environment}-eu-${local.resource_suffix}"

  tags = {
    Environment = var.environment
    Purpose     = "Regional testing - EU"
    Type        = "test-data"
    Region      = "eu-west-1"
  }
}

# Create various subscription types for testing
resource "aws_sqs_queue" "test_subscription_queue" {
  name = "${var.environment}-test-queue-${local.resource_suffix}"

  tags = {
    Environment = var.environment
    Purpose     = "SNS subscription testing"
  }
}

resource "aws_sns_topic_subscription" "test_sqs_subscription" {
  topic_arn = aws_sns_topic.test_notifications.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.test_subscription_queue.arn
}

resource "aws_sqs_queue_policy" "test_queue_policy" {
  queue_url = aws_sqs_queue.test_subscription_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.test_subscription_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.test_notifications.arn
          }
        }
      }
    ]
  })
}

# HTTP endpoint subscription (for testing) - disabled as endpoint doesn't exist
# resource "aws_sns_topic_subscription" "test_http_subscription" {
#   count     = var.create_vulnerable_configs ? 1 : 0
#   topic_arn = aws_sns_topic.test_public[0].arn
#   protocol  = "http"
#   endpoint  = "http://test-endpoint.${var.test_email_domain}/sns-webhook"
# }

# ===== SES TEST DATA =====

# Create SES email identities
resource "aws_ses_email_identity" "test_primary" {
  email = "hi@${var.test_email_domain}"
}

resource "aws_ses_email_identity" "test_secondary" {
  email = "hello@${var.test_email_domain}"
}

# Create SES domain identity
resource "aws_ses_domain_identity" "test_domain" {
  domain = var.test_email_domain
}

# SES Configuration Set
resource "aws_ses_configuration_set" "test_config_set" {
  name = "${var.environment}-test-config-${local.resource_suffix}"
}

# SES Event Destination - temporarily disabled due to permission issues
# resource "aws_ses_event_destination" "test_sns_events" {
#   name                   = "test-sns-events"
#   configuration_set_name = aws_ses_configuration_set.test_config_set.name
#   enabled                = true

#   sns_destination {
#     topic_arn = aws_sns_topic.test_notifications.arn
#   }

#   matching_types = [
#     "send",
#     "reject",
#     "bounce",
#     "complaint",
#     "delivery"
#   ]
# }

# SES Email Template
resource "aws_ses_template" "test_notification_template" {
  name    = "${var.environment}-notification-${local.resource_suffix}"
  subject = "Test Notification: {{subject}}"

  html = <<-EOT
    <html>
    <body>
      <h2>{{title}}</h2>
      <p>Hello {{name}},</p>
      <p>{{message}}</p>
      <p>Best regards,<br>{{sender_name}}</p>
    </body>
    </html>
  EOT

  text = <<-EOT
    {{title}}
    
    Hello {{name}},
    
    {{message}}
    
    Best regards,
    {{sender_name}}
  EOT
}

# SES Receipt Rule Set (if in a region that supports it)
resource "aws_ses_receipt_rule_set" "test_rule_set" {
  rule_set_name = "${var.environment}-test-rules-${local.resource_suffix}"
}

# SES Receipt Rule - temporarily disabled due to permission issues
# resource "aws_ses_receipt_rule" "test_rule" {
#   name          = "test-rule"
#   rule_set_name = aws_ses_receipt_rule_set.test_rule_set.rule_set_name
#   recipients    = ["test@${var.test_email_domain}"]
#   enabled       = true
#   scan_enabled  = true

#   s3_action {
#     bucket_name       = aws_s3_bucket.ses_storage.bucket
#     object_key_prefix = "emails/"
#     position          = 1
#   }

#   sns_action {
#     topic_arn = aws_sns_topic.test_notifications.arn
#     position  = 2
#   }
# }

# S3 bucket for SES storage
resource "aws_s3_bucket" "ses_storage" {
  bucket        = "${var.environment}-ses-storage-${local.resource_suffix}"
  force_destroy = true

  tags = {
    Environment = var.environment
    Purpose     = "SES email storage"
    Type        = "test-data"
  }
}

resource "aws_s3_bucket_policy" "ses_storage_policy" {
  bucket = aws_s3_bucket.ses_storage.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSESPuts"
        Effect = "Allow"
        Principal = {
          Service = "ses.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.ses_storage.arn}/*"
        Condition = {
          StringEquals = {
            "aws:Referer" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# ===== LAMBDA FUNCTIONS FOR TESTING =====

# Lambda function for SNS processing
resource "aws_lambda_function" "sns_processor" {
  filename      = "sns_processor.zip"
  function_name = "${var.environment}-sns-processor-${local.resource_suffix}"
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 30

  depends_on = [data.archive_file.sns_processor_zip]

  tags = {
    Environment = var.environment
    Purpose     = "SNS message processing"
    Type        = "test-data"
  }
}

# Create Lambda deployment package
data "archive_file" "sns_processor_zip" {
  type        = "zip"
  output_path = "sns_processor.zip"
  source {
    content  = <<-EOT
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """Process SNS messages for testing purposes"""
    logger.info(f"Received event: {json.dumps(event)}")
    
    for record in event.get('Records', []):
        if record.get('EventSource') == 'aws:sns':
            message = record['Sns']['Message']
            subject = record['Sns'].get('Subject', 'No Subject')
            
            logger.info(f"Processing message - Subject: {subject}")
            logger.info(f"Message: {message}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'SNS message processed successfully',
            'processedRecords': len(event.get('Records', []))
        })
    }
EOT
    filename = "index.py"
  }
}

# IAM role for Lambda execution
resource "aws_iam_role" "lambda_execution_role" {
  name = "${var.environment}-lambda-execution-${local.resource_suffix}"

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
    Purpose     = "Lambda execution role"
    Type        = "test-data"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Subscribe Lambda to SNS topic
resource "aws_sns_topic_subscription" "lambda_subscription" {
  topic_arn = aws_sns_topic.test_notifications.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.sns_processor.arn
}

resource "aws_lambda_permission" "allow_sns_invoke" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sns_processor.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.test_notifications.arn
}

# ===== IAM ROLES FOR TESTING =====

# Test role with SNS permissions
resource "aws_iam_role" "sns_test_role" {
  name = "${var.environment}-sns-test-${local.resource_suffix}"

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
    Purpose     = "SNS testing role"
    Type        = "test-data"
  }
}

resource "aws_iam_role_policy" "sns_test_policy" {
  name = "${var.environment}-sns-test-policy"
  role = aws_iam_role.sns_test_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:ListTopics",
          "sns:GetTopicAttributes",
          "sns:ListSubscriptions",
          "sns:ListSubscriptionsByTopic",
          "sns:Subscribe",
          "sns:Unsubscribe",
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })
}

# Test role with SES permissions
resource "aws_iam_role" "ses_test_role" {
  name = "${var.environment}-ses-test-${local.resource_suffix}"

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
    Purpose     = "SES testing role"
    Type        = "test-data"
  }
}

resource "aws_iam_role_policy" "ses_test_policy" {
  name = "${var.environment}-ses-test-policy"
  role = aws_iam_role.ses_test_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ses:ListIdentities",
          "ses:GetIdentityAttributes",
          "ses:GetIdentityPolicies",
          "ses:ListConfigurationSets",
          "ses:GetConfigurationSet",
          "ses:ListTemplates",
          "ses:GetTemplate",
          "ses:SendEmail",
          "ses:SendRawEmail",
          "ses:SendTemplatedEmail"
        ]
        Resource = "*"
      }
    ]
  })
}

# Combined role with both SNS and SES permissions
resource "aws_iam_role" "combined_test_role" {
  name = "${var.environment}-combined-test-${local.resource_suffix}"

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
    Purpose     = "Combined SNS/SES testing role"
    Type        = "test-data"
  }
}

resource "aws_iam_role_policy" "combined_test_policy" {
  name = "${var.environment}-combined-test-policy"
  role = aws_iam_role.combined_test_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:*",
          "ses:*",
          "sqs:GetQueueUrl",
          "sqs:GetQueueAttributes",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===== TEST DATA POPULATION =====

# Create some test messages in SQS for processing
resource "null_resource" "populate_test_data" {
  count = var.create_cross_region_resources ? 1 : 0

  provisioner "local-exec" {
    command = <<-EOT
      # Send test message to SNS topic
      aws sns publish \
        --topic-arn ${aws_sns_topic.test_notifications.arn} \
        --message "Test message from Terraform - SESNSploit test data population" \
        --subject "Test Notification" \
        --region ${var.primary_region} || true
    EOT
  }

  depends_on = [
    aws_sns_topic_subscription.lambda_subscription,
    aws_sns_topic_subscription.test_sqs_subscription
  ]
}

# ===== DATA SOURCES =====

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# ===== OUTPUTS =====

output "sns_topics" {
  description = "SNS topics created for testing"
  value = {
    notifications = aws_sns_topic.test_notifications.arn
    alerts        = aws_sns_topic.test_alerts.arn
    admin         = aws_sns_topic.test_admin.arn
    public        = var.create_vulnerable_configs ? aws_sns_topic.test_public[0].arn : null
  }
}

output "sns_regional_topics" {
  description = "Regional SNS topics"
  value = var.create_cross_region_resources ? {
    us_west_2 = aws_sns_topic.test_regional_us_west[0].arn
    eu_west_1 = aws_sns_topic.test_regional_eu[0].arn
  } : {}
}

output "ses_identities" {
  description = "SES identities created for testing"
  value = {
    domain         = aws_ses_domain_identity.test_domain.domain
    primary_email  = aws_ses_email_identity.test_primary.email
    secondary_email = aws_ses_email_identity.test_secondary.email
  }
}

output "ses_configuration" {
  description = "SES configuration details"
  value = {
    configuration_set = aws_ses_configuration_set.test_config_set.name
    template_name     = aws_ses_template.test_notification_template.name
    rule_set          = aws_ses_receipt_rule_set.test_rule_set.rule_set_name
    storage_bucket    = aws_s3_bucket.ses_storage.bucket
  }
}

output "iam_roles" {
  description = "IAM roles for testing"
  value = {
    sns_test_role      = aws_iam_role.sns_test_role.arn
    ses_test_role      = aws_iam_role.ses_test_role.arn
    combined_test_role = aws_iam_role.combined_test_role.arn
  }
}

output "lambda_functions" {
  description = "Lambda functions for testing"
  value = {
    sns_processor = aws_lambda_function.sns_processor.arn
  }
}

output "test_commands" {
  description = "Commands to test SESNSploit with the created resources"
  value       = <<-EOT
    # Test SESNSploit with the created resources:
    
    1. Test with SNS-only role:
    aws sts assume-role --role-arn ${aws_iam_role.sns_test_role.arn} --role-session-name SNSTest
    python3 main.py
    
    2. Test with SES-only role:
    aws sts assume-role --role-arn ${aws_iam_role.ses_test_role.arn} --role-session-name SESTest
    python3 main.py
    
    3. Test with combined permissions:
    aws sts assume-role --role-arn ${aws_iam_role.combined_test_role.arn} --role-session-name CombinedTest
    python3 main.py
    
    4. Send test message to SNS:
    aws sns publish --topic-arn ${aws_sns_topic.test_notifications.arn} --message "Test from SESNSploit"
    
    5. Send test email via SES:
    aws ses send-email \
      --source "hi@${var.test_email_domain}" \
      --destination "ToAddresses=hello@${var.test_email_domain}" \
      --message "Subject={Data='Test Email'},Body={Text={Data='This is a test email from SESNSploit testing infrastructure.'}}"
  EOT
}

output "verification_requirements" {
  description = "Steps needed to complete the test setup"
  value       = <<-EOT
    To complete the test setup:
    
    1. Verify the domain ${var.test_email_domain} in SES:
       - Add TXT record: _amazonses.${var.test_email_domain} = ${aws_ses_domain_identity.test_domain.verification_token}
    
    2. Verify email addresses in SES (check your email for verification links):
       - hi@${var.test_email_domain}
       - hello@${var.test_email_domain}
    
    3. Test regions configured: ${join(", ", local.test_regions)}
    
    4. Resources created in account: ${data.aws_caller_identity.current.account_id}
  EOT
}
