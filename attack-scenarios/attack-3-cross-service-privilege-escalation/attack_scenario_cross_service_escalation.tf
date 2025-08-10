# Vulnerable Cross-Service Infrastructure
# This Terraform creates vulnerable cross-service integrations for privilege escalation testing

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

# Create a vulnerable SNS topic that can trigger Lambda functions
resource "aws_sns_topic" "vulnerable_trigger_topic" {
  name = "${var.environment}-vulnerable-trigger"

  tags = {
    Environment = var.environment
    Purpose     = "Vulnerable topic for privilege escalation"
    Attack      = "Cross-Service Privilege Escalation"
  }
}

# Overly permissive policy allowing anyone to publish
resource "aws_sns_topic_policy" "vulnerable_trigger_policy" {
  arn = aws_sns_topic.vulnerable_trigger_topic.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPublicPublish"
        Effect = "Allow"
        Principal = "*"  # VULNERABILITY: Too permissive
        Action = [
          "sns:Publish",
          "sns:Subscribe"
        ]
        Resource = aws_sns_topic.vulnerable_trigger_topic.arn
      }
    ]
  })
}

# Lambda function with excessive permissions - VULNERABLE
resource "aws_lambda_function" "privileged_processor" {
  filename         = "privileged_processor.zip"
  function_name    = "${var.environment}-privileged-processor"
  role            = aws_iam_role.privileged_lambda_role.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 30

  # Create a simple Lambda function
  depends_on = [data.archive_file.lambda_zip]

  tags = {
    Environment = var.environment
    Purpose     = "Privileged Lambda function"
    Risk        = "High privilege escalation risk"
  }
}

# Create the Lambda function code
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "privileged_processor.zip"
  source {
    content = <<-EOT
import json
import boto3
import os

def handler(event, context):
    """
    Privileged Lambda function that processes SNS messages
    VULNERABILITY: Has excessive permissions and processes untrusted input
    """
    
    # Extract message from SNS event
    if 'Records' in event:
        for record in event['Records']:
            if record['EventSource'] == 'aws:sns':
                message = json.loads(record['Sns']['Message'])
                
                # VULNERABILITY: Processes user-controlled input
                if 'command' in message:
                    command = message['command']
                    
                    # Dangerous: Execute based on user input
                    if command == 'list_secrets':
                        secrets_client = boto3.client('secretsmanager')
                        try:
                            secrets = secrets_client.list_secrets()
                            print(f"Found secrets: {secrets}")
                        except Exception as e:
                            print(f"Error accessing secrets: {e}")
                    
                    elif command == 'read_s3':
                        s3_client = boto3.client('s3')
                        bucket = message.get('bucket', 'default-bucket')
                        try:
                            objects = s3_client.list_objects_v2(Bucket=bucket)
                            print(f"S3 objects in {bucket}: {objects}")
                        except Exception as e:
                            print(f"Error accessing S3: {e}")
                    
                    elif command == 'assume_role':
                        sts_client = boto3.client('sts')
                        role_arn = message.get('role_arn')
                        if role_arn:
                            try:
                                response = sts_client.assume_role(
                                    RoleArn=role_arn,
                                    RoleSessionName='privileged-session'
                                )
                                print(f"Assumed role: {response}")
                            except Exception as e:
                                print(f"Error assuming role: {e}")
    
    return {
        'statusCode': 200,
        'body': json.dumps('Message processed')
    }
EOT
    filename = "index.py"
  }
}

# Overly privileged IAM role for Lambda - VULNERABILITY
resource "aws_iam_role" "privileged_lambda_role" {
  name = "${var.environment}-privileged-lambda-role"

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
    Purpose     = "Privileged Lambda execution role"
    Risk        = "Excessive permissions"
  }
}

# Attach excessive permissions to Lambda role
resource "aws_iam_role_policy" "privileged_lambda_policy" {
  name = "${var.environment}-privileged-lambda-policy"
  role = aws_iam_role.privileged_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:*",  # VULNERABILITY: Full secrets access
          "s3:*",              # VULNERABILITY: Full S3 access
          "sts:AssumeRole",    # VULNERABILITY: Can assume any role
          "iam:*",             # VULNERABILITY: Full IAM access
          "ec2:*",             # VULNERABILITY: Full EC2 access
          "rds:*"              # VULNERABILITY: Full RDS access
        ]
        Resource = "*"
      }
    ]
  })
}

# Subscribe Lambda to SNS topic
resource "aws_sns_topic_subscription" "lambda_subscription" {
  topic_arn = aws_sns_topic.vulnerable_trigger_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.privileged_processor.arn
}

# Allow SNS to invoke Lambda
resource "aws_lambda_permission" "allow_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.privileged_processor.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.vulnerable_trigger_topic.arn
}

# Create a vulnerable SQS queue for message processing
resource "aws_sqs_queue" "vulnerable_processing_queue" {
  name = "${var.environment}-vulnerable-processing"

  tags = {
    Environment = var.environment
    Purpose     = "Vulnerable message queue"
  }
}

# Overly permissive SQS policy
resource "aws_sqs_queue_policy" "vulnerable_queue_policy" {
  queue_url = aws_sqs_queue.vulnerable_processing_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"  # VULNERABILITY: Anyone can send messages
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage"
        ]
        Resource = aws_sqs_queue.vulnerable_processing_queue.arn
      }
    ]
  })
}

# Subscribe SQS to SNS topic
resource "aws_sns_topic_subscription" "sqs_subscription" {
  topic_arn = aws_sns_topic.vulnerable_trigger_topic.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.vulnerable_processing_queue.arn
}

# Create S3 bucket with vulnerable access
resource "aws_s3_bucket" "vulnerable_data_bucket" {
  bucket        = "${var.environment}-vulnerable-data-${random_string.bucket_suffix.result}"
  force_destroy = true

  tags = {
    Environment = var.environment
    Purpose     = "Vulnerable data storage"
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# Vulnerable S3 bucket policy
resource "aws_s3_bucket_policy" "vulnerable_bucket_policy" {
  bucket = aws_s3_bucket.vulnerable_data_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "sns.amazonaws.com",
            "ses.amazonaws.com"
          ]
        }
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.vulnerable_data_bucket.arn,
          "${aws_s3_bucket.vulnerable_data_bucket.arn}/*"
        ]
      },
      {
        Sid    = "AllowLambdaAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.privileged_lambda_role.arn
        }
        Action = "s3:*"  # VULNERABILITY: Full access
        Resource = [
          aws_s3_bucket.vulnerable_data_bucket.arn,
          "${aws_s3_bucket.vulnerable_data_bucket.arn}/*"
        ]
      }
    ]
  })
}

# Create a cross-account role that can be assumed - VULNERABLE
resource "aws_iam_role" "cross_account_role" {
  name = "${var.environment}-cross-account-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.privileged_lambda_role.arn  # Lambda can assume this role
        }
        Action = "sts:AssumeRole"
        # VULNERABILITY: No external ID or conditions
      },
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "sns.amazonaws.com",
            "ses.amazonaws.com"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Environment = var.environment
    Purpose     = "Cross-account access role"
    Risk        = "Can be assumed without proper validation"
  }
}

# Attach admin permissions to cross-account role - DANGEROUS
resource "aws_iam_role_policy_attachment" "cross_account_admin" {
  role       = aws_iam_role.cross_account_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # VULNERABILITY: Full admin access
}

# Create SES identity for additional attack vectors
resource "aws_ses_email_identity" "vulnerable_ses_identity" {
  email = "notifications@${var.environment}.example.com"
  
  # Note: aws_ses_email_identity doesn't support tags
}

# Create SNS topic for S3 integration
resource "aws_sns_topic" "s3_integration_topic" {
  name = "${var.environment}-s3-integration"

  tags = {
    Environment = var.environment
    Purpose     = "S3 integration topic for SES events"
    Attack      = "Cross-Service Integration"
  }
}

# Vulnerable policy for S3 integration topic
resource "aws_sns_topic_policy" "s3_integration_policy" {
  arn = aws_sns_topic.s3_integration_topic.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSESPublish"
        Effect = "Allow"
        Principal = {
          Service = "ses.amazonaws.com"
        }
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.s3_integration_topic.arn
      },
      {
        Sid    = "AllowPublicSubscribe"
        Effect = "Allow"
        Principal = "*"  # VULNERABILITY: Anyone can subscribe
        Action = [
          "sns:Subscribe"
        ]
        Resource = aws_sns_topic.s3_integration_topic.arn
      }
    ]
  })
}

# SES configuration set for S3 integration
resource "aws_ses_configuration_set" "vulnerable_ses_config" {
  name = "${var.environment}-vulnerable-ses-config"
  
  # Note: aws_ses_configuration_set doesn't support tags
}

# SES event destination pointing to SNS
resource "aws_ses_event_destination" "sns_events" {
  name                   = "sns-events"
  configuration_set_name = aws_ses_configuration_set.vulnerable_ses_config.name
  enabled                = true

  sns_destination {
    topic_arn = aws_sns_topic.s3_integration_topic.arn
  }

  matching_types = [
    "send",
    "reject",
    "bounce",
    "complaint",
    "delivery"
  ]
}

# Create secrets for the Lambda function to access
resource "aws_secretsmanager_secret" "sensitive_data" {
  name = "${var.environment}-sensitive-database-credentials"

  tags = {
    Environment = var.environment
    Purpose     = "Sensitive database credentials"
  }
}

resource "aws_secretsmanager_secret_version" "sensitive_data_version" {
  secret_id = aws_secretsmanager_secret.sensitive_data.id
  secret_string = jsonencode({
    username = "admin"
    password = "SuperSecretPassword123!"
    database = "production-db"
    host     = "prod-db.internal.company.com"
  })
}

# RDS instance that the Lambda function can access
resource "aws_db_instance" "vulnerable_database" {
  count = var.create_database ? 1 : 0

  identifier     = "${var.environment}-vulnerable-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = "testdb"
  username = "admin"
  password = "ChangeMe123!"  # VULNERABILITY: Weak password

  vpc_security_group_ids = [aws_security_group.database_sg[0].id]
  skip_final_snapshot    = true

  tags = {
    Environment = var.environment
    Purpose     = "Vulnerable database"
  }
}

variable "create_database" {
  description = "Whether to create the RDS database (incurs costs)"
  type        = bool
  default     = false
}

# Security group for database - overly permissive
resource "aws_security_group" "database_sg" {
  count = var.create_database ? 1 : 0

  name_prefix = "${var.environment}-db-sg"
  
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABILITY: Open to internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = var.environment
    Purpose     = "Vulnerable database security group"
  }
}

# IAM role for red team testing
resource "aws_iam_role" "redteam_escalation_role" {
  name = "${var.environment}-redteam-escalation"

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
    Purpose     = "Red team privilege escalation testing"
  }
}

# Limited permissions that can be escalated
resource "aws_iam_role_policy" "redteam_initial_policy" {
  name = "${var.environment}-redteam-initial"
  role = aws_iam_role.redteam_escalation_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:ListTopics",
          "sns:GetTopicAttributes",
          "sns:Publish",
          "sns:Subscribe"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ses:ListIdentities",
          "ses:GetIdentityAttributes",
          "ses:SendEmail"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage"
        ]
        Resource = aws_sqs_queue.vulnerable_processing_queue.arn
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

# Outputs for red team testing
output "vulnerable_sns_topic_arn" {
  description = "ARN of vulnerable SNS topic"
  value       = aws_sns_topic.vulnerable_trigger_topic.arn
}

output "privileged_lambda_arn" {
  description = "ARN of privileged Lambda function"
  value       = aws_lambda_function.privileged_processor.arn
}

output "vulnerable_sqs_queue_url" {
  description = "URL of vulnerable SQS queue"
  value       = aws_sqs_queue.vulnerable_processing_queue.id
}

output "vulnerable_s3_bucket" {
  description = "Name of vulnerable S3 bucket"
  value       = aws_s3_bucket.vulnerable_data_bucket.bucket
}

output "cross_account_role_arn" {
  description = "ARN of cross-account role"
  value       = aws_iam_role.cross_account_role.arn
}

output "redteam_role_arn" {
  description = "ARN of red team role"
  value       = aws_iam_role.redteam_escalation_role.arn
}

output "secrets_manager_secret_arn" {
  description = "ARN of secrets manager secret"
  value       = aws_secretsmanager_secret.sensitive_data.arn
}

output "escalation_attack_examples" {
  description = "Examples of privilege escalation attacks"
  value = <<-EOT
    Privilege Escalation Attack Examples:
    
    1. SNS → Lambda Privilege Escalation:
    aws sns publish --topic-arn ${aws_sns_topic.vulnerable_trigger_topic.arn} \
      --message '{"command": "list_secrets"}'
    
    2. Cross-Service Role Assumption:
    aws sns publish --topic-arn ${aws_sns_topic.vulnerable_trigger_topic.arn} \
      --message '{"command": "assume_role", "role_arn": "${aws_iam_role.cross_account_role.arn}"}'
    
    3. S3 Data Access:
    aws sns publish --topic-arn ${aws_sns_topic.vulnerable_trigger_topic.arn} \
      --message '{"command": "read_s3", "bucket": "${aws_s3_bucket.vulnerable_data_bucket.bucket}"}'
    
    4. SQS Message Injection:
    aws sqs send-message --queue-url ${aws_sqs_queue.vulnerable_processing_queue.id} \
      --message-body '{"exploit": "payload"}'
    
    5. Use SESNSploit to enumerate and exploit:
    python3 main.py
    # Use discovered information to chain attacks
  EOT
}
