# Attack Scenario 3: Cross-Service Privilege Escalation

## Overview
This attack scenario demonstrates how an attacker with limited SNS/SES permissions can escalate privileges to access other AWS services through misconfigurations in cross-service trust relationships and resource-based policies.

## Attack Vector
- **Target**: Cross-service IAM roles and resource-based policies with overly permissive trust relationships
- **Method**: Abuse SNS/SES service integrations to assume roles or access resources in other services
- **Impact**: Complete account compromise, access to sensitive data, lateral movement across AWS services

## Prerequisites
- AWS credentials with SNS/SES permissions
- Knowledge of cross-service integrations
- Ability to create or modify SNS topics/SES configurations

## How to Use SESNSploit for This Attack

### Step 1: Reconnaissance
```bash
python3 main.py
# Use SESNSploit to enumerate:
# - Available SNS topics and their policies
# - SES identities and configuration sets
# - Cross-service subscriptions and integrations
```

### Step 2: Identify Escalation Paths
Look for:
- Lambda functions subscribed to SNS topics
- SQS queues with cross-service access
- S3 buckets used for SES notifications
- IAM roles with `sts:AssumeRole` permissions
- CloudWatch events triggered by SNS/SES

### Step 3: Execute Privilege Escalation
Common escalation paths:
1. **SNS → Lambda**: Trigger Lambda functions with malicious payloads
2. **SNS → SQS → Lambda**: Chain services for code execution
3. **SES → S3**: Access S3 buckets through bounce/complaint handling
4. **SES → Lambda**: Execute code through SES rule sets
5. **Cross-Account Role Assumption**: Use service-linked roles

## Attack Techniques

### 1. Lambda Function Hijacking
- Subscribe malicious endpoints to SNS topics that trigger Lambda
- Inject payloads through SNS message attributes
- Exploit Lambda environment variables or execution context

### 2. SQS Queue Poisoning
- Send messages to SQS queues that are processed by privileged services
- Exploit message visibility timeouts and DLQ configurations

### 3. S3 Bucket Access
- Use SES bounce/complaint notifications to write to S3
- Exploit S3 bucket policies that trust SNS/SES
- Access sensitive data stored in notification buckets

### 4. Cross-Account Role Assumption
- Abuse roles that trust SNS/SES services
- Exploit external ID misconfigurations
- Chain role assumptions across accounts

### 5. CloudWatch Events Manipulation
- Trigger CloudWatch events through SNS/SES activities
- Exploit event patterns that execute privileged actions

## Escalation Chains

### Chain 1: SNS → Lambda → IAM
1. Send malicious message to SNS topic
2. Lambda function processes message with elevated permissions
3. Lambda uses IAM permissions to access other services
4. Extract credentials or modify policies

### Chain 2: SES → S3 → Cross-Account
1. Configure SES to send notifications to S3 bucket
2. S3 bucket has cross-account access policies
3. Use S3 access to assume roles in other accounts
4. Gain access to additional AWS accounts

### Chain 3: SNS → SQS → Data Processing
1. Send messages to SQS queue through SNS
2. SQS queue is processed by data processing service
3. Inject malicious data that gets processed with high privileges
4. Extract sensitive information or modify data

## Potential Impact
1. **Complete Account Takeover**: Full administrative access
2. **Data Exfiltration**: Access to sensitive databases and storage
3. **Resource Manipulation**: Modify or delete critical infrastructure
4. **Cross-Account Access**: Compromise multiple AWS accounts
5. **Persistent Access**: Create backdoors in multiple services

## Detection Indicators
- Unusual cross-service API calls
- Unexpected role assumptions
- High-privilege actions from service accounts
- CloudTrail events showing service-to-service access patterns
- Unusual Lambda function invocations
- Unexpected S3 bucket access patterns
