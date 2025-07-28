# AWS SNS/SES Red Team Attack Scenarios

This directory contains various attack scenarios that can be used by authorized corporate cloud red team assessments to test AWS SNS (Simple Notification Service) and SES (Simple Email Service) misconfigurations.

## Overview

The SESNSploit tool can be leveraged in multiple attack scenarios when AWS IAM keys are compromised. These scenarios demonstrate common misconfigurations and how they can be exploited for lateral movement, privilege escalation, and data exfiltration.

## Attack Scenarios

### Attack 1: SNS Topic Hijacking
**Directory**: `attack-1-sns-topic-hijacking/`
- **Objective**: Hijack SNS topics to intercept notifications or send malicious messages
- **Prerequisites**: Basic SNS permissions
- **Impact**: Information disclosure, message injection

### Attack 2: SES Identity Spoofing  
**Directory**: `attack-2-ses-identity-spoofing/`
- **Objective**: Spoof email identities to send phishing emails or impersonate legitimate services
- **Prerequisites**: SES send permissions
- **Impact**: Phishing, reputation damage, social engineering

### Attack 3: Cross-Service Privilege Escalation
**Directory**: `attack-3-cross-service-privilege-escalation/`
- **Objective**: Use SNS/SES permissions to escalate privileges to other AWS services
- **Prerequisites**: Limited SNS/SES permissions with cross-service roles
- **Impact**: Full account compromise, data breach

### Attack 4: SNS-SES Lateral Movement
**Directory**: `attack-4-sns-ses-lateral-movement/`
- **Objective**: Move laterally between services using SNS subscriptions and SES integration
- **Prerequisites**: SNS subscription permissions
- **Impact**: Service hopping, extended persistence

### Attack 5: Configuration and Data Extraction
**Directory**: `attack-5-configuration-extraction/`
- **Objective**: Extract sensitive configuration data and subscription details
- **Prerequisites**: Read permissions on SNS/SES
- **Impact**: Information disclosure, reconnaissance for further attacks

## How Red Teamers Can Use This Tool

### Initial Access Scenarios

1. **Compromised IAM Keys**: When you obtain AWS access keys through:
   - Code repositories (GitHub, GitLab)
   - Configuration files
   - Environment variables
   - Stolen credentials

2. **Instance Metadata Service (IMDS)**: When you have access to EC2 instances with attached IAM roles

3. **Cross-Account Role Assumption**: When you can assume roles across AWS accounts

### Lateral Movement Strategies

#### From SNS to Other Services
- **SNS → Lambda**: Subscribe Lambda functions to SNS topics for code execution
- **SNS → SQS**: Use SQS subscriptions to intercept messages
- **SNS → HTTP/S**: Subscribe external endpoints to exfiltrate data
- **SNS → SMS**: Send SMS notifications for social engineering

#### From SES to Other Services  
- **SES → S3**: Access S3 buckets through SES configuration templates
- **SES → Lambda**: Trigger Lambda functions through SES rules
- **SES → CloudWatch**: Access logs and metrics through SES integration

#### Privilege Escalation Paths
1. **Policy Attachment**: Use `iam:AttachUserPolicy` or `iam:AttachRolePolicy`
2. **Role Creation**: Create new roles with elevated permissions
3. **Resource-Based Policies**: Modify SNS topic or SES identity policies
4. **Cross-Service Roles**: Assume roles used by SNS/SES for other services

### Reconnaissance Phase

Before executing attacks, use the SESNSploit tool to:

1. **Enumerate Active Regions**: Identify which regions have SNS/SES enabled
2. **List Topics and Identities**: Catalog available resources
3. **Analyze Policies**: Review permissions and access controls
4. **Map Subscriptions**: Understand message flow and dependencies

### Execution Guidelines

1. **Start with Reconnaissance**: Always begin with enumeration
2. **Test Permissions**: Verify what actions you can perform
3. **Document Findings**: Keep track of discovered resources
4. **Escalate Gradually**: Move from least to most privileged actions
5. **Maintain Stealth**: Avoid triggering security alerts

## Prerequisites for Red Team Assessments

### Required AWS Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sns:*",
                "ses:*",
                "iam:GetUser",
                "iam:GetRole",
                "iam:ListRoles",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

### Tools and Dependencies
- AWS CLI configured with target credentials
- Python 3.7+ with boto3
- SESNSploit tool (this repository)
- Terraform for infrastructure deployment

## Legal and Ethical Considerations

⚠️ **IMPORTANT**: These attack scenarios are designed for authorized security testing only.

- Only use against systems you own or have explicit written permission to test
- Follow responsible disclosure practices for any vulnerabilities found
- Ensure proper documentation and approval before conducting assessments
- Comply with all applicable laws and regulations

## Getting Started

1. Clone this repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure AWS credentials
4. Choose an appropriate attack scenario
5. Deploy the vulnerable infrastructure using provided Terraform files
6. Execute the attack using SESNSploit tool
7. Apply the remediation using fix Terraform files

## Support and Contributions

For questions or contributions to these attack scenarios, please create an issue or pull request in this repository.

---
**Copyright © Harekrishna Rai**
