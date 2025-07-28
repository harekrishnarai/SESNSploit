# Attack Scenario 5: Configuration and Data Extraction

## Overview
This attack scenario demonstrates how an attacker with read permissions on SNS/SES can extract sensitive configuration data, subscription details, and use this information for reconnaissance and further attacks.

## Attack Vector
- **Target**: SNS/SES configuration data, policies, and metadata
- **Method**: Extract detailed configuration information to understand the environment and identify vulnerabilities
- **Impact**: Information disclosure, reconnaissance data for advanced attacks, credential exposure

## Prerequisites
- AWS credentials with read permissions on SNS/SES
- Understanding of AWS configuration structures
- Knowledge of sensitive data patterns

## How to Use SESNSploit for This Attack

### Step 1: Comprehensive Enumeration
```bash
python3 main.py
# Use all available SESNSploit options to gather:
# - All active regions for SNS/SES
# - Complete topic and identity listings
# - Detailed attribute information
# - Subscription and configuration details
```

### Step 2: Deep Configuration Analysis
Extract detailed information about:
- Resource policies and permissions
- Cross-account access patterns
- Service integrations and dependencies
- Encryption configurations
- Monitoring and logging setups

### Step 3: Data Correlation and Analysis
- Map relationships between resources
- Identify security gaps and misconfigurations
- Document access patterns for exploitation
- Prepare intelligence for advanced attacks

## Information Extraction Targets

### SNS Configuration Data
1. **Topic Attributes**
   - Topic ARNs and names
   - Access policies and permissions
   - Subscription counts and types
   - Encryption settings
   - Delivery policies

2. **Subscription Details**
   - Endpoint information (emails, URLs, phone numbers)
   - Protocol types and configurations
   - Subscription ARNs
   - Filter policies
   - Dead letter queue configurations

3. **Cross-Service Integrations**
   - Lambda function ARNs
   - SQS queue URLs
   - HTTP/HTTPS endpoints
   - Platform application ARNs

### SES Configuration Data
1. **Identity Information**
   - Verified email addresses and domains
   - DKIM configurations
   - Bounce and complaint handling
   - Notification preferences

2. **Sending Statistics**
   - Send quotas and rates
   - Bounce and complaint rates
   - Reputation metrics
   - Sending history patterns

3. **Configuration Sets**
   - Event destinations
   - Tracking options
   - Reputation tracking settings
   - IP pool assignments

4. **Receipt Rules**
   - Rule sets and priorities
   - Condition matching
   - Action configurations
   - S3 bucket destinations

## Sensitive Data Patterns

### Credential Exposure
- Embedded access keys in policies
- External service credentials in configurations
- Database connection strings in Lambda environment variables
- API keys in notification endpoints

### Network Information
- Internal IP addresses and CIDR blocks
- VPC configurations
- Security group references
- Load balancer endpoints

### Business Intelligence
- Email addresses of key personnel
- Organizational structure from distribution lists
- Business process flows from notification chains
- Partner and vendor relationships

### Infrastructure Details
- Account IDs and resource ARNs
- Region deployment patterns
- Service architecture and dependencies
- Backup and disaster recovery configurations

## Advanced Extraction Techniques

### 1. Policy Mining
```bash
# Extract and analyze all resource policies
aws sns get-topic-attributes --topic-arn <topic-arn>
aws ses get-identity-policies --identity <identity>
```

### 2. Subscription Enumeration
```bash
# Map all subscriptions and endpoints
aws sns list-subscriptions
aws sns list-subscriptions-by-topic --topic-arn <topic-arn>
```

### 3. Cross-Account Discovery
```bash
# Identify cross-account access patterns
aws sts get-caller-identity
# Analyze policies for cross-account principals
```

### 4. Template and Configuration Analysis
```bash
# Extract email templates and configurations
aws ses list-templates
aws ses get-template --template-name <template-name>
```

## Data Exfiltration Methods

### 1. Direct API Extraction
- Use AWS CLI/SDK to systematically extract all accessible data
- Automate data collection with scripts
- Store extracted data in structured formats

### 2. Subscription-Based Exfiltration
- Subscribe own endpoints to SNS topics
- Monitor message flow and content
- Extract data from email notifications

### 3. Template Abuse
- Use existing templates to send data to external endpoints
- Modify templates to include sensitive configuration data
- Exploit template variables for data extraction

### 4. Event Monitoring
- Monitor SES events for business intelligence
- Track email patterns and recipients
- Analyze bounce/complaint data for insights

## Intelligence Gathering Applications

### 1. Attack Surface Mapping
- Identify all connected services and endpoints
- Map trust relationships and permissions
- Document potential attack vectors

### 2. Business Process Understanding
- Analyze notification flows to understand business processes
- Identify critical communication channels
- Map organizational structure from email patterns

### 3. Vulnerability Assessment
- Identify misconfigurations and security gaps
- Find overly permissive policies
- Locate unencrypted data flows

### 4. Social Engineering Preparation
- Extract email addresses for phishing campaigns
- Understand communication patterns
- Identify high-value targets from subscription patterns

## Tools and Automation

### Custom Scripts for Data Extraction
```python
import boto3
import json

def extract_sns_data(session):
    """Extract comprehensive SNS configuration data"""
    sns = session.client('sns')
    
    # Extract topics, subscriptions, and policies
    topics = sns.list_topics()
    for topic in topics['Topics']:
        attributes = sns.get_topic_attributes(TopicArn=topic['TopicArn'])
        subscriptions = sns.list_subscriptions_by_topic(TopicArn=topic['TopicArn'])
        # Process and store data
```

### SESNSploit Integration
- Use SESNSploit as a foundation for systematic extraction
- Extend functionality for specific intelligence requirements
- Automate data correlation and analysis

## Detection Indicators
- High volume of describe/list API calls
- Systematic enumeration across regions
- Unusual read patterns on sensitive resources
- Multiple GetTopicAttributes/GetIdentityPolicies calls
- Bulk subscription listing activities
- Automated tool signatures in CloudTrail logs
