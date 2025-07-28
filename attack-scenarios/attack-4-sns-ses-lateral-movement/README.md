# Attack Scenario 4: SNS-SES Lateral Movement

## Overview
This attack scenario demonstrates how an attacker can move laterally between AWS services using SNS subscriptions and SES integrations as a pivot point to access additional services and resources.

## Attack Vector
- **Target**: Service interconnections and subscription chains between SNS, SES, and other AWS services
- **Method**: Use existing service integrations to pivot between services and gain access to new resources
- **Impact**: Extended persistence, access to additional services, data exfiltration across service boundaries

## Prerequisites
- Initial access to SNS or SES
- Knowledge of service interconnections
- Understanding of AWS service integration patterns

## How to Use SESNSploit for This Attack

### Step 1: Map Service Topology
```bash
python3 main.py
# Use SESNSploit to discover:
# - All SNS topics and their subscriptions
# - SES identities and their configurations
# - Connected services (Lambda, SQS, S3, etc.)
```

### Step 2: Identify Pivot Points
Look for:
- SNS topics with multiple service subscriptions
- SES rules that trigger other services
- Cross-service notification chains
- Shared resources between services

### Step 3: Execute Lateral Movement
Follow the service integration chains:
1. **SNS → Multiple Services**: Use topic subscriptions to reach new services
2. **SES → S3 → Lambda**: Chain through storage to compute services
3. **Service Mesh Traversal**: Move through interconnected services

## Lateral Movement Paths

### Path 1: SNS Topic Fan-Out
```
SNS Topic → [Lambda, SQS, HTTP Endpoint, Email, SMS]
```
- Start with SNS access
- Discover all subscribed services
- Use each subscription to access new services
- Chain permissions across service boundaries

### Path 2: SES Rule Set Chaining
```
SES → [S3, Lambda, SNS, SQS, WorkMail]
```
- Begin with SES access
- Exploit receipt rules and configuration sets
- Follow rule actions to reach other services
- Use gained access for further pivoting

### Path 3: Cross-Service Data Flow
```
SES → S3 (logs) → Lambda (processing) → DynamoDB (storage)
```
- Use SES to write data to S3
- Trigger Lambda through S3 events
- Access DynamoDB through Lambda permissions

### Path 4: Notification Chain Exploitation
```
Application → SNS → SQS → Lambda → RDS/ElastiCache
```
- Inject messages into notification chains
- Follow the data flow through services
- Exploit each service's permissions

## Advanced Techniques

### 1. Service Hopping
- Use legitimate service integrations to move between services
- Exploit trust relationships between services
- Avoid direct access by using service intermediaries

### 2. Permission Inheritance
- Leverage inherited permissions from service roles
- Use temporary credentials obtained through service access
- Chain role assumptions across services

### 3. Data Plane Pivoting
- Use data flowing between services as a pivot mechanism
- Inject malicious data that gets processed by other services
- Exploit data processing workflows

### 4. Event-Driven Lateral Movement
- Trigger events that cause other services to perform actions
- Use CloudWatch Events and EventBridge for movement
- Exploit event patterns and rules

## Service Integration Exploitation

### SNS Integration Points
- **Lambda Functions**: Execute code with function permissions
- **SQS Queues**: Access queue messages and dead letter queues
- **HTTP/HTTPS Endpoints**: Reach external systems
- **Email/SMS**: Contact users or trigger email-based workflows
- **Mobile Push**: Access mobile notification systems

### SES Integration Points
- **S3 Buckets**: Store and access email content and logs
- **Lambda Functions**: Process emails and execute custom logic
- **SNS Topics**: Trigger notifications based on email events
- **CloudWatch**: Access metrics and logs
- **WorkMail**: Integrate with corporate email systems

### Common Targets for Lateral Movement
1. **Databases**: RDS, DynamoDB, ElastiCache
2. **Storage**: S3, EFS, FSx
3. **Compute**: EC2, ECS, Fargate
4. **Analytics**: Redshift, EMR, Kinesis
5. **Security**: Secrets Manager, Parameter Store, KMS

## Persistence Mechanisms

### 1. Subscription Persistence
- Create persistent subscriptions that survive service restarts
- Use multiple subscription types for redundancy
- Hide subscriptions among legitimate ones

### 2. Configuration Backdoors
- Modify SES receipt rules for persistent access
- Create SNS topic policies that allow re-access
- Use email forwarding rules for persistence

### 3. Cross-Service Triggers
- Set up triggers that activate from normal business processes
- Use legitimate data flows to maintain access
- Create event-driven persistence mechanisms

## Detection Indicators
- Unusual patterns in service-to-service communication
- Unexpected subscriptions to SNS topics
- Abnormal SES rule configurations
- High volume of cross-service API calls
- Unusual data flows between services
- Unexpected Lambda function invocations
- Anomalous CloudWatch Events activity
