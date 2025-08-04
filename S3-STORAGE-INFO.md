# S3 Storage for Sensitive Files

## Overview

This document contains information about the S3 bucket where sensitive files that cannot be stored in the public GitHub repository are maintained.

## S3 Bucket Details

- **Bucket Name**: `sesnploit-terraform-state-1754301535`
- **Region**: `us-east-1`
- **Created**: August 4, 2025
- **Purpose**: Store terraform state files and other sensitive artifacts

## Security Configuration

### Encryption
- **Method**: AES256 Server-Side Encryption
- **Bucket Key**: Enabled for cost optimization
- **Status**: ✅ Enabled

### Versioning
- **Status**: ✅ Enabled
- **Purpose**: Track changes to terraform state files and maintain history

### Access Control
- **HTTPS Only**: ✅ Enforced via bucket policy
- **Public Access**: ❌ Blocked
- **Access Method**: AWS CLI with proper IAM credentials

## Files Stored

### Terraform State Files
```
terraform-states/
├── terraform.tfstate          # Current terraform state (182 bytes)
└── terraform.tfstate.backup   # Backup terraform state (61,861 bytes)
```

### Configuration Files
```
config/
└── terraform.tfvars          # Terraform variables with actual values (1,188 bytes)
```

### Artifacts
```
artifacts/
└── sns_processor.zip         # Lambda deployment package (495 bytes)
```

## Access Instructions

### Download All Files
```bash
# Set bucket name
BUCKET_NAME="sesnploit-terraform-state-1754301535"

# Create local directories
mkdir -p terraform-states config artifacts

# Download terraform state files
aws s3 cp s3://$BUCKET_NAME/terraform-states/terraform.tfstate ./terraform-states/
aws s3 cp s3://$BUCKET_NAME/terraform-states/terraform.tfstate.backup ./terraform-states/

# Download configuration
aws s3 cp s3://$BUCKET_NAME/config/terraform.tfvars ./config/

# Download artifacts
aws s3 cp s3://$BUCKET_NAME/artifacts/sns_processor.zip ./artifacts/
```

### Download Specific Files
```bash
# Download only terraform state
aws s3 cp s3://sesnploit-terraform-state-1754301535/terraform-states/terraform.tfstate ./

# Download only terraform variables
aws s3 cp s3://sesnploit-terraform-state-1754301535/config/terraform.tfvars ./

# Download Lambda package
aws s3 cp s3://sesnploit-terraform-state-1754301535/artifacts/sns_processor.zip ./
```

### List All Files in Bucket
```bash
aws s3 ls s3://sesnploit-terraform-state-1754301535/ --recursive
```

### Sync Entire Bucket to Local Directory
```bash
aws s3 sync s3://sesnploit-terraform-state-1754301535/ ./s3-backup/
```

## File Descriptions

### terraform.tfstate
- **Purpose**: Current terraform state after infrastructure deployment
- **Size**: 182 bytes (infrastructure destroyed, minimal state)
- **Contains**: Resource tracking information
- **Security**: Contains AWS account ID and resource ARNs

### terraform.tfstate.backup
- **Purpose**: Previous terraform state when infrastructure was active
- **Size**: 61,861 bytes (full deployment state)
- **Contains**: Complete resource configuration and metadata
- **Security**: Contains AWS account ID, resource ARNs, IAM role details

### terraform.tfvars
- **Purpose**: Actual terraform variables used for deployment
- **Size**: 1,188 bytes
- **Contains**: Domain name (harekrishnarai.me), environment settings
- **Security**: Contains real domain and email addresses

### sns_processor.zip
- **Purpose**: Lambda function deployment package
- **Size**: 495 bytes
- **Contains**: Python code for SNS message processing
- **Security**: Contains application logic

## Why These Files Are Not in GitHub

### Security Reasons
1. **State Files**: Contain AWS account IDs, resource ARNs, and internal metadata
2. **terraform.tfvars**: Contains actual domain names and email addresses
3. **Sensitive Metadata**: May expose infrastructure details useful to attackers

### Best Practices
1. **Terraform State**: Should never be stored in version control
2. **Sensitive Variables**: Should be stored securely, not in public repositories
3. **Deployment Artifacts**: May contain environment-specific configurations

## Backup and Recovery

### Manual Backup Process
```bash
# Create timestamped backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
aws s3 sync s3://sesnploit-terraform-state-1754301535/ ./backup_$TIMESTAMP/
```

### Restore Process
```bash
# Upload files back to S3 if needed
aws s3 sync ./backup_$TIMESTAMP/ s3://sesnploit-terraform-state-1754301535/
```

## Security Considerations

### Access Requirements
- Valid AWS credentials with S3 access
- Appropriate IAM permissions for the bucket
- AWS CLI configured with correct region

### Monitoring
- Consider enabling CloudTrail for S3 access logging
- Set up CloudWatch alarms for unauthorized access attempts
- Review access patterns regularly

### Rotation
- Regularly review and rotate AWS access keys
- Monitor for any unauthorized bucket access
- Consider implementing bucket notifications for security events

## Emergency Procedures

### If Bucket is Compromised
1. Immediately revoke AWS access keys
2. Review CloudTrail logs for unauthorized access
3. Create new bucket with enhanced security
4. Migrate files to new secure location
5. Update access documentation

### If Files are Lost
1. Check bucket versioning for previous versions
2. Restore from local backups if available
3. Recreate terraform.tfvars from terraform.tfvars.example
4. Redeploy infrastructure to generate new state files

## Cost Optimization

- **Storage Class**: Standard (for frequently accessed files)
- **Versioning**: Enabled but consider lifecycle policies for old versions
- **Bucket Key**: Enabled to reduce KMS costs
- **Estimated Monthly Cost**: < $1 USD for current file sizes

---

**Note**: This bucket contains sensitive infrastructure information. Ensure proper AWS IAM permissions and secure access when working with these files.
