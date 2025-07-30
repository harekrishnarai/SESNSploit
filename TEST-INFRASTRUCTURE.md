# SESNSploit Test Infrastructure

This directory contains Terraform configurations to create test data and infrastructure for the SESNSploit tool. The infrastructure creates various SNS topics, SES identities, and related AWS resources that can be used to test and demonstrate the tool's capabilities.

## 📋 Prerequisites

1. **AWS CLI configured** with appropriate credentials
2. **Terraform installed** (version 1.0 or later)
3. **Domain ownership** - You must control a domain for SES testing
4. **AWS permissions** to create SNS, SES, Lambda, IAM, and S3 resources

## 🚀 Quick Start

### 1. Configure Variables

Copy the example variables file and customize it:
```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and set your domain:
```hcl
test_email_domain = "yourdomain.com"  # Replace with your domain
environment = "your-test-env"
```

### 2. Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Deploy the infrastructure
terraform apply
```

### 3. Complete SES Verification

After deployment, you'll need to verify your domain and email addresses:

1. **Domain Verification**: Add the TXT record shown in the output to your DNS
2. **Email Verification**: Check your email for verification links from AWS

### 4. Test SESNSploit

Use the provided test commands from the Terraform output:
```bash
# Assume a test role and run SESNSploit
aws sts assume-role --role-arn <ROLE_ARN> --role-session-name SESNSpliotTest
python3 main.py
```

## 🏗️ Infrastructure Components

### SNS Resources
- **Multiple Topics**: Notifications, alerts, admin, and public topics
- **Cross-Region Topics**: Topics in US East, US West, and EU regions
- **Various Policies**: From secure to intentionally vulnerable
- **Subscriptions**: SQS, Lambda, and HTTP endpoint subscriptions

### SES Resources
- **Email Identities**: Multiple test email addresses
- **Domain Identity**: Full domain verification setup
- **Configuration Sets**: Event tracking and monitoring
- **Email Templates**: Pre-configured templates for testing
- **Receipt Rules**: Email processing and routing rules

### Supporting Infrastructure
- **Lambda Functions**: SNS message processors
- **SQS Queues**: Message queues for testing subscriptions
- **S3 Buckets**: Email storage and event logging
- **IAM Roles**: Various permission levels for testing

### Test Roles
1. **SNS-Only Role**: Limited to SNS operations
2. **SES-Only Role**: Limited to SES operations  
3. **Combined Role**: Full SNS and SES permissions

## 🔧 Configuration Options

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `primary_region` | Main AWS region | `us-east-1` | No |
| `environment` | Environment name for tagging | `sesnsloit-test` | No |
| `test_email_domain` | Domain for SES testing | `test.example.com` | **Yes** |
| `create_cross_region_resources` | Deploy in multiple regions | `true` | No |
| `create_vulnerable_configs` | Create vulnerable configurations | `true` | No |

### Deployment Scenarios

#### Minimal Setup (Cost Optimized)
```hcl
primary_region = "us-east-1"
create_cross_region_resources = false
create_vulnerable_configs = false
```

#### Full Testing Setup
```hcl
primary_region = "us-east-1" 
create_cross_region_resources = true
create_vulnerable_configs = true
```

#### Production-Like Testing
```hcl
primary_region = "us-east-1"
create_cross_region_resources = true
create_vulnerable_configs = false
```

## 🧪 Testing Scenarios

### 1. Basic Enumeration Test
```bash
# Test topic discovery across regions
python3 main.py
# Select: List SNS active regions
# Select: List SNS topics in active regions
```

### 2. Permission Testing
```bash
# Assume different roles to test permission boundaries
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/ENV-sns-test-SUFFIX --role-session-name SNSTest
python3 main.py
```

### 3. Vulnerability Testing
```bash
# Test against vulnerable configurations (if enabled)
python3 main.py
# Look for topics with overly permissive policies
```

### 4. Cross-Service Integration Testing
```bash
# Test SNS-Lambda integration
aws sns publish --topic-arn TOPIC_ARN --message "Test message"
# Check Lambda logs for processing
```

### 5. SES Testing
```bash
# Test email sending capabilities
python3 main.py
# Select SES options to test email identities and sending
```

## 🔍 What SESNSploit Will Discover

After deployment, SESNSploit should discover:

### SNS Resources
- 3-6 SNS topics (depending on configuration)
- Topics across multiple regions (if enabled)
- Various subscription types (SQS, Lambda, HTTP)
- Different permission policies

### SES Resources  
- Domain identity with verification status
- Multiple email identities
- Configuration sets and event destinations
- Email templates
- Receipt rules (in supported regions)

### Integration Points
- SNS→Lambda subscriptions
- SNS→SQS subscriptions  
- SES→SNS event notifications
- SES→S3 storage integration

## 🛡️ Security Considerations

### Vulnerable Configurations (Optional)
When `create_vulnerable_configs = true`, the infrastructure includes:
- SNS topics with public access policies
- HTTP endpoint subscriptions
- Overly permissive IAM roles

**⚠️ Warning**: Only enable vulnerable configurations in isolated test environments.

### Secure Configurations
Even in test mode, the infrastructure includes secure examples:
- Properly scoped IAM policies
- Encrypted storage options
- Secure subscription patterns

## 💰 Cost Optimization

### Cost-Conscious Deployment
- Set `create_cross_region_resources = false` for single-region testing
- Set `create_database = false` in attack scenarios (default)
- Use minimal instance types where applicable

### Resource Cleanup
```bash
# Destroy all test infrastructure
terraform destroy
```

### Cost Breakdown
- SNS topics: Free tier covers testing
- SES: Pay per email sent (very low for testing)
- Lambda: Free tier covers testing
- S3: Minimal storage costs
- Cross-region resources: Multiply base costs by regions

## 🔧 Troubleshooting

### Common Issues

#### Domain Verification Fails
- Ensure you own the domain specified in `test_email_domain`
- Add the TXT record to your DNS as shown in Terraform output
- DNS propagation can take up to 48 hours

#### Email Verification Fails
- Check spam folders for verification emails
- Ensure email addresses at your domain can receive mail
- Try verifying through AWS Console if links don't work

#### SESNSploit Finds No Resources
- Check AWS credentials are properly configured
- Verify you're looking in the correct regions
- Some resources may need time to propagate

#### Permission Denied Errors
- Ensure your AWS credentials have sufficient permissions
- Check if you're using the correct test role ARNs
- Review IAM policies for required permissions

### Terraform Issues

#### State File Conflicts
```bash
# If multiple people are testing
terraform workspace new your-name
terraform workspace select your-name
```

#### Resource Already Exists
```bash
# If resources exist from previous runs
terraform import <resource_type>.<resource_name> <resource_id>
```

## 📚 Additional Resources

### SESNSploit Documentation
- Main tool documentation: `README.md`
- Attack scenarios: `attack-scenarios/README.md`

### AWS Documentation
- [SNS Documentation](https://docs.aws.amazon.com/sns/)
- [SES Documentation](https://docs.aws.amazon.com/ses/)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

### Terraform Resources
- [AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Terraform Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)

## 🤝 Contributing

To contribute improvements to the test infrastructure:

1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request with detailed description

## 📄 License

This test infrastructure is part of the SESNSploit project and follows the same licensing terms.

---

**⚠️ Disclaimer**: This infrastructure is designed for authorized security testing only. Always ensure you have proper authorization before testing against any AWS environment.
