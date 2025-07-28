# Attack Scenario 2: SES Identity Spoofing

## Overview
This attack scenario demonstrates how an attacker with SES permissions can spoof email identities to send phishing emails, impersonate legitimate services, or conduct social engineering attacks.

## Attack Vector
- **Target**: Misconfigured SES identities with overly permissive sending policies
- **Method**: Verify and use unauthorized email identities for malicious purposes
- **Impact**: Phishing attacks, reputation damage, social engineering, business email compromise

## Prerequisites
- AWS credentials with SES permissions
- Ability to verify email identities or domains
- Knowledge of target email addresses or domains

## How to Use SESNSploit for This Attack

### Step 1: Reconnaissance
```bash
python3 main.py
# Select option for SES: List SES active regions
# Select option: List SES identities
# Select option: Get SES identity attributes
```

### Step 2: Identify Opportunities
Look for:
- Unverified but usable identities
- Domains with loose verification
- Sending policies that allow cross-account access
- Configuration templates with broad permissions

### Step 3: Execute the Attack
```bash
# Use SESNSploit to:
# 1. Verify a new identity (if permissions allow)
# 2. Send test emails to validate access
# 3. Craft phishing emails using legitimate-looking sender addresses
```

### Step 4: Advanced Exploitation
- Impersonate system notifications
- Send password reset requests
- Conduct spear-phishing campaigns
- Business email compromise (BEC)

## Attack Techniques

### 1. Domain Spoofing
- Verify similar domains (typosquatting)
- Use subdomains of legitimate domains
- Leverage internationalized domain names (IDN)

### 2. Display Name Spoofing
- Use legitimate display names with different email addresses
- Combine with domain spoofing for maximum effect

### 3. Template Abuse
- Modify existing SES templates
- Create malicious templates that appear legitimate
- Abuse template variables for payload injection

### 4. Cross-Account Abuse
- Use SES permissions to send on behalf of other accounts
- Exploit cross-account trust relationships

## Potential Impact
1. **Phishing Campaigns**: Mass credential harvesting
2. **Business Email Compromise**: Financial fraud via executive impersonation
3. **Reputation Damage**: Damage to legitimate domain reputation
4. **Social Engineering**: Targeted attacks using trusted sender addresses
5. **Lateral Movement**: Use email access to gain access to other systems

## Detection Indicators
- Unexpected email identity verifications
- Unusual sending patterns or volumes
- Emails from verified domains to unexpected recipients
- CloudTrail events: `VerifyEmailIdentity`, `VerifyDomainIdentity`, `SendEmail`, `SendRawEmail`
- High bounce rates or spam complaints
- DMARC/SPF failures from legitimate domains
