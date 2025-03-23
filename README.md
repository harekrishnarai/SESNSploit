# SESNSploit

A tool for identifying and exploiting misconfigurations in AWS SNS and SES services.

## Demo

![SESNSploit Demo](/media/demo.gif)

## Overview

SESNSploit is designed to perform various reconnaissance and exploitation tasks related to AWS Simple Notification Service (SNS) and Simple Email Service (SES). It provides a user-friendly interface to check for active regions, inspect topic attributes, list subscriptions, send messages, and detect misconfigurations.

## Main Script

The main script for this tool is `main.py`. It includes various functionalities to interact with AWS SNS and SES services, manage AWS profiles, and maintain state across sessions.

## Functionalities

### AWS Profile Selection

The tool allows you to select an AWS profile from your configured profiles. If no profile is selected, the default profile is used.

### State Management

The tool saves its state in a `state.json` file, allowing you to resume your session later. The state includes information about the last selected AWS profile, active regions, and retrieved SNS topics and SES identities.

### SNS Operations

- **Check Active Regions:** Identifies which AWS regions have SNS services active.
- **List SNS Topics:** Retrieves SNS topics from each active region.
- **Get SNS Topic Attributes:** Retrieves and displays the attributes of a specified SNS topic.
- **List Subscriptions:** Lists all subscriptions for a given SNS topic.
- **Send a Message:** Sends a message to a specified SNS topic, useful for testing or demonstration purposes.
- **Create an SNS Topic:** Creates a new SNS topic in a specified region.
- **Subscribe to an SNS Topic:** Subscribes an endpoint to a specified SNS topic.
- **Simulate SNS Policy Assessment:** Assesses SNS topic policies for overly permissive configurations.

### SES Operations

- **Check Active Regions:** Identifies which AWS regions have SES services active.
- **List Verified Identities:** Retrieves SES email identities from each active region.
- **Get Identity Verification Attributes:** Retrieves and displays the verification attributes of a specified SES identity.
- **Simulate SES Send Email:** Sends a test email via SES to a specified destination.

### Other Operations

- **Brute-Force Check Regions:** Attempts to check all AWS regions for SNS and SES activity.
- **Check for SNS Topic Misconfigurations:** Looks for potentially insecure configurations in SNS topics.

## Usage

### Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/harekrishnarai/SESNSploit
   cd SESNSploit
   ```

2. **Install Dependencies:**

   Ensure you have Python 3 installed. Then install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

3. **Setup AWS Credentials:**

   Make sure your AWS CLI is configured with the appropriate credentials. You can do this by running:

   ```bash
   aws configure
   ```

   Enter your AWS Access Key ID, Secret Access Key, region, and output format as prompted.

### Running the Script

- Execute the script with:

  ```bash
  python main.py
  ```

- You will be greeted with a menu offering several options:

  ```
  1. Check Active Regions for SNS
  2. Check Active Regions for SES
  3. List SNS Topics in Active Regions
  4. Get SNS Topic Attributes
  5. List Subscriptions for an SNS Topic
  6. Send a Message to an SNS Topic
  7. Create an SNS Topic
  8. Subscribe to an SNS Topic
  9. List Verified SES Identities
  10. Get SES Identity Verification Attributes
  11. Brute-Force Check Regions for SNS and SES
  12. Check for SNS Topic Misconfigurations
  13. Simulated Red Teaming: Assess SNS Access Policies
  14. Simulated Red Teaming: Attempt to Send Test Email via SES
  0. Exit
  ```

- Choose your option by entering the corresponding number.

### Important Notes

- **Ethical Use:** This tool should only be used on systems you have permission to test. Unauthorized use is illegal and unethical.
- **AWS Rate Limits:** Be aware of AWS API rate limits. The script includes small delays to mitigate this, but you might need to adjust based on your specific use case.
- **Permissions:** Ensure your AWS credentials have the necessary permissions to perform these actions.

## Disclaimer

This tool is provided for educational and ethical security testing purposes only. The author and contributors are not responsible for any misuse or damage caused by this software.

## Copyright

© 2025 Harekrishna Rai. All rights reserved.
