# Snare

A tool for identifying and exploiting misconfigurations in AWS SNS and SES services.

## Overview

Snare is designed to perform various reconnaissance and exploitation tasks related to AWS Simple Notification Service (SNS) and Simple Email Service (SES). It provides a user-friendly interface to check for active regions, inspect topic attributes, list subscriptions, send messages, and detect misconfigurations.

## Usage

### Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/harekrishnarai/snare
   cd snare
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
  python snare.py
  ```

- You will be greeted with a menu offering several options:

  ```
  1. Check Active Regions for SNS
  2. Check Active Regions for SES
  3. Get SNS Topic Attributes
  4. List Subscriptions for an SNS Topic
  5. Send a Message to an SNS Topic
  6. Brute-Force Check Regions for SNS and SES
  7. Check for SNS Topic Misconfigurations
  8. Exit
  ```

- Choose your option by entering the corresponding number.

### Options Explained

- **Check Active Regions:** Identifies which AWS regions have SNS or SES services active.
- **Get SNS Topic Attributes:** Retrieves and displays the attributes of a specified SNS topic.
- **List Subscriptions:** Lists all subscriptions for a given SNS topic.
- **Send a Message:** Sends a message to a specified SNS topic, useful for testing or demonstration purposes.
- **Brute-Force Check Regions:** Attempts to check all AWS regions for SNS and SES activity.
- **Check for SNS Topic Misconfigurations:** Looks for potentially insecure configurations in SNS topics.

### Important Notes

- **Ethical Use:** This tool should only be used on systems you have permission to test. Unauthorized use is illegal and unethical.
- **AWS Rate Limits:** Be aware of AWS API rate limits. The script includes small delays to mitigate this, but you might need to adjust based on your specific use case.
- **Permissions:** Ensure your AWS credentials have the necessary permissions to perform these actions.

## Disclaimer

This tool is provided for educational and ethical security testing purposes only. The author and contributors are not responsible for any misuse or damage caused by this software.

## Copyright

© 2025 Harekrishna Rai. All rights reserved.



Remember to replace `<your-repository-url>` with the actual URL of your repository and adjust the year in the copyright notice if necessary. Also, if you have a specific license you wish to use, add the appropriate license text or link to the license file in your repository.
