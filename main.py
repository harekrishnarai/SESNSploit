#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError
import pyfiglet
import time

# Your name for copyright
COPYRIGHT_OWNER = "Harekrishna Rai"

regions = [
    'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ca-central-1', 'eu-central-1',
    'eu-central-2', 'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-west-1', 'eu-west-2',
    'eu-west-3', 'me-central-1', 'me-south-1', 'sa-east-1', 'us-east-1', 'us-east-2',
    'us-west-1', 'us-west-2'
]

def figlet_header():
    ascii_art = pyfiglet.figlet_format("Snare", font = "slant")
    print(ascii_art)
    print(f"Copyright © {COPYRIGHT_OWNER}")

def check_service_in_region(service, region):
    try:
        if service == 'sns':
            client = boto3.client('sns', region_name=region)
            client.list_topics()
        elif service == 'ses':
            client = boto3.client('ses', region_name=region)
            client.list_identities()
        print(f"{service.upper()} is active in {region}")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            print(f"Credentials are not valid for {service.upper()} in {region}")
        else:
            print(f"{service.upper()} is not active in {region}")
        return False

def list_active_regions(service):
    active_regions = []
    for region in regions:
        if check_service_in_region(service, region):
            active_regions.append(region)
    return active_regions

def get_topic_attributes():
    topic_arn = input("Enter the ARN of the topic to check attributes: ")
    try:
        sns = boto3.client('sns')
        attributes = sns.get_topic_attributes(TopicArn=topic_arn)
        print(f"Attributes of Topic {topic_arn}:")
        for key, value in attributes['Attributes'].items():
            print(f"  {key}: {value}")
    except ClientError as e:
        print(f"Error: {e.response['Error']['Message']}")

def list_subscriptions():
    topic_arn = input("Enter the ARN of the topic to list subscriptions: ")
    try:
        sns = boto3.client('sns')
        subscriptions = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
        print(f"Subscriptions for {topic_arn}:")
        for sub in subscriptions['Subscriptions']:
            print(f"  - {sub['SubscriptionArn']}")
    except ClientError as e:
        print(f"Error: {e.response['Error']['Message']}")

def send_message():
    topic_arn = input("Enter the ARN of the topic to send message: ")
    message = input("Enter the message to send: ")
    try:
        sns = boto3.client('sns')
        response = sns.publish(TopicArn=topic_arn, Message=message)
        print(f"Message ID: {response['MessageId']}")
    except ClientError as e:
        print(f"Error: {e.response['Error']['Message']}")

def brute_force_regions():
    print("Brute-forcing regions for SNS and SES:")
    for region in regions:
        check_service_in_region('sns', region)
        check_service_in_region('ses', region)

def check_sns_misconfigurations():
    print("Checking for SNS misconfigurations:")
    sns = boto3.client('sns')
    for region in regions:
        try:
            topics = sns.list_topics()['Topics']
            for topic in topics:
                attributes = sns.get_topic_attributes(TopicArn=topic['TopicArn'])
                policy = attributes['Attributes'].get('Policy')
                if policy:
                    print(f"Topic {topic['TopicArn']} has a policy:")
                    print(policy)
                else:
                    print(f"Topic {topic['TopicArn']} has no explicit policy set.")
        except ClientError:
            print(f"Error accessing topics in {region}.")

def main():
    figlet_header()
    while True:
        print("\n1. Check Active Regions for SNS")
        print("2. Check Active Regions for SES")
        print("3. Get SNS Topic Attributes")
        print("4. List Subscriptions for an SNS Topic")
        print("5. Send a Message to an SNS Topic")
        print("6. Brute-Force Check Regions for SNS and SES")
        print("7. Check for SNS Topic Misconfigurations")
        print("8. Exit")
        
        choice = input("Choose an option: ")

        if choice == '1':
            list_active_regions('sns')
        elif choice == '2':
            list_active_regions('ses')
        elif choice == '3':
            get_topic_attributes()
        elif choice == '4':
            list_subscriptions()
        elif choice == '5':
            send_message()
        elif choice == '6':
            brute_force_regions()
        elif choice == '7':
            check_sns_misconfigurations()
        elif choice == '8':
            print("Exiting program.")
            break
        else:
            print("Invalid option, please try again.")

        # Add a small delay to avoid rate limiting
        time.sleep(0.5)

if __name__ == "__main__":
    main()
