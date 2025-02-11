#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError
import pyfiglet
import time
import os
import colorama
from colorama import Fore, Back, Style
import random
import json  # For state saving

# Initialize colorama for cross-platform colored terminal text
colorama.init()

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
    print(Fore.RED + ascii_art + Style.RESET_ALL)
    print(f"{Fore.YELLOW}Copyright © {COPYRIGHT_OWNER}{Style.RESET_ALL}")

def list_available_profiles():
    profiles = []
    config_path = os.path.expanduser('~/.aws/config')
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            for line in f:
                if line.strip().startswith('[') and 'profile ' in line:
                    profiles.append(line.split('profile ')[1].strip()[:-1])  # Remove the closing bracket
    return profiles

def select_profile():
    profiles = list_available_profiles()
    if not profiles:
        print(f"{Fore.RED}No AWS profiles found in ~/.aws/config.{Style.RESET_ALL}")
        return None
    print(f"{Fore.CYAN}Available AWS Profiles:{Style.RESET_ALL}")
    for i, profile in enumerate(profiles, 1):
        print(f"{i}. {profile}")
    choice = input(f"{Fore.GREEN}Select profile number (or press Enter for default): {Style.RESET_ALL}")
    if choice == "":
        return None  # Use default profile
    try:
        return profiles[int(choice) - 1]
    except (ValueError, IndexError):
        print(f"{Fore.RED}Invalid selection. Using default profile.{Style.RESET_ALL}")
        return None

def loading_animation():
    animations = ['[■□□□□□□□□□]', '[■■□□□□□□□□]', '[■■■□□□□□□□]', '[■■■■□□□□□□]', '[■■■■■□□□□□]', '[■■■■■■□□□□]', '[■■■■■■■□□□]', '[■■■■■■■■□□]', '[■■■■■■■■■□]', '[■■■■■■■■■■]']
    for i in range(20):
        print(f"\r{animations[i % len(animations)]}", end='', flush=True)
        time.sleep(0.1)

def check_service_in_region(service, region, session):
    try:
        if service == 'sns':
            client = session.client('sns', region_name=region)
            client.list_topics()
        elif service == 'ses':
            client = session.client('ses', region_name=region)
            client.list_identities()
        print(f"{Fore.GREEN}{service.upper()} is active in {region}{Style.RESET_ALL}")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            print(f"{Fore.RED}Credentials are not valid for {service.upper()} in {region}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}{service.upper()} is not active in {region}{Style.RESET_ALL}")
        return False

def list_active_regions(service, session):
    active_regions = []
    print(f"{Fore.CYAN}Checking regions for {service.upper()}:{Style.RESET_ALL}")
    for region in regions:
        loading_animation()
        if check_service_in_region(service, region, session):
            active_regions.append(region)
    print("\n")
    return active_regions

def get_topic_attributes(session):
    topic_arn = input(f"{Fore.GREEN}Enter the ARN of the topic to check attributes: {Style.RESET_ALL}")
    try:
        sns = session.client('sns')
        attributes = sns.get_topic_attributes(TopicArn=topic_arn)
        print(f"{Fore.CYAN}Attributes of Topic {topic_arn}:{Style.RESET_ALL}")
        for key, value in attributes['Attributes'].items():
            print(f"  {key}: {value}")
    except ClientError as e:
        print(f"{Fore.RED}Error: {e.response['Error']['Message']}{Style.RESET_ALL}")

def list_subscriptions(session):
    topic_arn = input(f"{Fore.GREEN}Enter the ARN of the topic to list subscriptions: {Style.RESET_ALL}")
    try:
        sns = session.client('sns')
        subscriptions = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
        print(f"{Fore.CYAN}Subscriptions for {topic_arn}:{Style.RESET_ALL}")
        for sub in subscriptions['Subscriptions']:
            print(f"  - {sub['SubscriptionArn']}")
    except ClientError as e:
        print(f"{Fore.RED}Error: {e.response['Error']['Message']}{Style.RESET_ALL}")

def send_message(session):
    topic_arn = input(f"{Fore.GREEN}Enter the ARN of the topic to send message: {Style.RESET_ALL}")
    message = input(f"{Fore.GREEN}Enter the message to send: {Style.RESET_ALL}")
    try:
        sns = session.client('sns')
        response = sns.publish(TopicArn=topic_arn, Message=message)
        print(f"{Fore.CYAN}Message ID: {response['MessageId']}{Style.RESET_ALL}")
    except ClientError as e:
        print(f"{Fore.RED}Error: {e.response['Error']['Message']}{Style.RESET_ALL}")

def brute_force_regions(session):
    print(f"{Fore.CYAN}Brute-forcing regions for SNS and SES:{Style.RESET_ALL}")
    for region in regions:
        loading_animation()
        check_service_in_region('sns', region, session)
        check_service_in_region('ses', region, session)
    print("\n")

def check_sns_misconfigurations(session):
    print(f"{Fore.CYAN}Checking for SNS misconfigurations:{Style.RESET_ALL}")
    sns = session.client('sns')
    for region in regions:
        try:
            topics = sns.list_topics()['Topics']
            for topic in topics:
                loading_animation()
                attributes = sns.get_topic_attributes(TopicArn=topic['TopicArn'])
                policy = attributes['Attributes'].get('Policy')
                if policy:
                    print(f"\n{Fore.GREEN}Topic {topic['TopicArn']} has a policy:{Style.RESET_ALL}")
                    print(policy)
                else:
                    print(f"\n{Fore.YELLOW}Topic {topic['TopicArn']} has no explicit policy set.{Style.RESET_ALL}")
        except ClientError:
            print(f"\n{Fore.RED}Error accessing topics in {region}.{Style.RESET_ALL}")

def save_state(state, filename='state.json'):
    with open(filename, 'w') as f:
        json.dump(state, f)

def load_state(filename='state.json'):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return None

def main():
    figlet_header()
    profile_name = select_profile()
    
    if profile_name:
        session = boto3.Session(profile_name=profile_name)
    else:
        session = boto3.Session()

    state = load_state()
    if state:
        print(f"{Fore.YELLOW}Resuming from last saved state.{Style.RESET_ALL}")
    else:
        state = {'last_choice': None}

    while True:
        print(f"\n{Fore.BLUE}1. Check Active Regions for SNS 🔍")
        print("2. Check Active Regions for SES 🔍")
        print("3. Get SNS Topic Attributes 📊")
        print("4. List Subscriptions for an SNS Topic 📋")
        print("5. Send a Message to an SNS Topic 📩")
        print("6. Brute-Force Check Regions for SNS and SES 💣")
        print("7. Check for SNS Topic Misconfigurations 🚨")
        print("8. Exit 🚪{Style.RESET_ALL}")
        
        choice = input(f"{Fore.GREEN}Choose an option: {Style.RESET_ALL}")

        if choice == '1':
            list_active_regions('sns', session)
        elif choice == '2':
            list_active_regions('ses', session)
        elif choice == '3':
            get_topic_attributes(session)
        elif choice == '4':
            list_subscriptions(session)
        elif choice == '5':
            send_message(session)
        elif choice == '6':
            brute_force_regions(session)
        elif choice == '7':
            check_sns_misconfigurations(session)
        elif choice == '8':
            print(f"{Fore.YELLOW}Exiting program.{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid option, please try again.{Style.RESET_ALL}")

        state['last_choice'] = choice
        save_state(state)

        # Add a small delay to avoid rate limiting
        time.sleep(0.5)

if __name__ == "__main__":
    main()
