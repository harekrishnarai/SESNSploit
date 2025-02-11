#!/usr/bin/env python3
"""
This script simulates red teaming activities (e.g., assessing SNS policies or sending SES test emails)
while clearly storing and using region information along with each retrieved value.
"""

import boto3

from botocore.exceptions import ClientError, EndpointConnectionError
import pyfiglet
import time
import os
import colorama
from colorama import Fore, Style
import json  # Used for state saving
import platform  # Used for clearing the console

# Initialize colorama with automatic reset for colors
colorama.init(autoreset=True)

# Global Variables
COPYRIGHT_OWNER = "Harekrishna Rai"
regions = [
    'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ca-central-1', 'eu-central-1',
    'eu-central-2', 'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-west-1', 'eu-west-2',
    'eu-west-3', 'me-central-1', 'me-south-1', 'sa-east-1', 'us-east-1', 'us-east-2',
    'us-west-1', 'us-west-2'
]


# ----------------------- Utility Functions -----------------------

def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def pause():
    input(f"\n{Fore.GREEN}Press Enter to return to the main menu...{Style.RESET_ALL}")

def figlet_header():
    ascii_art = pyfiglet.figlet_format("Redsense", font="slant")
    print(Fore.RED + ascii_art + Style.RESET_ALL)
    print(f"{Fore.YELLOW}Copyright © {COPYRIGHT_OWNER}{Style.RESET_ALL}")

def list_available_profiles():
    profiles = []
    config_path = os.path.expanduser('~/.aws/config')
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            for line in f:
                if line.strip().startswith('[') and 'profile ' in line:
                    profiles.append(line.split('profile ')[1].strip()[:-1])
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
    if choice.strip() == "":
        return None
    try:
        return profiles[int(choice) - 1]
    except (ValueError, IndexError):
        print(f"{Fore.RED}Invalid selection. Using default profile.{Style.RESET_ALL}")
        return None

def loading_animation():
    animations = [
        '[■□□□□□□□□□]', '[■■□□□□□□□□]', '[■■■□□□□□□□]', '[■■■■□□□□□□]',
        '[■■■■■□□□□□]', '[■■■■■■□□□□]', '[■■■■■■■□□□]', '[■■■■■■■■□□]',
        '[■■■■■■■■■□]', '[■■■■■■■■■■]'
    ]
    for i in range(len(animations)):
        print(f"\r{animations[i]}", end='', flush=True)
        time.sleep(0.1)
    print("")  # New line after animation finishes

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
    except EndpointConnectionError as e:
        print(f"{Fore.YELLOW}Could not connect to {service.upper()} endpoint in {region}. Skipping this region. ({e}){Style.RESET_ALL}")
        return False
    except ClientError as e:
        if e.response['Error'].get('Code') == 'InvalidClientTokenId':
            print(f"{Fore.RED}Credentials are not valid for {service.upper()} in {region}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}{service.upper()} is not active in {region}: {e.response['Error'].get('Message', 'Unknown Error')}{Style.RESET_ALL}")
        return False

def list_active_regions(service, session):
    active_regions = []
    print(f"{Fore.CYAN}Checking regions for {service.upper()}... (Press Ctrl+C to cancel){Style.RESET_ALL}")
    try:
        for region in regions:
            loading_animation()  # Show animation for each region
            if check_service_in_region(service, region, session):
                active_regions.append(region)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user. Returning to main menu.{Style.RESET_ALL}")
        return active_regions
    return active_regions

# ----------------------- SNS Functions -----------------------

def list_topics_in_active_regions(session, active_regions):
    """
    Retrieves SNS topics from each active region and stores them as dictionaries:
    { "region": <region>, "arn": <topic_arn> }
    """
    topics = []
    if not active_regions:
        print(f"{Fore.RED}No active SNS regions available. Run option 1 for SNS region check first.{Style.RESET_ALL}")
        return topics
    try:
        for region in active_regions:
            try:
                sns = session.client('sns', region_name=region)
                region_topics = sns.list_topics().get('Topics', [])
                if region_topics:
                    print(f"{Fore.CYAN}SNS Topics in {region}:{Style.RESET_ALL}")
                    for topic in region_topics:
                        topic_arn = topic.get('TopicArn')
                        print(f"  - {topic_arn}")
                        topics.append({"region": region, "arn": topic_arn})
                else:
                    print(f"{Fore.YELLOW}No SNS topics found in {region}.{Style.RESET_ALL}")
            except ClientError as e:
                print(f"{Fore.RED}Error accessing topics in {region}: {e.response['Error']['Message']}{Style.RESET_ALL}")
    except KeyboardInterrupt:
         print(f"\n{Fore.YELLOW}Operation cancelled by user. Returning to main menu.{Style.RESET_ALL}")
         return topics
    return topics

def get_topic_attributes(session, state):
    """
    Uses the saved SNS topics (with region info) from state['sns_topics'] to allow the user
    to select one and view its attributes.
    """
    if 'sns_topics' not in state or not state['sns_topics']:
        print(f"{Fore.RED}No SNS topics found in saved state. Please enter the ARN manually.{Style.RESET_ALL}")
        topic_arn = input(f"{Fore.GREEN}Enter SNS topic ARN: {Style.RESET_ALL}").strip()
        topic_info = {"region": None, "arn": topic_arn}
    else:
        print(f"{Fore.CYAN}Saved SNS Topics:{Style.RESET_ALL}")
        for i, topic in enumerate(state['sns_topics'], 1):
            print(f"{i}. (Region: {topic['region']}) {topic['arn']}")
        choice = input(f"{Fore.GREEN}Select a topic number (or press Enter for manual entry): {Style.RESET_ALL}").strip()
        if choice == "":
            topic_arn = input(f"{Fore.GREEN}Enter SNS topic ARN: {Style.RESET_ALL}").strip()
            topic_info = {"region": None, "arn": topic_arn}
        else:
            try:
                index = int(choice) - 1
                if 0 <= index < len(state['sns_topics']):
                    topic_info = state['sns_topics'][index]
                else:
                    print(f"{Fore.RED}Invalid selection.{Style.RESET_ALL}")
                    pause()
                    return
            except ValueError:
                print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")
                pause()
                return

    # If region info is missing, ask the user to specify it.
    if not topic_info.get("region"):
        region = input(f"{Fore.GREEN}Enter region for SNS topic: {Style.RESET_ALL}").strip()
    else:
        region = topic_info["region"]
    try:
        sns = session.client('sns', region_name=region)
        attributes = sns.get_topic_attributes(TopicArn=topic_info['arn'])
        print(f"{Fore.CYAN}Attributes for SNS Topic {topic_info['arn']} (Region: {region}):{Style.RESET_ALL}")
        for key, value in attributes.get('Attributes', {}).items():
            print(f"  {key}: {value}")
    except ClientError as e:
        print(f"{Fore.RED}Error: {e.response['Error']['Message']}{Style.RESET_ALL}")

def simulate_sns_policy_assessment(session, state):
    """
    Simulated red teaming function that assesses SNS topic policies.
    It prints the policy of each saved SNS topic along with the region and flags overly permissive policies.
    """
    if 'sns_topics' not in state or not state['sns_topics']:
        print(f"{Fore.RED}No SNS topics in saved state. Please list topics first (Option 2).{Style.RESET_ALL}")
        return
    try:
        for topic in state['sns_topics']:
            region = topic.get("region")
            arn = topic.get("arn")
            sns = session.client('sns', region_name=region)
            attributes = sns.get_topic_attributes(TopicArn=arn)
            policy = attributes.get('Attributes', {}).get('Policy', "{}")
            print(f"\nTopic: {arn} (Region: {region})")
            print(f"Policy: {policy}")
            # Simulate assessment: warn if policy appears overly permissive
            if '"Effect":"Allow"' in policy and '"Principal":"*"' in policy:
                print(f"{Fore.RED}Warning: Overly permissive policy detected!")
            else:
                print(f"{Fore.GREEN}Policy appears to be locked down.")
    except ClientError as e:
        print(f"{Fore.RED}Error assessing policy: {e.response['Error']['Message']}{Style.RESET_ALL}")

def list_subscriptions(session, state):
    """
    Lists subscriptions for an SNS topic by prompting the user to select a topic.
    The SNS topics are stored in state['sns_topics'] as dictionaries with keys:
    "region" and "arn".
    """
    if not state.get("sns_topics"):
        print(f"{Fore.RED}No SNS topics found in saved state. Please fetch topics first by running option 2.{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}Saved SNS Topics:{Style.RESET_ALL}")
    for i, topic in enumerate(state["sns_topics"], 1):
        print(f"{i}. {topic['arn']} (Region: {topic['region']})")

    choice = input(f"{Fore.GREEN}Select a topic number to list its subscriptions: {Style.RESET_ALL}").strip()
    try:
        index = int(choice) - 1
        if index < 0 or index >= len(state["sns_topics"]):
            print(f"{Fore.RED}Invalid topic selection.{Style.RESET_ALL}")
            return
    except ValueError:
        print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")
        return

    topic_info = state["sns_topics"][index]
    region = topic_info["region"]
    topic_arn = topic_info["arn"]

    try:
        sns = session.client('sns', region_name=region)
        response = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
        subscriptions = response.get('Subscriptions', [])
        if not subscriptions:
            print(f"{Fore.YELLOW}No subscriptions found for topic: {topic_arn}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}Subscriptions for topic {topic_arn} in region {region}:{Style.RESET_ALL}")
            for sub in subscriptions:
                print(f"  - Endpoint: {sub.get('Endpoint', '-')}, Protocol: {sub.get('Protocol', '-')}, "
                      f"Subscription ARN: {sub.get('SubscriptionArn')}")
    except ClientError as e:
        print(f"{Fore.RED}Error retrieving subscriptions: {e.response['Error']['Message']}{Style.RESET_ALL}")

def send_sns_message(session, state):
    """
    Prompts the user to select an SNS topic (or enter one manually), then asks for a message
    (and optionally a subject), and publishes the message to the selected SNS topic.
    """
    # Determine topic ARN and region either from saved state or manual input
    if state.get('sns_topics'):
        print(f"{Fore.CYAN}Saved SNS Topics:{Style.RESET_ALL}")
        for idx, topic in enumerate(state['sns_topics']):
            print(f"{idx+1}. {topic['arn']} (Region: {topic['region']})")
        choice = input(f"{Fore.GREEN}Select a topic number to send a message (or press Enter for manual entry): {Style.RESET_ALL}").strip()
        if choice == "":
            topic_arn = input(f"{Fore.GREEN}Enter SNS topic ARN: {Style.RESET_ALL}").strip()
            region = input(f"{Fore.GREEN}Enter region for SNS topic: {Style.RESET_ALL}").strip()
        else:
            try:
                index = int(choice) - 1
                if index < 0 or index >= len(state['sns_topics']):
                    print(f"{Fore.RED}Invalid selection. Aborting message send.{Style.RESET_ALL}")
                    return
                selected_topic = state['sns_topics'][index]
                topic_arn = selected_topic['arn']
                region = selected_topic['region']
            except ValueError:
                print(f"{Fore.RED}Invalid input. Aborting message send.{Style.RESET_ALL}")
                return
    else:
        topic_arn = input(f"{Fore.GREEN}Enter SNS topic ARN: {Style.RESET_ALL}").strip()
        region = input(f"{Fore.GREEN}Enter region for SNS topic: {Style.RESET_ALL}").strip()

    # Prompt the user for message content
    message = input(f"{Fore.GREEN}Enter the message to send: {Style.RESET_ALL}").strip()
    subject = input(f"{Fore.GREEN}Enter subject (optional, press Enter to skip): {Style.RESET_ALL}").strip()

    try:
        sns = session.client('sns', region_name=region)
        publish_params = {
            "TopicArn": topic_arn,
            "Message": message
        }
        if subject:
            publish_params["Subject"] = subject
        response = sns.publish(**publish_params)
        print(f"{Fore.GREEN}Message sent to {topic_arn}. Message ID: {response.get('MessageId')}{Style.RESET_ALL}")
    except Exception as e:
        # Using a generic exception catch here, but you can narrow it down to ClientError if desired.
        print(f"{Fore.RED}Error sending message: {str(e)}{Style.RESET_ALL}")

def create_sns_topic(session, state):
    """
    Prompts the user for a region and topic name to create an SNS topic.
    On success, displays the new topic ARN and stores the topic into state['sns_topics'].
    """
    region = input(f"{Fore.GREEN}Enter region for new SNS topic: {Style.RESET_ALL}").strip()
    topic_name = input(f"{Fore.GREEN}Enter SNS topic name: {Style.RESET_ALL}").strip()
    try:
        sns = session.client('sns', region_name=region)
        response = sns.create_topic(Name=topic_name)
        topic_arn = response.get('TopicArn')
        if topic_arn:
            print(f"{Fore.GREEN}SNS Topic created successfully. Topic ARN: {topic_arn}{Style.RESET_ALL}")
            # Optionally add the new topic to state for later operations
            state.setdefault('sns_topics', []).append({"region": region, "arn": topic_arn})
        else:
            print(f"{Fore.RED}Failed to retrieve TopicArn. Please check the response.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error creating SNS topic: {str(e)}{Style.RESET_ALL}")

def subscribe_to_sns_topic(session, state):
    """
    Prompts the user to select an SNS topic (or enter one manually), then asks for the subscription protocol and endpoint,
    and subscribes the endpoint to the selected SNS topic.
    """
    if state.get('sns_topics'):
        print(f"{Fore.CYAN}Saved SNS Topics:{Style.RESET_ALL}")
        for idx, topic in enumerate(state['sns_topics']):
            print(f"{idx+1}. {topic['arn']} (Region: {topic['region']})")
        choice = input(f"{Fore.GREEN}Select a topic number to subscribe (or press Enter for manual entry): {Style.RESET_ALL}").strip()
        if choice == "":
            topic_arn = input(f"{Fore.GREEN}Enter SNS topic ARN: {Style.RESET_ALL}").strip()
            region = input(f"{Fore.GREEN}Enter region for SNS topic: {Style.RESET_ALL}").strip()
        else:
            try:
                index = int(choice) - 1
                if index < 0 or index >= len(state['sns_topics']):
                    print(f"{Fore.RED}Invalid selection. Aborting subscription.{Style.RESET_ALL}")
                    return
                selected_topic = state['sns_topics'][index]
                topic_arn = selected_topic['arn']
                region = selected_topic['region']
            except ValueError:
                print(f"{Fore.RED}Invalid input. Aborting subscription.{Style.RESET_ALL}")
                return
    else:
        topic_arn = input(f"{Fore.GREEN}Enter SNS topic ARN: {Style.RESET_ALL}").strip()
        region = input(f"{Fore.GREEN}Enter region for SNS topic: {Style.RESET_ALL}").strip()
    
    # Prompt for protocol and endpoint
    print(f"{Fore.CYAN}Available protocols: email, email-json, sms, sqs, application, lambda, http, https{Style.RESET_ALL}")
    protocol = input(f"{Fore.GREEN}Enter subscription protocol: {Style.RESET_ALL}").strip().lower()
    endpoint = input(f"{Fore.GREEN}Enter subscription endpoint (email address, phone number, etc.): {Style.RESET_ALL}").strip()

    try:
        sns = session.client('sns', region_name=region)
        response = sns.subscribe(
            TopicArn=topic_arn,
            Protocol=protocol,
            Endpoint=endpoint,
            ReturnSubscriptionArn=True
        )
        subscription_arn = response.get('SubscriptionArn')
        print(f"{Fore.GREEN}Subscription request sent. Subscription ARN: {subscription_arn}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error subscribing to SNS topic: {str(e)}{Style.RESET_ALL}")

# ----------------------- SES Functions -----------------------

def list_verified_identities_in_active_regions(session, active_regions):
    """
    Retrieves SES email identities from each active region and stores them as dictionaries:
    { "region": <region>, "identity": <email> }
    """
    identities = []
    if not active_regions:
        print(f"{Fore.RED}No active SES regions available. Run option 1 for SES region check first.{Style.RESET_ALL}")
        return identities
    try:
        for region in active_regions:
            try:
                ses = session.client('ses', region_name=region)
                response = ses.list_identities(IdentityType='EmailAddress')
                region_identities = response.get('Identities', [])
                if region_identities:
                    print(f"{Fore.CYAN}SES Identities in {region}:{Style.RESET_ALL}")
                    for identity in region_identities:
                        print(f"  - {identity}")
                        identities.append({"region": region, "identity": identity})
                else:
                    print(f"{Fore.YELLOW}No SES identities found in {region}.{Style.RESET_ALL}")
            except ClientError as e:
                print(f"{Fore.RED}Error accessing SES identities in {region}: {e.response['Error']['Message']}{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user. Returning to main menu.{Style.RESET_ALL}")
        return identities
    return identities

def get_identity_verification_attributes(session, state):
    """
    Uses the saved SES identities (with region info) from state['ses_identities'] to allow the user to
    select one and view its verification attributes.
    """
    if 'ses_identities' not in state or not state['ses_identities']:
        print(f"{Fore.RED}No SES identities found in saved state. Please enter the SES identity manually.{Style.RESET_ALL}")
        identity = input(f"{Fore.GREEN}Enter the SES identity: {Style.RESET_ALL}").strip()
        identity_info = {"region": None, "identity": identity}
    else:
        print(f"{Fore.CYAN}Saved SES Identities:{Style.RESET_ALL}")
        for i, id_info in enumerate(state['ses_identities'], 1):
            print(f"{i}. (Region: {id_info['region']}) {id_info['identity']}")
        choice = input(f"{Fore.GREEN}Select an identity number (or press Enter for manual entry): {Style.RESET_ALL}").strip()
        if choice == "":
            identity = input(f"{Fore.GREEN}Enter the SES identity: {Style.RESET_ALL}").strip()
            identity_info = {"region": None, "identity": identity}
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(state['ses_identities']):
                    identity_info = state['ses_identities'][idx]
                else:
                    print(f"{Fore.RED}Invalid selection.{Style.RESET_ALL}")
                    return
            except ValueError:
                print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
                return

    # If region info is missing, ask the user to specify it.
    if not identity_info.get("region"):
        region = input(f"{Fore.GREEN}Enter region for SES identity: {Style.RESET_ALL}").strip()
        identity_info["region"] = region
    else:
        region = identity_info["region"]

    try:
        ses = session.client('ses', region_name=region)
        response = ses.get_identity_verification_attributes(Identities=[identity_info['identity']])
        attributes = response.get('VerificationAttributes', {}).get(identity_info['identity'], {})
        if attributes:
            print(f"{Fore.CYAN}Verification Attributes for {identity_info['identity']} (Region: {region}):{Style.RESET_ALL}")
            for key, value in attributes.items():
                print(f"  {key}: {value}")
            status = attributes.get("VerificationStatus", "Unknown")
            if status.lower() == "success":
                print(f"{Fore.GREEN}The identity is verified.")
            else:
                print(f"{Fore.YELLOW}The identity is not verified (Status: {status}).{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}No verification attributes found for {identity_info['identity']} in {region}.{Style.RESET_ALL}")
    except ClientError as e:
        print(f"{Fore.RED}Error: {e.response['Error']['Message']}{Style.RESET_ALL}")

def simulate_ses_send_email(session, state):
    """
    Simulated red teaming function that attempts to send a test email via SES.
    The user is prompted for email details and the region is selected either from the saved SES active regions or manually.
    """
    print(f"{Fore.CYAN}Simulated SES Send Email Test{Style.RESET_ALL}")
    source = input(f"{Fore.GREEN}Enter source email address (verified SES identity): {Style.RESET_ALL}").strip()
    destination = input(f"{Fore.GREEN}Enter destination email address: {Style.RESET_ALL}").strip()
    subject = input(f"{Fore.GREEN}Enter subject: {Style.RESET_ALL}").strip()
    body = input(f"{Fore.GREEN}Enter email body: {Style.RESET_ALL}").strip()

    # Choose SES region: use saved SES active regions if available.
    if 'ses_active_regions' in state and state['ses_active_regions']:
        print(f"{Fore.CYAN}Available SES Regions:{Style.RESET_ALL}")
        for i, reg in enumerate(state['ses_active_regions'], 1):
            print(f"{i}. {reg}")
        region_input = input(f"{Fore.GREEN}Select a region number (or press Enter to default to the first region): {Style.RESET_ALL}").strip()
        if region_input == "":
            region = state['ses_active_regions'][0]
        else:
            try:
                idx = int(region_input) - 1
                if 0 <= idx < len(state['ses_active_regions']):
                    region = state['ses_active_regions'][idx]
                else:
                    print(f"{Fore.RED}Invalid selection, defaulting to the first region.{Style.RESET_ALL}")
                    region = state['ses_active_regions'][0]
            except ValueError:
                print(f"{Fore.RED}Invalid input, defaulting to the first region.{Style.RESET_ALL}")
                region = state['ses_active_regions'][0]
    else:
        print(f"{Fore.YELLOW}No active SES region defined. Using us-east-1 as default.{Style.RESET_ALL}")
        region = "us-east-1"

    try:
        ses = session.client('ses', region_name=region)
        response = ses.send_email(
            Source=source,
            Destination={'ToAddresses': [destination]},
            Message={
                'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                'Body': {'Text': {'Data': body, 'Charset': 'UTF-8'}}
            }
        )
        print(f"{Fore.GREEN}Test email successfully sent. Message ID: {response['MessageId']}{Style.RESET_ALL}")
    except ClientError as e:
        print(f"{Fore.RED}Error sending test email: {e.response['Error']['Message']}{Style.RESET_ALL}")

def check_sns_topic_misconfigurations(session, state):
    """
    Checks each SNS topic in saved state for potential misconfigurations in its policy.
    For demonstration, this function parses the SNS topic policy and flags statements that are overly permissive.
    """
    if 'sns_topics' not in state or not state['sns_topics']:
        print(f"{Fore.RED}No SNS topics available in saved state. Please list topics first.{Style.RESET_ALL}")
        return
    for topic in state['sns_topics']:
        region = topic.get("region")
        arn = topic.get("arn")
        try:
            sns = session.client('sns', region_name=region)
            attributes = sns.get_topic_attributes(TopicArn=arn)
            policy = attributes.get('Attributes', {}).get('Policy', "{}")
            print(f"\nTopic: {arn} (Region: {region})")
            print(f"Policy: {policy}")
            try:
                policy_data = json.loads(policy)
                misconfigured = False
                for statement in policy_data.get("Statement", []):
                    effect = statement.get("Effect")
                    principal = statement.get("Principal")
                    # Check if the policy allows all principals
                    if effect == "Allow" and (principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")):
                        misconfigured = True
                        print(f"{Fore.RED}Warning: Overly permissive access detected in statement: {statement}{Style.RESET_ALL}")
                if not misconfigured:
                    print(f"{Fore.GREEN}No misconfigurations detected.{Style.RESET_ALL}")
            except json.JSONDecodeError:
                print(f"{Fore.YELLOW}Policy is not valid JSON.{Style.RESET_ALL}")
        except ClientError as e:
            print(f"{Fore.RED}Error getting attributes for topic {arn}: {e.response['Error']['Message']}{Style.RESET_ALL}")

def brute_force_check_regions(session):
    """
    Brute forces SNS and SES across all configured regions.
    """
    print(f"{Fore.CYAN}Brute-forcing regions for SNS...{Style.RESET_ALL}")
    sns_regions = list_active_regions('sns', session)
    print(f"{Fore.GREEN}SNS active regions: {sns_regions}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Brute-forcing regions for SES...{Style.RESET_ALL}")
    ses_regions = list_active_regions('ses', session)
    print(f"{Fore.GREEN}SES active regions: {ses_regions}{Style.RESET_ALL}")

# ----------------------- State Management -----------------------

def save_state(state, filename='state.json'):
    with open(filename, 'w') as f:
        json.dump(state, f)

def load_state(current_profile, filename='state.json'):
    """
    Loads the state if a state file exists.
    If a state file exists, checks if it was created using the same AWS profile.
    If the profiles differ, the user is prompted to either continue with the previous session or start a new one.
    If no state file exists, returns a new state with the current profile.
    """
    default_state = {
        'aws_profile': current_profile,
        'last_choice': None,
        'sns_active_regions': [],
        'ses_active_regions': [],
        'sns_topics': [],
        'ses_identities': []
    }
    
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                state = json.load(f)
        except Exception as e:
            print(f"{Fore.RED}Error loading state file: {str(e)}. Starting a new session.{Style.RESET_ALL}")
            return default_state

        saved_profile = state.get('aws_profile')
        if saved_profile and saved_profile != current_profile:
            print(f"{Fore.YELLOW}The state file is associated with AWS profile '{saved_profile}', but you're using '{current_profile}'.{Style.RESET_ALL}")
            answer = input(f"{Fore.GREEN}Do you want to continue with the previous session? (Y/n): {Style.RESET_ALL}").strip().lower()
            if answer in ['n', 'no']:
                print(f"{Fore.YELLOW}Starting a new session for profile '{current_profile}'.{Style.RESET_ALL}")
                return default_state
            else:
                print(f"{Fore.YELLOW}Continuing with the previous session even though the profile differs.{Style.RESET_ALL}")
        else:
            if not saved_profile:
                # If for some reason the state file did not store a profile, update with the current one.
                state['aws_profile'] = current_profile
            print(f"{Fore.YELLOW}Continuing with the previous session for profile '{state.get('aws_profile')}'.{Style.RESET_ALL}")
        
        # Ensure required keys exist in the loaded state
        state.setdefault('last_choice', None)
        state.setdefault('sns_active_regions', [])
        state.setdefault('ses_active_regions', [])
        state.setdefault('sns_topics', [])
        state.setdefault('ses_identities', [])
        return state
    else:
        return default_state

# ----------------------- Menu and Main Loop -----------------------

def print_menu():
    print(f"{Fore.BLUE}============= MAIN MENU ============={Style.RESET_ALL}")
    print(f"{Fore.BLUE}--- SNS Operations ---{Style.RESET_ALL}")
    print(" 1. Check Active Regions")
    print("    a. For SNS")
    print("    b. For SES")
    print(" 2. List SNS Topics in Active Regions")
    print(" 3. Get SNS Topic Attributes")
    print(" 4. List Subscriptions for an SNS Topic")
    print(" 5. Send a Message to an SNS Topic")
    print(" 6. Create an SNS Topic")
    print(" 7. Subscribe to an SNS Topic")
    print(f"{Fore.BLUE}--- SES Operations ---{Style.RESET_ALL}")
    print(" 8. List Verified SES Identities")
    print(" 9. Get SES Identity Verification Attributes")
    print(f"{Fore.BLUE}--- Other Operations ---{Style.RESET_ALL}")
    print("10. Brute-Force Check Regions for SNS and SES")
    print("11. Check for SNS Topic Misconfigurations")
    print("12. Simulated Red Teaming: Assess SNS Access Policies")
    print("13. Simulated Red Teaming: Attempt to Send Test Email via SES")
    print(" 0. Exit")
    print(f"{Fore.MAGENTA}NOTE: At any time, press Ctrl+C to cancel the current operation.{Style.RESET_ALL}")
    print(f"{Fore.BLUE}====================================={Style.RESET_ALL}")

def clear_and_print_header():
    """
    Clears the screen and prints the header.
    """
    clear_screen()
    figlet_header()

def main():
    clear_and_print_header()  # Clear screen and print header initially
    profile_name = select_profile()
    # Create a boto3 session based on the selected profile
    session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
    clear_and_print_header()  # Reprint header after selecting profile
    print(f"{Fore.CYAN}Using profile: {profile_name if profile_name else 'default'}{Style.RESET_ALL}\n")
    
    # Load state specific to the current AWS profile
    state = load_state(profile_name)
    
    if state.get('last_choice'):
        print(f"{Fore.YELLOW}Resuming from last saved state...{Style.RESET_ALL}")

    # Main loop with cancellation handling.
    while True:
        clear_and_print_header()  # Always clear and print header before each iteration
        print_menu()
        try:
            choice = input(f"\n{Fore.GREEN}Please choose an option: {Style.RESET_ALL}").strip()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
            answer = input(f"{Fore.GREEN}Would you like to return to the main menu? (Y/n): {Style.RESET_ALL}")
            if answer.strip().lower() in ['n', 'no']:
                print(f"{Fore.YELLOW}Exiting program. Goodbye!{Style.RESET_ALL}")
                break
            else:
                continue  # Go back to printing the menu

        if choice == '1':
            service_choice = input(f"{Fore.GREEN}Select service for active region check (a for SNS, b for SES): {Style.RESET_ALL}").strip().lower()
            if service_choice == 'a':
                state['sns_active_regions'] = list_active_regions('sns', session)
            elif service_choice == 'b':
                state['ses_active_regions'] = list_active_regions('ses', session)
            else:
                print(f"{Fore.RED}Invalid service selection.{Style.RESET_ALL}")
        elif choice == '2':
            state['sns_topics'] = list_topics_in_active_regions(session, state.get('sns_active_regions', []))
        elif choice == '3':
            get_topic_attributes(session, state)
        elif choice == '4':
            list_subscriptions(session, state)
        elif choice == '5':
            send_sns_message(session, state)
        elif choice == '6':
            create_sns_topic(session, state)
        elif choice == '7':
            subscribe_to_sns_topic(session, state)
        elif choice == '8':
            state['ses_identities'] = list_verified_identities_in_active_regions(session, state.get('ses_active_regions', []))
        elif choice == '9':
            get_identity_verification_attributes(session, state)
        elif choice == '10':
            brute_force_check_regions(session)
        elif choice == '11':
            check_sns_topic_misconfigurations(session, state)
        elif choice == '12':
            simulate_sns_policy_assessment(session, state)
        elif choice == '13':
            simulate_ses_send_email(session, state)
        elif choice == '0':
            print(f"{Fore.YELLOW}Exiting program. Goodbye!{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid option. Please try again.{Style.RESET_ALL}")

        state['last_choice'] = choice
        save_state(state)
        pause()

if __name__ == "__main__":
    main()
