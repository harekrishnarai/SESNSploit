from botocore.exceptions import ClientError
from colorama import Fore, Style
from main import regions, loading_animation

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
