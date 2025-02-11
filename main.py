#!/usr/bin/env python3

import boto3
from colorama import Fore, Style
from header import figlet_header
from profile import select_profile
from region_check import list_active_regions, check_service_in_region
from sns_operations import get_topic_attributes, list_subscriptions, send_message, brute_force_regions, check_sns_misconfigurations
from state import save_state, load_state

regions = [
    'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ca-central-1', 'eu-central-1',
    'eu-central-2', 'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-west-1', 'eu-west-2',
    'eu-west-3', 'me-central-1', 'me-south-1', 'sa-east-1', 'us-east-1', 'us-east-2',
    'us-west-1', 'us-west-2'
]

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
