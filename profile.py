import os
from colorama import Fore, Style

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
