from botocore.exceptions import ClientError
from colorama import Fore, Style
from main import regions, loading_animation

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
