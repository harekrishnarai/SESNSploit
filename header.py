import pyfiglet
import colorama
from colorama import Fore, Style

# Your name for copyright
COPYRIGHT_OWNER = "Harekrishna Rai"

def figlet_header():
    ascii_art = pyfiglet.figlet_format("Snare", font = "slant")
    print(Fore.RED + ascii_art + Style.RESET_ALL)
    print(f"{Fore.YELLOW}Copyright © {COPYRIGHT_OWNER}{Style.RESET_ALL}")
