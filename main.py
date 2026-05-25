import argparse
from colorama import init, Fore, Style

init(autoreset=True)

def banner():
    print(Fore.CYAN + """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ███╗██╗███╗   ██╗██████╗ 
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗ ████║██║████╗  ██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔████╔██║██║██╔██╗ ██║██║  ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╔╝██║██║██║╚██╗██║██║  ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝ 
    """)
    print(Fore.YELLOW + "        AI-Powered OSINT Intelligence Engine")
    print(Fore.WHITE + "        Built by Amay Jogdand & Atharva Tavaskar\n")

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="ReconMind - OSINT Intelligence Engine")
    parser.add_argument("target", help="Target IP / domain / email / username")
    parser.add_argument("--output", choices=["terminal", "pdf", "json", "all"], 
                        default="terminal", help="Output format")
    args = parser.parse_args()

    print(Fore.GREEN + f"[*] Target: {args.target}")
    print(Fore.GREEN + f"[*] Output: {args.output}")
    print(Fore.YELLOW + "\n[*] Starting reconnaissance...\n")

    # Collectors will be called here one by one
    # We'll add them in next steps

if __name__ == "__main__":
    main()
