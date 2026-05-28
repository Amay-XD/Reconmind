import argparse
import json
import os
import re
from datetime import datetime
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# Collectors
from collectors.shodan_collector import collect_shodan
from collectors.github_collector import GitHubCollector
from collectors.google_collector import GoogleDorkCollector
from collectors.hibp_collector import HIBPCollector
from collectors.social_scan_collectors import SocialScanner

# Output modules
from output.terminal_report import print_report
from output.pdf_export import export_pdf

# AI engine
try:
    from ai_engine.groq_analysis import analyze_osint_data
    AI_AVAILABLE = True
except Exception:
    AI_AVAILABLE = False


# ============================================================
# BANNER
# ============================================================
def banner():
    print(Fore.CYAN + r'''
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ███╗██╗███╗   ██╗██████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗ ████║██║████╗  ██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔████╔██║██║██╔██╗ ██║██║  ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╔╝██║██║██║╚██╗██║██║  ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
''')

    print(Fore.YELLOW + '      AI-Powered OSINT Intelligence Engine')
    print(Fore.WHITE + '      Built by Amay Jogdand & Atharva Tavaskar\n')


# ============================================================
# TARGET DETECTION
# ============================================================
def detect_target_type(target):

    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    ip_regex = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    domain_regex = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if re.match(email_regex, target):
        return 'email'

    elif re.match(ip_regex, target):
        return 'ip'

    elif re.match(domain_regex, target):
        return 'domain'

    else:
        return 'username'


# ============================================================
# MAIN
# ============================================================
def main():

    banner()

    parser = argparse.ArgumentParser(
        description='ReconMind - AI Powered OSINT Engine'
    )

    parser.add_argument(
        'target',
        help='IP / Domain / Email / Username'
    )

    parser.add_argument(
        '--output',
        choices=['terminal', 'json', 'pdf', 'all'],
        default='terminal',
        help='Output format'
    )

    args = parser.parse_args()

    target = args.target
    output_format = args.output

    target_type = detect_target_type(target)

    print(Fore.GREEN + f'[+] Target: {target}')
    print(Fore.GREEN + f'[+] Target Type: {target_type}')
    print(Fore.GREEN + f'[+] Output Mode: {output_format}')
    print(Fore.YELLOW + '\n[+] Starting Reconnaissance...\n')

    results = {
        'target': target,
        'target_type': target_type,
        'timestamp': str(datetime.now()),
        'data': {}
    }

    # ========================================================
    # IP TARGET
    # ========================================================
    if target_type == 'ip':

        try:
            print(Fore.CYAN + '[*] Running Shodan Collector...')
            shodan_data = collect_shodan(target)
            results['data']['shodan'] = shodan_data
        except Exception as e:
            print(Fore.RED + f'[ERROR] Shodan failed: {e}')

    # ========================================================
    # EMAIL TARGET
    # ========================================================
    elif target_type == 'email':

        try:
            print(Fore.CYAN + '[*] Running HIBP Collector...')
            hibp = HIBPCollector()
            hibp_data = hibp.collect(target)
            results['data']['hibp'] = hibp_data
        except Exception as e:
            print(Fore.RED + f'[ERROR] HIBP failed: {e}')

    # ========================================================
    # DOMAIN TARGET
    # ========================================================
    elif target_type == 'domain':

        try:
            print(Fore.CYAN + '[*] Running Google Dork Collector...')
            google = GoogleDorkCollector()
            google_data = google.collect(target)
            results['data']['google_dorks'] = google_data
        except Exception as e:
            print(Fore.RED + f'[ERROR] Google Dorks failed: {e}')

    # ========================================================
    # USERNAME TARGET
    # ========================================================
    elif target_type == 'username':

        # GitHub
        try:
            print(Fore.CYAN + '[*] Running GitHub Collector...')
            github = GitHubCollector()
            github_data = github.collect(target)
            results['data']['github'] = github_data
        except Exception as e:
            print(Fore.RED + f'[ERROR] GitHub failed: {e}')

        # Social Scanner
        try:
            print(Fore.CYAN + '[*] Running Social Scanner...')
            social = SocialScanner()
            social_data = social.collect(target)
            results['data']['social_scan'] = social_data
        except Exception as e:
            print(Fore.RED + f'[ERROR] Social Scan failed: {e}')

    # ========================================================
    # AI ANALYSIS
    # ========================================================
    if AI_AVAILABLE:

        try:
            print(Fore.MAGENTA + '\n[*] Running AI Threat Analysis...')

            ai_report = analyze_osint_data(results)

            results['ai_analysis'] = ai_report

        except Exception as e:
            print(Fore.RED + f'[ERROR] AI Analysis failed: {e}')

    else:
        print(Fore.YELLOW + '[!] AI engine unavailable.')

    # ========================================================
    # OUTPUTS
    # ========================================================

    os.makedirs('reports', exist_ok=True)

    filename_base = target.replace('@', '_').replace('.', '_')

    # TERMINAL
    if output_format in ['terminal', 'all']:

        try:
            print(Fore.GREEN + '\n========== RECON REPORT ==========' )

            try:
               print_report(results)
            except Exception:
                print(json.dumps(results, indent=4))

        except Exception as e:
            print(Fore.RED + f'[ERROR] Terminal output failed: {e}')

    # JSON
    if output_format in ['json', 'all']:

        try:
            json_path = f'reports/{filename_base}.json'

            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4)

            print(Fore.GREEN + f'[+] JSON saved: {json_path}')

        except Exception as e:
            print(Fore.RED + f'[ERROR] JSON export failed: {e}')

    # PDF
    if output_format in ['pdf', 'all']:

        try:
            pdf_path = f'reports/{filename_base}.pdf'

            export_pdf(results, pdf_path)

            print(Fore.GREEN + f'[+] PDF saved: {pdf_path}')

        except Exception as e:
            print(Fore.RED + f'[ERROR] PDF export failed: {e}')

    print(Fore.GREEN + '\n[✓] Recon Completed Successfully!')


# ============================================================
# ENTRY
# ============================================================
if __name__ == '__main__':
    main()
