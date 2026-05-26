# ============================================================
# ReconMind - Shodan Collector
# File: collectors/shodan_collector.py
# Purpose: Collects open port, vulnerability, and host data
#          from Shodan for a given IP address target
# Author: Amay Jogdand
# ============================================================

import shodan                  # Official Shodan Python library
import json                    # For pretty printing raw output
import sys                     # For path manipulation
import os                      # For file path operations
from colorama import init, Fore, Style  # For colored terminal output

# This allows us to import config.py from the parent folder
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import SHODAN_API_KEY

# Initialize colorama so colors work on Windows too
init(autoreset=True)

# ============================================================
# HELPER FUNCTION: Print a styled section header
# ============================================================
def print_section(title):
    print(Fore.CYAN + "\n" + "="*50)
    print(Fore.CYAN + f"  {title}")
    print(Fore.CYAN + "="*50)


# ============================================================
# HELPER FUNCTION: Print individual result rows cleanly
# ============================================================
def print_field(label, value, color=Fore.WHITE):
    if value:
        print(color + f"  ► {label:<20}: {value}")
    else:
        print(Fore.YELLOW + f"  ► {label:<20}: Not found")


# ============================================================
# MAIN COLLECTOR FUNCTION
# Input  : target (string) — must be an IP address
#          e.g. "8.8.8.8" or "192.168.1.1"
# Output : dictionary with all collected data
# ============================================================
def collect_shodan(target):

    print_section(f"SHODAN COLLECTOR — Target: {target}")
    print(Fore.YELLOW + "  [*] Connecting to Shodan API...")

    # --------------------------------------------------------
    # Base result dictionary
    # All keys initialized to None or empty
    # This ensures we always return a consistent structure
    # even if the API call fails
    # --------------------------------------------------------
    result = {
        "source"          : "shodan",
        "target"          : target,
        "ip"              : None,
        "hostnames"       : [],      # Domain names pointing to this IP
        "country"         : None,    # Country where server is hosted
        "city"            : None,    # City where server is hosted
        "region"          : None,    # State/region
        "org"             : None,    # Organization that owns the IP
        "isp"             : None,    # Internet Service Provider
        "asn"             : None,    # Autonomous System Number
        "open_ports"      : [],      # List of open ports found
        "services"        : [],      # Services running on those ports
        "vulnerabilities" : [],      # Known CVEs found on this host
        "tags"            : [],      # Shodan tags e.g. "cloud", "vpn"
        "os"              : None,    # Operating system if detected
        "last_update"     : None,    # When Shodan last scanned this IP
        "total_services"  : 0,       # Count of running services
        "error"           : None     # Error message if something fails
    }

    try:
        # --------------------------------------------------------
        # Step 1: Initialize Shodan API with our key
        # --------------------------------------------------------
        api = shodan.Shodan(SHODAN_API_KEY)
        print(Fore.GREEN + "  [✓] Connected to Shodan API")

        # --------------------------------------------------------
        # Step 2: Look up the target IP
        # history=True gives us more scan data
        # minify=False gives us full details
        # --------------------------------------------------------
        print(Fore.YELLOW + f"  [*] Querying host: {target}")
        host = api.host(target, history=False, minify=False)
        print(Fore.GREEN + "  [✓] Host data received successfully\n")

        # --------------------------------------------------------
        # Step 3: Extract basic host information
        # .get() is used so we don't crash if a key is missing
        # --------------------------------------------------------
        result["ip"]          = host.get("ip_str")
        result["hostnames"]   = host.get("hostnames", [])
        result["country"]     = host.get("country_name")
        result["city"]        = host.get("city")
        result["region"]      = host.get("region_code")
        result["org"]         = host.get("org")
        result["isp"]         = host.get("isp")
        result["asn"]         = host.get("asn")
        result["os"]          = host.get("os")
        result["tags"]        = host.get("tags", [])
        result["last_update"] = host.get("last_update")

        # --------------------------------------------------------
        # Step 4: Extract open ports
        # --------------------------------------------------------
        result["open_ports"] = host.get("ports", [])
        result["total_services"] = len(host.get("data", []))

        # --------------------------------------------------------
        # Step 5: Extract services running on each port
        # Each item in host["data"] is one open port/service
        # --------------------------------------------------------
        services = []
        for service in host.get("data", []):
            service_info = {
                "port"      : service.get("port"),
                "protocol"  : service.get("transport"),   # tcp or udp
                "banner"    : service.get("data", "")[:200],  # first 200 chars
                "product"   : service.get("product"),     # e.g. Apache httpd
                "version"   : service.get("version"),     # e.g. 2.4.41
                "cpe"       : service.get("cpe", [])      # Common Platform Enum
            }
            services.append(service_info)
        result["services"] = services

        # --------------------------------------------------------
        # Step 6: Extract known vulnerabilities (CVEs)
        # Shodan sometimes lists CVEs found on the host
        # --------------------------------------------------------
        vulns = host.get("vulns", {})
        result["vulnerabilities"] = list(vulns.keys())  # e.g. ["CVE-2021-44228"]

        # --------------------------------------------------------
        # Step 7: Print everything nicely to terminal
        # --------------------------------------------------------
        print_section("HOST INFORMATION")
        print_field("IP Address",   result["ip"],      Fore.WHITE)
        print_field("Hostnames",    ", ".join(result["hostnames"]) or "None", Fore.WHITE)
        print_field("Country",      result["country"], Fore.WHITE)
        print_field("City",         result["city"],    Fore.WHITE)
        print_field("Region",       result["region"],  Fore.WHITE)
        print_field("Organization", result["org"],     Fore.WHITE)
        print_field("ISP",          result["isp"],     Fore.WHITE)
        print_field("ASN",          result["asn"],     Fore.WHITE)
        print_field("OS Detected",  result["os"],      Fore.WHITE)
        print_field("Last Scanned", result["last_update"], Fore.WHITE)

        print_section("OPEN PORTS & SERVICES")
        if result["open_ports"]:
            print(Fore.RED + f"  ► Open Ports ({len(result['open_ports'])} found): {result['open_ports']}")
            print()
            for svc in result["services"]:
                print(Fore.YELLOW + f"  PORT {svc['port']}/{svc['protocol']}")
                if svc["product"]:
                    print(Fore.WHITE + f"    Product : {svc['product']} {svc['version'] or ''}")
                if svc["banner"]:
                    # Clean up banner for display
                    banner_preview = svc["banner"].replace('\n', ' ').strip()[:100]
                    print(Fore.WHITE + f"    Banner  : {banner_preview}")
                print()
        else:
            print(Fore.GREEN + "  ► No open ports found")

        print_section("VULNERABILITIES")
        if result["vulnerabilities"]:
            print(Fore.RED + f"  ⚠ {len(result['vulnerabilities'])} CVE(s) found!")
            for cve in result["vulnerabilities"]:
                print(Fore.RED + f"    → {cve}")
        else:
            print(Fore.GREEN + "  ✓ No known vulnerabilities found")

        print_section("TAGS")
        if result["tags"]:
            print(Fore.MAGENTA + f"  ► {', '.join(result['tags'])}")
        else:
            print(Fore.WHITE + "  ► No tags")

        print(Fore.GREEN + "\n  [✓] Shodan collection complete!\n")

    # --------------------------------------------------------
    # Error Handling
    # Different errors need different messages
    # --------------------------------------------------------
    except shodan.APIError as e:
        # This catches Shodan-specific errors
        # e.g. "No information available for that IP"
        # e.g. "Invalid API key"
        result["error"] = f"Shodan API Error: {str(e)}"
        print(Fore.RED + f"\n  [✗] Shodan API Error: {e}")
        print(Fore.YELLOW + "  [!] Possible reasons:")
        print(Fore.YELLOW + "      - IP has no Shodan data yet")
        print(Fore.YELLOW + "      - Invalid API key in config.py")
        print(Fore.YELLOW + "      - Free account query limit reached")

    except ConnectionError:
        result["error"] = "Connection failed — check your internet"
        print(Fore.RED + "  [✗] Connection Error: Check your internet connection")

    except Exception as e:
        # Catch-all for any other unexpected errors
        result["error"] = f"Unexpected error: {str(e)}"
        print(Fore.RED + f"  [✗] Unexpected Error: {e}")

    # Always return the result dictionary
    # Even if it failed, main.py needs a consistent object
    return result


# ============================================================
# DIRECT TEST
# Run this file directly to test: python shodan_collector.py
# Uses Google's public DNS IP — safe and always has data
# ============================================================
if __name__ == "__main__":
    print(Fore.CYAN + "\n[TEST MODE] Running Shodan collector directly...")

    # Test with Google DNS — always has rich Shodan data
    test_ip = "8.8.8.8"
    data = collect_shodan(test_ip)

    # Print the raw dictionary output at the end
    print(Fore.CYAN + "\n--- RAW JSON OUTPUT (what main.py receives) ---")
    print(json.dumps(data, indent=2, default=str))
