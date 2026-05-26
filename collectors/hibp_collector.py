# collectors/hibp_collector.py
# ReconMind — HaveIBeenPwned Collector
# Checks if an email appears in known data breach databases.
#
# Strategy:
#   Primary  → HIBP /breachedaccount/{email} (requires paid API key)
#   Fallback → HIBP /breaches (free, full public breach list — no per-email lookup)
#
# If HIBP_API_KEY is set in config.py, the precise per-email check runs.
# If not, we return a "no key" result with a clear message rather than fake data.
 
import requests
import time
from colorama import Fore, Style, init
 
init()  # Required on Windows for colorama to work
 
# Try to import the API key — it's optional for this collector
try:
    from config import HIBP_API_KEY
except ImportError:
    HIBP_API_KEY = None
 
 
class HIBPCollector:
    """
    Queries the HaveIBeenPwned API to check if an email address
    has appeared in any publicly known data breaches.
    """
 
    BASE_URL = "https://haveibeenpwned.com/api/v3"
    HEADERS = {
        # HIBP requires a descriptive User-Agent — generic ones get blocked
        "User-Agent": "ReconMind-OSINT-Tool/1.0",
        "hibp-api-key": "",  # filled in at runtime if key is available
    }
    # HIBP rate-limits to 1 request per 1500ms on free tier
    REQUEST_DELAY = 1.6
 
    def collect(self, email: str) -> dict:
        """
        Main entry point. Accepts an email string, returns a clean dict.
 
        Returns:
            {
                "email":        str,
                "breached":     bool,
                "breach_count": int,
                "breaches":     list[str],   # breach names, e.g. ["Adobe", "LinkedIn"]
                "error":        str | None
            }
        """
        print(f"\n{Fore.CYAN}[~] HIBP: Checking {email}...{Style.RESET_ALL}")
 
        # --- Guard: validate email looks reasonable before hitting the API ---
        if not self._looks_like_email(email):
            return self._error_result(email, "Invalid email format")
 
        # --- Route: use paid endpoint if key is available, otherwise inform ---
        if HIBP_API_KEY:
            return self._check_with_key(email)
        else:
            return self._no_key_result(email)
 
    # ------------------------------------------------------------------ #
    #  Primary path — paid API key present                                 #
    # ------------------------------------------------------------------ #
 
    def _check_with_key(self, email: str) -> dict:
        """Calls /breachedaccount/{email} — returns per-email breach list."""
        url = f"{self.BASE_URL}/breachedaccount/{email}"
        headers = {**self.HEADERS, "hibp-api-key": HIBP_API_KEY}
 
        try:
            time.sleep(self.REQUEST_DELAY)  # respect rate limit
            response = requests.get(
                url,
                headers=headers,
                params={"truncateResponse": "false"},  # get full breach details
                timeout=10,
            )
 
            # 200 → breaches found
            if response.status_code == 200:
                breach_names = [b["Name"] for b in response.json()]
                return self._build_result(email, breached=True, breaches=breach_names)
 
            # 404 → email is clean (not in any breach)
            elif response.status_code == 404:
                return self._build_result(email, breached=False, breaches=[])
 
            # 401 → bad or missing API key
            elif response.status_code == 401:
                return self._error_result(email, "HIBP API key is invalid or unauthorised")
 
            # 429 → rate limited
            elif response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "unknown")
                return self._error_result(
                    email, f"Rate limited by HIBP. Retry after {retry_after}s"
                )
 
            # anything else unexpected
            else:
                return self._error_result(
                    email, f"Unexpected HTTP {response.status_code} from HIBP"
                )
 
        except requests.Timeout:
            return self._error_result(email, "Request timed out (HIBP took > 10s)")
        except requests.ConnectionError:
            return self._error_result(email, "Connection failed — check internet access")
        except Exception as e:
            return self._error_result(email, f"Unexpected error: {str(e)}")
 
    # ------------------------------------------------------------------ #
    #  Fallback — no API key                                               #
    # ------------------------------------------------------------------ #
 
    def _no_key_result(self, email: str) -> dict:
        """
        Called when no HIBP_API_KEY is set.
 
        We do NOT return fake data. Instead we return a clear, honest result
        so the AI analysis layer knows the check was skipped and why.
        The /breaches endpoint (free) lists all public breaches globally but
        cannot tell us whether THIS specific email is in them — so we skip it.
        """
        print(
            f"{Fore.YELLOW}[!] HIBP: No API key found in config.py. "
            f"Per-email check skipped.{Style.RESET_ALL}"
        )
        print(
            f"{Fore.YELLOW}    Get a free key at: https://haveibeenpwned.com/API/Key{Style.RESET_ALL}"
        )
        return {
            "email": email,
            "breached": None,         # None = unknown, not False
            "breach_count": None,
            "breaches": [],
            "error": "HIBP_API_KEY not set in config.py — per-email check requires a key",
        }
 
    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #
 
    def _build_result(self, email: str, breached: bool, breaches: list) -> dict:
        """Assembles the final result dict and prints a colored status line."""
        count = len(breaches)
 
        if breached:
            print(
                f"{Fore.RED}[!] HIBP: BREACHED — {email} found in "
                f"{count} breach(es): {', '.join(breaches[:5])}"
                f"{'...' if count > 5 else ''}{Style.RESET_ALL}"
            )
        else:
            print(f"{Fore.GREEN}[+] HIBP: CLEAN — {email} not found in any known breach{Style.RESET_ALL}")
 
        return {
            "email": email,
            "breached": breached,
            "breach_count": count,
            "breaches": breaches,
            "error": None,
        }
 
    def _error_result(self, email: str, message: str) -> dict:
        """Returns a standardised error dict and prints a warning."""
        print(f"{Fore.YELLOW}[!] HIBP error: {message}{Style.RESET_ALL}")
        return {
            "email": email,
            "breached": None,
            "breach_count": None,
            "breaches": [],
            "error": message,
        }
 
    @staticmethod
    def _looks_like_email(value: str) -> bool:
        """Minimal sanity check — not a full RFC validator, just catches obvious junk."""
        return "@" in value and "." in value.split("@")[-1]

