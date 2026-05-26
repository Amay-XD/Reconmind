# collectors/whois_collector.py
# ReconMind — WHOIS Collector
# Looks up domain registration data: owner, registrar, dates, name servers.
#
# Library: python-whois (already in requirements.txt)
# No API key required — queries public WHOIS records directly.
 
import whois
from datetime import datetime
from colorama import Fore, Style, init
 
init()  # Required on Windows
 
 
class WhoisCollector:
    """
    Queries public WHOIS records for a domain.
    Returns registration metadata useful for threat intelligence:
    - Who registered it and when
    - When it expires (recently registered + short expiry = suspicious)
    - Name servers (can reveal hosting provider or CDN)
    - Contact emails (useful for pivoting to other targets)
    """
 
    def collect(self, domain: str) -> dict:
        """
        Main entry point. Accepts a domain string, returns a clean dict.
 
        Returns:
            {
                "domain":          str,
                "registrar":       str | None,
                "creation_date":   str | None,
                "expiration_date": str | None,
                "updated_date":    str | None,
                "age_days":        int | None,   # how old the domain is
                "name_servers":    list[str],
                "emails":          list[str],
                "country":         str | None,
                "org":             str | None,
                "flags":           list[str],    # analyst notes e.g. "recently registered"
                "error":           str | None
            }
        """
        print(f"\n{Fore.CYAN}[~] WHOIS: Looking up {domain}...{Style.RESET_ALL}")
 
        # Basic sanity check before querying
        if not self._looks_like_domain(domain):
            return self._error_result(domain, "Input does not look like a valid domain")
 
        try:
            w = whois.whois(domain)
 
            # python-whois returns dates as datetime objects or lists of datetimes
            # Normalise everything to a single value for clean output
            creation   = self._parse_date(w.creation_date)
            expiration = self._parse_date(w.expiration_date)
            updated    = self._parse_date(w.updated_date)
 
            # Calculate domain age in days (useful risk indicator)
            age_days = None
            if creation:
                try:
                    # creation is stored as a string by this point — re-parse for math
                    created_dt = datetime.strptime(creation, "%Y-%m-%d")
                    age_days = (datetime.utcnow() - created_dt).days
                except Exception:
                    pass
 
            # Normalise name servers and emails to plain lists of strings
            name_servers = self._parse_list(w.name_servers)
            emails       = self._parse_list(w.emails)
 
            # Clean up registrar string (some responses have extra whitespace/newlines)
            registrar = self._clean_str(w.registrar)
            org       = self._clean_str(w.org)
            country   = self._clean_str(w.country)
 
            # Build analyst flags — these surface in the AI prompt as risk signals
            flags = self._build_flags(age_days, expiration, name_servers, registrar)
 
            result = {
                "domain":          domain,
                "registrar":       registrar,
                "creation_date":   creation,
                "expiration_date": expiration,
                "updated_date":    updated,
                "age_days":        age_days,
                "name_servers":    name_servers,
                "emails":          emails,
                "country":         country,
                "org":             org,
                "flags":           flags,
                "error":           None,
            }
 
            self._print_status(result)
            return result
 
        except whois.parser.PywhoisError as e:
            return self._error_result(domain, f"WHOIS parse error: {str(e)}")
        except ConnectionResetError:
            return self._error_result(domain, "Connection reset — WHOIS server may have blocked request")
        except Exception as e:
            return self._error_result(domain, f"Unexpected error: {str(e)}")
 
    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #
 
    def _parse_date(self, value) -> str | None:
        """
        python-whois returns dates as datetime, list of datetimes, or None.
        We always want a single 'YYYY-MM-DD' string or None.
        """
        if value is None:
            return None
        # Some registrars return a list — take the first entry
        if isinstance(value, list):
            value = value[0]
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d")
        # Already a string (some edge cases)
        return str(value)[:10]
 
    def _parse_list(self, value) -> list:
        """Normalise a value that might be None, a string, or a list."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value.lower().strip()]
        if isinstance(value, list):
            # Deduplicate, lowercase, remove None entries
            seen = set()
            result = []
            for item in value:
                if item:
                    cleaned = str(item).lower().strip()
                    if cleaned not in seen:
                        seen.add(cleaned)
                        result.append(cleaned)
            return result
        return []
 
    def _clean_str(self, value) -> str | None:
        """Strip whitespace and normalise to None if empty."""
        if value is None:
            return None
        if isinstance(value, list):
            value = value[0] if value else None
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned if cleaned else None
 
    def _build_flags(self, age_days, expiration, name_servers, registrar) -> list:
        """
        Generate analyst-readable flags based on the WHOIS data.
        These are passed to the AI engine as structured risk signals.
        """
        flags = []
 
        # Recently registered domains are a common phishing/C2 indicator
        if age_days is not None:
            if age_days < 30:
                flags.append("RECENTLY_REGISTERED: domain is less than 30 days old")
            elif age_days < 90:
                flags.append("NEW_DOMAIN: domain is less than 90 days old")
 
        # Expiring soon may indicate abandoned or temp infrastructure
        if expiration:
            try:
                exp_dt = datetime.strptime(expiration, "%Y-%m-%d")
                days_to_expiry = (exp_dt - datetime.utcnow()).days
                if days_to_expiry < 0:
                    flags.append("EXPIRED: domain registration has lapsed")
                elif days_to_expiry < 30:
                    flags.append("EXPIRING_SOON: domain expires in under 30 days")
            except Exception:
                pass
 
        # Privacy-protected registrations hide owner identity
        if registrar and "privacy" in registrar.lower():
            flags.append("PRIVACY_PROTECTED: registrant identity is hidden")
 
        # Bulletproof or high-abuse hosting providers
        high_risk_ns = ["namecheap", "njalla", "epik", "porkbun"]
        ns_str = " ".join(name_servers).lower()
        for provider in high_risk_ns:
            if provider in ns_str:
                flags.append(f"HIGH_RISK_REGISTRAR: name server associated with {provider}")
                break
 
        return flags
 
    def _print_status(self, result: dict):
        """Print a colored summary line to the terminal."""
        age_str = f"{result['age_days']} days old" if result['age_days'] else "age unknown"
        flag_count = len(result['flags'])
 
        if flag_count > 0:
            print(
                f"{Fore.YELLOW}[!] WHOIS: {result['domain']} — "
                f"{result['registrar'] or 'Unknown registrar'} — "
                f"{age_str} — {flag_count} flag(s): "
                f"{result['flags'][0]}{Style.RESET_ALL}"
            )
        else:
            print(
                f"{Fore.GREEN}[+] WHOIS: {result['domain']} — "
                f"{result['registrar'] or 'Unknown registrar'} — "
                f"{age_str} — no flags{Style.RESET_ALL}"
            )
 
    def _error_result(self, domain: str, message: str) -> dict:
        """Standardised error dict — matches the shape of a successful result."""
        print(f"{Fore.YELLOW}[!] WHOIS error for {domain}: {message}{Style.RESET_ALL}")
        return {
            "domain":          domain,
            "registrar":       None,
            "creation_date":   None,
            "expiration_date": None,
            "updated_date":    None,
            "age_days":        None,
            "name_servers":    [],
            "emails":          [],
            "country":         None,
            "org":             None,
            "flags":           [],
            "error":           message,
        }
 
    @staticmethod
    def _looks_like_domain(value: str) -> bool:
        """Minimal check — must have at least one dot and no spaces."""
        return "." in value and " " not in value and len(value) > 3

