# collectors/google_dork_collector.py
# ReconMind — Google Dork Collector
# Automates Google search operator queries (dorks) to surface exposed files,
# admin panels, login pages, and sensitive information indexed about a target.
#
# No API key required — uses Google's public search HTML endpoint.
#
# IMPORTANT LIMITATIONS:
#   - Google aggressively rate-limits automated requests (429 / CAPTCHA)
#   - We add delays and rotate User-Agents to reduce blocking
#   - If Google blocks you, results will be empty — NOT an error in your code
#   - For production use, consider Google Custom Search API (100 free queries/day)
 
import requests
import time
import random
from urllib.parse import quote_plus, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
 
init()  # Required on Windows
 
 
# Rotate these to reduce the chance of Google's bot detection triggering
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
]
 
 
class GoogleDorkCollector:
    """
    Runs pre-built Google dork queries against a target domain.
 
    Dork categories:
    - Exposed files (PDF, XLS, SQL, config, backup)
    - Open directory listings
    - Login / admin panels
    - Subdomain enumeration
    - Sensitive string leaks (passwords, API keys, tokens)
    - Technology fingerprinting (error pages, framework signatures)
 
    Returns structured results per dork with extracted URLs and a
    severity rating so the AI engine can prioritise findings.
    """
 
    # Delay range between requests (seconds) — randomised to look more human
    MIN_DELAY = 2.5
    MAX_DELAY = 5.0
 
    # Max results to extract per dork — keeps output clean
    MAX_RESULTS_PER_DORK = 3
 
    def collect(self, target: str) -> dict:
        """
        Main entry point. Accepts a domain string, returns a clean dict.
 
        Returns:
            {
                "target":        str,
                "dorks_run":     int,
                "hits":          int,           # dorks that returned results
                "results":       list[dict],    # one dict per dork
                "flags":         list[str],     # analyst risk signals
                "blocked":       bool,          # True if Google blocked us
                "error":         str | None
            }
 
        Each result dict:
            {
                "dork":      str,               # the query string used
                "category":  str,               # e.g. "exposed_files"
                "severity":  str,               # "high" / "medium" / "low"
                "urls":      list[str],         # extracted result URLs
                "hit":       bool               # True if any URLs found
            }
        """
        print(f"\n{Fore.CYAN}[~] Google Dorks: Running queries against {target}...{Style.RESET_ALL}")
 
        if not self._looks_like_domain(target):
            return self._error_result(target, "Input does not look like a valid domain")
 
        # Build the full dork list for this target
        dorks = self._build_dorks(target)
        results = []
        blocked = False
        hits = 0
 
        for i, dork_def in enumerate(dorks):
            # Randomised delay between every request
            delay = random.uniform(self.MIN_DELAY, self.MAX_DELAY)
            if i > 0:
                time.sleep(delay)
 
            print(
                f"  {Fore.CYAN}[{i+1}/{len(dorks)}]{Style.RESET_ALL} "
                f"{dork_def['category']}: {dork_def['dork'][:60]}...",
                end="",
                flush=True,
            )
 
            urls, was_blocked = self._run_dork(dork_def["dork"])
 
            if was_blocked:
                print(f" {Fore.RED}BLOCKED{Style.RESET_ALL}")
                blocked = True
                # Don't keep hammering Google if we're blocked — stop early
                results.append({**dork_def, "urls": [], "hit": False, "blocked": True})
                break
 
            hit = len(urls) > 0
            if hit:
                hits += 1
                print(f" {Fore.RED}HIT ({len(urls)} URLs){Style.RESET_ALL}")
            else:
                print(f" {Fore.GREEN}clean{Style.RESET_ALL}")
 
            results.append({
                **dork_def,
                "urls":    urls,
                "hit":     hit,
                "blocked": False,
            })
 
        flags = self._build_flags(results, blocked)
        self._print_summary(target, hits, len(dorks), blocked, flags)
 
        return {
            "target":     target,
            "dorks_run":  len(results),
            "hits":       hits,
            "results":    results,
            "flags":      flags,
            "blocked":    blocked,
            "error":      None,
        }
 
    # ------------------------------------------------------------------ #
    #  Dork definitions                                                    #
    # ------------------------------------------------------------------ #
 
    def _build_dorks(self, target: str) -> list:
        """
        Returns a list of dork definitions for the target.
        Each dict has: dork (query string), category, severity.
 
        Ordered from highest to lowest severity so the most important
        findings run first — if Google blocks us partway through, we
        still have the critical results.
        """
        t = target  # shorthand
        return [
            # ── HIGH severity ──────────────────────────────────────────
            {
                "dork":     f"site:{t} ext:sql OR ext:db OR ext:sqlite",
                "category": "exposed_database",
                "severity": "high",
            },
            {
                "dork":     f"site:{t} ext:env OR ext:cfg OR ext:conf OR ext:ini",
                "category": "exposed_config",
                "severity": "high",
            },
            {
                "dork":     f"site:{t} ext:log",
                "category": "exposed_logs",
                "severity": "high",
            },
            {
                "dork":     f'site:{t} "password" OR "passwd" OR "api_key" OR "secret"',
                "category": "credential_leak",
                "severity": "high",
            },
            {
                "dork":     f"site:{t} ext:bak OR ext:backup OR ext:old OR ext:swp",
                "category": "backup_files",
                "severity": "high",
            },
            # ── MEDIUM severity ────────────────────────────────────────
            {
                "dork":     f"site:{t} intitle:index.of",
                "category": "open_directory",
                "severity": "medium",
            },
            {
                "dork":     f"site:{t} inurl:admin OR inurl:administrator OR inurl:wp-admin",
                "category": "admin_panel",
                "severity": "medium",
            },
            {
                "dork":     f"site:{t} inurl:login OR inurl:signin OR inurl:portal",
                "category": "login_page",
                "severity": "medium",
            },
            {
                "dork":     f"site:{t} inurl:phpinfo OR inurl:test OR inurl:debug",
                "category": "debug_page",
                "severity": "medium",
            },
            {
                "dork":     f"site:{t} ext:xml OR ext:json inurl:api",
                "category": "api_endpoint",
                "severity": "medium",
            },
            # ── LOW severity ───────────────────────────────────────────
            {
                "dork":     f"site:{t} ext:pdf OR ext:doc OR ext:docx OR ext:xls",
                "category": "public_documents",
                "severity": "low",
            },
            {
                "dork":     f"site:*.{t} -www",
                "category": "subdomain_enum",
                "severity": "low",
            },
            {
                "dork":     f'site:{t} "error" OR "exception" OR "stack trace" OR "fatal"',
                "category": "error_disclosure",
                "severity": "low",
            },
        ]
 
    # ------------------------------------------------------------------ #
    #  HTTP / parsing                                                      #
    # ------------------------------------------------------------------ #
 
    def _run_dork(self, dork: str) -> tuple:
        """
        Executes one Google search for the given dork string.
        Returns (list_of_urls, was_blocked).
 
        was_blocked = True means Google returned a CAPTCHA or 429.
        In that case the URL list will be empty.
        """
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            # Accept-Language makes results less likely to return localised CAPTCHA pages
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        search_url = f"https://www.google.com/search?q={quote_plus(dork)}&num=5&hl=en"
 
        try:
            response = requests.get(search_url, headers=headers, timeout=10)
 
            # 429 = rate limited
            if response.status_code == 429:
                return [], True
 
            # Unusual status
            if response.status_code != 200:
                return [], False
 
            # Check for CAPTCHA page — Google serves 200 but with a challenge form
            if self._is_captcha_page(response.text):
                return [], True
 
            urls = self._extract_urls(response.text, dork)
            return urls, False
 
        except requests.Timeout:
            return [], False
        except requests.ConnectionError:
            return [], False
        except Exception:
            return [], False
 
    def _extract_urls(self, html: str, dork: str) -> list:
        """
        Parses Google search result HTML and extracts clean result URLs.
        Filters out Google's own URLs and tracking redirects.
        """
        soup = BeautifulSoup(html, "html.parser")
        urls = []
 
        # Google wraps result links in <a> tags with href starting with /url?q=
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
 
            # Google's result links look like /url?q=https://example.com&sa=...
            if href.startswith("/url?q="):
                raw = href[7:]                    # strip the /url?q= prefix
                clean = raw.split("&")[0]         # strip tracking params
                if self._is_valid_result_url(clean):
                    urls.append(clean)
                    if len(urls) >= self.MAX_RESULTS_PER_DORK:
                        break
 
        return urls
 
    def _is_captcha_page(self, html: str) -> bool:
        """Detect Google's 'unusual traffic' / CAPTCHA page."""
        captcha_signals = [
            "Our systems have detected unusual traffic",
            "detected unusual traffic from your computer",
            "g-recaptcha",
            "/sorry/index",
            "recaptcha/api.js",
        ]
        return any(signal in html for signal in captcha_signals)
 
    def _is_valid_result_url(self, url: str) -> bool:
        """
        Filter out Google internal URLs, ads, and non-http links
        that sometimes slip through the parser.
        """
        if not url.startswith("http"):
            return False
        skip_domains = [
            "google.com", "google.co", "googleapis.com",
            "googleadservices.com", "youtube.com", "accounts.google",
        ]
        try:
            domain = urlparse(url).netloc.lower()
            return not any(skip in domain for skip in skip_domains)
        except Exception:
            return False
 
    # ------------------------------------------------------------------ #
    #  Analyst flags                                                       #
    # ------------------------------------------------------------------ #
 
    def _build_flags(self, results: list, blocked: bool) -> list:
        """
        Derives analyst risk flags from dork results.
        High-severity hits get individual flags; patterns get summary flags.
        """
        flags = []
 
        if blocked:
            flags.append("GOOGLE_BLOCKED: Google blocked requests — results may be incomplete")
 
        for r in results:
            if not r.get("hit"):
                continue
            category = r.get("category", "")
            severity = r.get("severity", "low")
            sample   = r["urls"][0] if r["urls"] else ""
 
            if severity == "high":
                flags.append(
                    f"HIGH: {category.upper()} — exposed content found "
                    f"({sample[:80]}{'...' if len(sample) > 80 else ''})"
                )
            elif severity == "medium":
                flags.append(f"MEDIUM: {category.upper()} — indexed page found")
 
        # Summarise low-severity hits without flooding the flag list
        low_hits = [r for r in results if r.get("hit") and r.get("severity") == "low"]
        if low_hits:
            categories = ", ".join(r["category"] for r in low_hits)
            flags.append(f"LOW: additional findings in — {categories}")
 
        return flags
 
    # ------------------------------------------------------------------ #
    #  Output helpers                                                      #
    # ------------------------------------------------------------------ #
 
    def _print_summary(self, target, hits, total, blocked, flags):
        """Print a colored summary after all dorks have run."""
        if blocked:
            print(
                f"\n{Fore.RED}[!] Google Dorks: BLOCKED by Google after partial scan. "
                f"{hits} hit(s) before block.{Style.RESET_ALL}"
            )
        elif hits > 0:
            print(
                f"\n{Fore.RED}[!] Google Dorks: {hits}/{total} dorks returned results "
                f"for {target} — {len(flags)} flag(s){Style.RESET_ALL}"
            )
        else:
            print(
                f"\n{Fore.GREEN}[+] Google Dorks: {target} — no exposed content "
                f"found across {total} dorks{Style.RESET_ALL}"
            )
 
    def _error_result(self, target: str, message: str) -> dict:
        """Standardised error dict."""
        print(f"{Fore.YELLOW}[!] Google Dorks error: {message}{Style.RESET_ALL}")
        return {
            "target":    target,
            "dorks_run": 0,
            "hits":      0,
            "results":   [],
            "flags":     [],
            "blocked":   False,
            "error":     message,
        }
 
    @staticmethod
    def _looks_like_domain(value: str) -> bool:
        """Minimal check — must have a dot and no spaces."""
        return "." in value and " " not in value and len(value) > 3
 
