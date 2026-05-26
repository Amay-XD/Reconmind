# collectors/social_scan.py
# ReconMind — Social Scanner
# Checks if a username exists across major social platforms by sending
# HTTP requests and analysing the response.
#
# No API key required — all checks use public profile URLs.
#
# HOW IT WORKS:
#   For most platforms: GET the profile URL → 200 means exists, 404 means not found.
#   Some platforms (e.g. Instagram, Twitter/X) always return 200 and hide
#   existence in the HTML — we check for known "not found" strings in those cases.
#   A few platforms (e.g. Facebook) block bots entirely — marked as RESTRICTED.

import requests
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init()  # Required on Windows


# Rotate User-Agents — some platforms block obvious bot strings
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


class SocialScanner:
    """
    Checks username existence across 20+ social platforms concurrently.

    Detection methods per platform:
    - STATUS_200:    exists if HTTP 200, not found if HTTP 404
    - HTML_PROBE:    exists if response body does NOT contain a known
                     "not found" string (used where platform always returns 200)
    - RESTRICTED:    platform blocks automated checks — marked as unknown

    Results include:
    - Per-platform status (found / not_found / unknown / error)
    - Profile URL for found accounts
    - Analyst flags (e.g. high presence, security community presence)
    """

    # Timeout per request — some platforms are slow
    TIMEOUT = 8

    # Max concurrent threads — too many triggers rate limiting
    MAX_WORKERS = 5

    # Platform definitions
    # Each entry: url_template, detection_method, not_found_string (for HTML_PROBE only)
    PLATFORMS = {
        # ── Professional / General ─────────────────────────────────────
        "github": {
            "url":    "https://github.com/{}",
            "method": "STATUS_200",
        },
        "gitlab": {
            "url":    "https://gitlab.com/{}",
            "method": "STATUS_200",
        },
        "linkedin": {
            "url":    "https://www.linkedin.com/in/{}",
            "method": "STATUS_200",
        },
        "keybase": {
            "url":    "https://keybase.io/{}",
            "method": "STATUS_200",
        },
        # ── Social Media ───────────────────────────────────────────────
        "reddit": {
            "url":    "https://www.reddit.com/user/{}",
            "method": "HTML_PROBE",
            "not_found": "Sorry, nobody on Reddit goes by that name.",
        },
        "twitter_x": {
            "url":    "https://x.com/{}",
            "method": "HTML_PROBE",
            "not_found": "This account doesn\u2019t exist",
        },
        "instagram": {
            "url":    "https://www.instagram.com/{}/",
            "method": "HTML_PROBE",
            "not_found": "Sorry, this page isn\u2019t available.",
        },
        "pinterest": {
            "url":    "https://www.pinterest.com/{}/",
            "method": "STATUS_200",
        },
        "tumblr": {
            "url":    "https://{}.tumblr.com",
            "method": "STATUS_200",
        },
        # ── Tech / Dev Community ───────────────────────────────────────
        "stackoverflow": {
            "url":    "https://stackoverflow.com/users/{}",
            "method": "STATUS_200",
        },
        "hackerrank": {
            "url":    "https://www.hackerrank.com/{}",
            "method": "STATUS_200",
        },
        "leetcode": {
            "url":    "https://leetcode.com/{}",
            "method": "HTML_PROBE",
            "not_found": "The page you requested does not exist",
        },
        "dev_to": {
            "url":    "https://dev.to/{}",
            "method": "STATUS_200",
        },
        "medium": {
            "url":    "https://medium.com/@{}",
            "method": "HTML_PROBE",
            "not_found": "Page not found",
        },
        # ── Security Community ─────────────────────────────────────────
        "tryhackme": {
            "url":    "https://tryhackme.com/p/{}",
            "method": "STATUS_200",
        },
        "hackthebox": {
            "url":    "https://app.hackthebox.com/users/{}",
            "method": "STATUS_200",
        },
        "bugcrowd": {
            "url":    "https://bugcrowd.com/{}",
            "method": "STATUS_200",
        },
        # ── Content / Creative ─────────────────────────────────────────
        "youtube": {
            "url":    "https://www.youtube.com/@{}",
            "method": "HTML_PROBE",
            "not_found": "This page isn\u2019t available",
        },
        "twitch": {
            "url":    "https://www.twitch.tv/{}",
            "method": "HTML_PROBE",
            "not_found": "Sorry. Unless you\u2019ve got a time machine",
        },
        "pastebin": {
            "url":    "https://pastebin.com/u/{}",
            "method": "STATUS_200",
        },
        # ── Restricted platforms (always block bots) ───────────────────
        "facebook": {
            "url":    "https://www.facebook.com/{}",
            "method": "RESTRICTED",
        },
        "tiktok": {
            "url":    "https://www.tiktok.com/@{}",
            "method": "RESTRICTED",
        },
    }

    def collect(self, username: str) -> dict:
        """
        Main entry point. Accepts a username string, returns a clean dict.

        Returns:
            {
                "username":   str,
                "checked":    int,               # platforms actually checked
                "found":      int,               # accounts confirmed found
                "results":    dict[str, dict],   # per-platform result
                "flags":      list[str],         # analyst risk signals
                "error":      str | None
            }

        Each per-platform result dict:
            {
                "status":  "found" | "not_found" | "unknown" | "error",
                "url":     str,                  # profile URL
                "detail":  str | None            # error message if status=error
            }
        """
        print(f"\n{Fore.CYAN}[~] Social Scan: Checking @{username} across "
              f"{len(self.PLATFORMS)} platforms...{Style.RESET_ALL}")

        if not self._looks_like_username(username):
            return self._error_result(username, "Invalid username — contains spaces or is empty")

        # Run checks concurrently to keep scan time reasonable
        results = self._run_concurrent_checks(username)

        found_count = sum(1 for r in results.values() if r["status"] == "found")
        checked_count = sum(1 for r in results.values() if r["status"] != "unknown")
        flags = self._build_flags(username, results, found_count)

        self._print_summary(username, found_count, checked_count, flags)

        return {
            "username": username,
            "checked":  checked_count,
            "found":    found_count,
            "results":  results,
            "flags":    flags,
            "error":    None,
        }

    # ------------------------------------------------------------------ #
    #  Concurrent execution                                                #
    # ------------------------------------------------------------------ #

    def _run_concurrent_checks(self, username: str) -> dict:
        """
        Runs all platform checks using a thread pool.
        MAX_WORKERS threads run simultaneously — fast but not aggressive.
        """
        results = {}

        # Handle RESTRICTED platforms immediately without making any request
        for platform, config in self.PLATFORMS.items():
            if config["method"] == "RESTRICTED":
                results[platform] = {
                    "status": "unknown",
                    "url":    config["url"].format(username),
                    "detail": "Platform blocks automated checks",
                }

        # Check all other platforms concurrently
        checkable = {
            k: v for k, v in self.PLATFORMS.items()
            if v["method"] != "RESTRICTED"
        }

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            future_to_platform = {
                executor.submit(self._check_platform, platform, config, username): platform
                for platform, config in checkable.items()
            }

            for future in as_completed(future_to_platform):
                platform = future_to_platform[future]
                try:
                    results[platform] = future.result()
                except Exception as e:
                    results[platform] = {
                        "status": "error",
                        "url":    self.PLATFORMS[platform]["url"].format(username),
                        "detail": str(e),
                    }

        return results

    # ------------------------------------------------------------------ #
    #  Per-platform check                                                  #
    # ------------------------------------------------------------------ #

    def _check_platform(self, platform: str, config: dict, username: str) -> dict:
        """
        Executes a single platform check.
        Returns a standardised result dict.
        """
        url = config["url"].format(username)
        method = config["method"]

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.9",
            # Some platforms check this header before returning profile pages
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        try:
            # Small random jitter even in threaded context
            time.sleep(random.uniform(0.1, 0.5))

            response = requests.get(
                url,
                headers=headers,
                timeout=self.TIMEOUT,
                allow_redirects=True,
            )

            if method == "STATUS_200":
                return self._evaluate_status(url, response)

            elif method == "HTML_PROBE":
                return self._evaluate_html(
                    url, response, config.get("not_found", "")
                )

            else:
                return {"status": "unknown", "url": url, "detail": "Unknown method"}

        except requests.Timeout:
            return {"status": "error", "url": url, "detail": "Request timed out"}
        except requests.ConnectionError:
            return {"status": "error", "url": url, "detail": "Connection failed"}
        except Exception as e:
            return {"status": "error", "url": url, "detail": str(e)}

    def _evaluate_status(self, url: str, response) -> dict:
        """STATUS_200 method: 200 = found, 404 = not found, anything else = unknown."""
        if response.status_code == 200:
            return {"status": "found",     "url": url, "detail": None}
        elif response.status_code == 404:
            return {"status": "not_found", "url": url, "detail": None}
        else:
            return {
                "status": "unknown",
                "url":    url,
                "detail": f"Unexpected HTTP {response.status_code}",
            }

    def _evaluate_html(self, url: str, response, not_found_string: str) -> dict:
        """
        HTML_PROBE method: platform always returns 200, so we check page content.
        If the not_found_string appears in the HTML, the user doesn't exist.
        """
        if response.status_code == 200:
            if not_found_string and not_found_string in response.text:
                return {"status": "not_found", "url": url, "detail": None}
            else:
                # 200 with no not-found string = account likely exists
                return {"status": "found", "url": url, "detail": None}
        elif response.status_code == 404:
            return {"status": "not_found", "url": url, "detail": None}
        else:
            return {
                "status": "unknown",
                "url":    url,
                "detail": f"Unexpected HTTP {response.status_code}",
            }

    # ------------------------------------------------------------------ #
    #  Analyst flags                                                       #
    # ------------------------------------------------------------------ #

    def _build_flags(self, username: str, results: dict, found_count: int) -> list:
        """Generates analyst-readable signals for the AI engine."""
        flags = []

        # High platform presence = established online identity
        if found_count >= 10:
            flags.append(f"HIGH_PRESENCE: username found on {found_count} platforms")
        elif found_count >= 5:
            flags.append(f"MODERATE_PRESENCE: username found on {found_count} platforms")
        elif found_count == 0:
            flags.append("NO_PRESENCE: username not found on any checked platform")

        # Security community presence — relevant for threat actor profiling
        security_platforms = ["tryhackme", "hackthebox", "bugcrowd"]
        security_found = [
            p for p in security_platforms
            if results.get(p, {}).get("status") == "found"
        ]
        if security_found:
            flags.append(
                f"SECURITY_COMMUNITY: active on {', '.join(security_found)}"
            )

        # Developer presence
        dev_platforms = ["github", "gitlab", "stackoverflow", "dev_to", "hackerrank"]
        dev_found = [
            p for p in dev_platforms
            if results.get(p, {}).get("status") == "found"
        ]
        if len(dev_found) >= 2:
            flags.append(f"DEVELOPER_PRESENCE: active on {', '.join(dev_found)}")

        # Content creator presence
        content_platforms = ["youtube", "twitch", "medium", "tumblr"]
        content_found = [
            p for p in content_platforms
            if results.get(p, {}).get("status") == "found"
        ]
        if content_found:
            flags.append(f"CONTENT_CREATOR: active on {', '.join(content_found)}")

        # Cross-platform consistency — same username everywhere suggests real identity
        if found_count >= 8:
            flags.append(
                "CONSISTENT_IDENTITY: same username active across many unrelated platforms"
            )

        return flags

    # ------------------------------------------------------------------ #
    #  Output helpers                                                      #
    # ------------------------------------------------------------------ #

    def _print_summary(self, username: str, found: int, checked: int, flags: list):
        """Print a colored summary with per-platform found list."""
        found_platforms = [
            platform for platform, r in self.PLATFORMS.items()
            # We need results here — passed via the caller
        ]

        if found >= 5:
            color = Fore.RED
            icon  = "[!]"
        elif found >= 1:
            color = Fore.YELLOW
            icon  = "[~]"
        else:
            color = Fore.GREEN
            icon  = "[+]"

        print(
            f"{color}{icon} Social Scan: @{username} — "
            f"{found} account(s) found across {checked} checked platforms"
            f"{Style.RESET_ALL}"
        )
        if flags:
            for flag in flags:
                print(f"  {Fore.YELLOW}→ {flag}{Style.RESET_ALL}")

    def _error_result(self, username: str, message: str) -> dict:
        """Standardised error dict."""
        print(f"{Fore.YELLOW}[!] Social Scan error: {message}{Style.RESET_ALL}")
        return {
            "username": username,
            "checked":  0,
            "found":    0,
            "results":  {},
            "flags":    [],
            "error":    message,
        }

    @staticmethod
    def _looks_like_username(value: str) -> bool:
        """Minimal check — non-empty and no spaces."""
        return bool(value) and " " not in value.strip() and len(value.strip()) >= 1
