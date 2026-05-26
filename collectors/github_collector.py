# collectors/github_collector.py
# ReconMind — GitHub Collector
# Pulls public profile data, repositories, recent activity, and org memberships
# for a target username.
#
# No API key required for basic use (60 req/hour unauthenticated).
# Optional: set GITHUB_TOKEN in config.py for 5000 req/hour.
 
import requests
import time
from colorama import Fore, Style, init
 
init()  # Required on Windows
 
# GitHub token is optional — unauthenticated works fine for testing
try:
    from config import GITHUB_TOKEN
except ImportError:
    GITHUB_TOKEN = None
 
 
class GitHubCollector:
    """
    Queries the GitHub REST API for a target username.
 
    Collects:
    - Profile metadata (name, bio, location, company, account age)
    - Public repositories with language and star data
    - Organisation memberships
    - Recent public activity (push events, issue comments, PRs)
    - Analyst flags (e.g. no activity, very new account, suspicious repo names)
    """
 
    BASE_URL = "https://api.github.com"
    REQUEST_DELAY = 0.5  # seconds between calls — stay well under 60 req/hour
 
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ReconMind-OSINT-Tool/1.0",
        })
        # Attach token if available — raises rate limit to 5000/hour
        if GITHUB_TOKEN:
            self.session.headers.update({"Authorization": f"Bearer {GITHUB_TOKEN}"})
 
    def collect(self, username: str) -> dict:
        """
        Main entry point. Accepts a GitHub username, returns a clean dict.
 
        Returns:
            {
                "username":       str,
                "found":          bool,
                "profile":        dict | None,
                "repositories":   list[dict],
                "organisations":  list[str],
                "activity":       list[dict],
                "top_languages":  list[str],
                "flags":          list[str],
                "error":          str | None
            }
        """
        print(f"\n{Fore.CYAN}[~] GitHub: Looking up @{username}...{Style.RESET_ALL}")
 
        if not self._looks_like_username(username):
            return self._error_result(username, "Invalid GitHub username format")
 
        # Step 1: Fetch profile — if this 404s, the user doesn't exist
        profile, err = self._fetch_profile(username)
        if err:
            return self._error_result(username, err)
        if not profile:
            print(f"{Fore.YELLOW}[-] GitHub: @{username} not found{Style.RESET_ALL}")
            return {
                "username":      username,
                "found":         False,
                "profile":       None,
                "repositories":  [],
                "organisations": [],
                "activity":      [],
                "top_languages": [],
                "flags":         ["ACCOUNT_NOT_FOUND"],
                "error":         None,
            }
 
        # Step 2: Fetch repos, orgs, activity in sequence with small delay
        time.sleep(self.REQUEST_DELAY)
        repos = self._fetch_repos(username)
 
        time.sleep(self.REQUEST_DELAY)
        orgs = self._fetch_orgs(username)
 
        time.sleep(self.REQUEST_DELAY)
        activity = self._fetch_activity(username)
 
        # Step 3: Derive top languages from repo data
        top_languages = self._extract_top_languages(repos)
 
        # Step 4: Build analyst flags
        flags = self._build_flags(profile, repos, activity)
 
        result = {
            "username":      username,
            "found":         True,
            "profile":       profile,
            "repositories":  repos,
            "organisations": orgs,
            "activity":      activity,
            "top_languages": top_languages,
            "flags":         flags,
            "error":         None,
        }
 
        self._print_status(result)
        return result
 
    # ------------------------------------------------------------------ #
    #  API fetch methods                                                   #
    # ------------------------------------------------------------------ #
 
    def _fetch_profile(self, username):
        """
        Fetches /users/{username}.
        Returns (profile_dict, None) on success, (None, error_str) on failure,
        or (None, None) if the user simply doesn't exist.
        """
        try:
            r = self.session.get(
                f"{self.BASE_URL}/users/{username}", timeout=10
            )
            if r.status_code == 404:
                return None, None   # user doesn't exist — not an error
            if r.status_code == 403:
                return None, "Rate limited by GitHub — add GITHUB_TOKEN to config.py"
            if r.status_code != 200:
                return None, f"Unexpected HTTP {r.status_code} from GitHub"
 
            u = r.json()
            return {
                "name":         u.get("name"),
                "bio":          u.get("bio"),
                "location":     u.get("location"),
                "company":      u.get("company"),
                "blog":         u.get("blog"),
                "email":        u.get("email"),          # only if user made it public
                "twitter":      u.get("twitter_username"),
                "public_repos": u.get("public_repos", 0),
                "followers":    u.get("followers", 0),
                "following":    u.get("following", 0),
                "created_at":   u.get("created_at", "")[:10],  # YYYY-MM-DD only
                "updated_at":   u.get("updated_at", "")[:10],
                "profile_url":  u.get("html_url"),
                "hireable":     u.get("hireable"),
                "site_admin":   u.get("site_admin", False),
            }, None
 
        except requests.Timeout:
            return None, "Request timed out fetching GitHub profile"
        except requests.ConnectionError:
            return None, "Connection failed — check internet access"
        except Exception as e:
            return None, f"Unexpected error: {str(e)}"
 
    def _fetch_repos(self, username):
        """
        Fetches /users/{username}/repos — top 10 by most recently pushed.
        Returns a list of repo dicts. Empty list on any failure.
        """
        try:
            r = self.session.get(
                f"{self.BASE_URL}/users/{username}/repos",
                params={"sort": "pushed", "per_page": 10},
                timeout=10,
            )
            if r.status_code != 200:
                return []
 
            repos = []
            for repo in r.json():
                repos.append({
                    "name":        repo.get("name"),
                    "description": repo.get("description"),
                    "language":    repo.get("language"),
                    "stars":       repo.get("stargazers_count", 0),
                    "forks":       repo.get("forks_count", 0),
                    "is_fork":     repo.get("fork", False),
                    "created_at":  repo.get("created_at", "")[:10],
                    "pushed_at":   repo.get("pushed_at", "")[:10],
                    "url":         repo.get("html_url"),
                    "topics":      repo.get("topics", []),
                })
            return repos
 
        except Exception:
            return []
 
    def _fetch_orgs(self, username):
        """
        Fetches /users/{username}/orgs — public org memberships.
        Returns a list of org name strings.
        """
        try:
            r = self.session.get(
                f"{self.BASE_URL}/users/{username}/orgs",
                params={"per_page": 20},
                timeout=10,
            )
            if r.status_code != 200:
                return []
            return [org.get("login") for org in r.json() if org.get("login")]
 
        except Exception:
            return []
 
    def _fetch_activity(self, username):
        """
        Fetches /users/{username}/events/public — last 5 public events.
        Summarises event type, repo name, and date rather than raw blobs.
        """
        try:
            r = self.session.get(
                f"{self.BASE_URL}/users/{username}/events/public",
                params={"per_page": 5},
                timeout=10,
            )
            if r.status_code != 200:
                return []
 
            events = []
            for event in r.json():
                events.append({
                    "type":       event.get("type"),      # e.g. PushEvent, IssueCommentEvent
                    "repo":       event.get("repo", {}).get("name"),
                    "created_at": event.get("created_at", "")[:10],
                })
            return events
 
        except Exception:
            return []
 
    # ------------------------------------------------------------------ #
    #  Derived data                                                        #
    # ------------------------------------------------------------------ #
 
    def _extract_top_languages(self, repos):
        """
        Counts language occurrences across all repos.
        Returns languages sorted by frequency, most common first.
        """
        counts = {}
        for repo in repos:
            lang = repo.get("language")
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
        return [lang for lang, _ in sorted(counts.items(), key=lambda x: x[1], reverse=True)]
 
    def _build_flags(self, profile, repos, activity):
        """
        Generates analyst-readable flags for the AI engine.
        These are risk/interest signals, not verdicts.
        """
        from datetime import datetime
        flags = []
 
        # Very new account — common in fake/throwaway profiles
        if profile.get("created_at"):
            try:
                created = datetime.strptime(profile["created_at"], "%Y-%m-%d")
                age_days = (datetime.utcnow() - created).days
                if age_days < 30:
                    flags.append("NEW_ACCOUNT: created less than 30 days ago")
                elif age_days < 90:
                    flags.append("RECENT_ACCOUNT: created less than 90 days ago")
            except Exception:
                pass
 
        # No repos at all — may be a lurker, scraper, or recon account
        if profile.get("public_repos", 0) == 0:
            flags.append("NO_PUBLIC_REPOS: account has no public repositories")
 
        # High follower count with no repos is unusual
        if profile.get("followers", 0) > 100 and profile.get("public_repos", 0) == 0:
            flags.append("FOLLOWER_REPO_MISMATCH: high followers but no public repos")
 
        # No recent activity
        if not activity:
            flags.append("NO_RECENT_ACTIVITY: no public events found")
 
        # Security/offensive-tool keywords in repo names or topics
        security_keywords = [
            "exploit", "payload", "c2", "malware", "rat", "botnet",
            "keylogger", "ransomware", "shellcode", "reverse-shell",
        ]
        all_topics = []
        all_names = []
        for repo in repos:
            all_topics.extend(repo.get("topics", []))
            all_names.append((repo.get("name") or "").lower())
 
        for kw in security_keywords:
            if any(kw in t.lower() for t in all_topics) or any(kw in n for n in all_names):
                flags.append(f"SECURITY_TOOL_PRESENT: repo name or topic contains '{kw}'")
                break  # one flag is enough
 
        # GitHub site admin — extremely rare, always noteworthy
        if profile.get("site_admin"):
            flags.append("GITHUB_STAFF: account is a GitHub site administrator")
 
        return flags
 
    # ------------------------------------------------------------------ #
    #  Output helpers                                                      #
    # ------------------------------------------------------------------ #
 
    def _print_status(self, result):
        """Print a colored summary line to the terminal."""
        p = result["profile"]
        flag_count = len(result["flags"])
        repo_count = len(result["repositories"])
        langs = ", ".join(result["top_languages"][:3]) or "none detected"
 
        if flag_count > 0:
            print(
                f"{Fore.YELLOW}[!] GitHub: @{result['username']} — "
                f"{p.get('followers', 0)} followers — "
                f"{repo_count} repos — {langs} — "
                f"{flag_count} flag(s): {result['flags'][0]}{Style.RESET_ALL}"
            )
        else:
            print(
                f"{Fore.GREEN}[+] GitHub: @{result['username']} — "
                f"{p.get('followers', 0)} followers — "
                f"{repo_count} repos — {langs} — no flags{Style.RESET_ALL}"
            )
 
    def _error_result(self, username, message):
        """Standardised error dict — always matches the expected shape."""
        print(f"{Fore.YELLOW}[!] GitHub error for @{username}: {message}{Style.RESET_ALL}")
        return {
            "username":      username,
            "found":         None,
            "profile":       None,
            "repositories":  [],
            "organisations": [],
            "activity":      [],
            "top_languages": [],
            "flags":         [],
            "error":         message,
        }
 
    @staticmethod
    def _looks_like_username(value):
        """GitHub usernames: 1-39 chars, no spaces."""
        return bool(value) and " " not in value and 1 <= len(value) <= 39
 
