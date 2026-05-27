"""
╔══════════════════════════════════════════════════════════════════╗
║          ReconMind — AI-Powered OSINT Intelligence Engine        ║
║                      terminal_report.py                          ║
║    Beautiful, professional coloured threat report renderer       ║
╚══════════════════════════════════════════════════════════════════╝

This module takes the structured report dictionary produced by
groq_analysis.py and renders it as a stunning, colour-coded terminal
report with risk indicators, section dividers, and formatted content.

Author  : Amay Jogdand
Module  : terminal_report.py
Requires: colorama
"""

# ──────────────────────────────────────────────────────────────────
# Standard library imports
# ──────────────────────────────────────────────────────────────────
import textwrap
import re
from datetime import datetime

# ──────────────────────────────────────────────────────────────────
# Third-party imports
# ──────────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Back, Style, init as colorama_init
    # autoreset=True resets colour automatically after each print —
    # critical for Windows terminal compatibility
    colorama_init(autoreset=True, strip=False)
except ImportError:
    print("[FATAL] colorama not installed. Run: pip install colorama")
    raise

# ──────────────────────────────────────────────────────────────────
# Layout constants — change these to resize the whole report at once
# ──────────────────────────────────────────────────────────────────
REPORT_WIDTH   = 62   # Total character width of the outer box
CONTENT_WIDTH  = 70   # Wrap width for body text
BAR_LENGTH     = 10   # Number of block chars in the risk progress bar
DIVIDER_CHAR   = "━"  # Section divider character
BOX_H          = "═"  # Horizontal box-drawing character
BOX_TL         = "╔"  # Top-left corner
BOX_TR         = "╗"  # Top-right corner
BOX_BL         = "╚"  # Bottom-left corner
BOX_BR         = "╝"  # Bottom-right corner
BOX_SIDE       = "║"  # Vertical side character
BLOCK_FILLED   = "█"  # Filled block for risk bar
BLOCK_EMPTY    = "░"  # Empty block for risk bar


# ──────────────────────────────────────────────────────────────────
# Risk level colour / label lookup
# Maps a risk_level string → (colorama colour, display label)
# ──────────────────────────────────────────────────────────────────
RISK_STYLES = {
    "LOW":      (Fore.GREEN,                    "LOW"),
    "MEDIUM":   (Fore.YELLOW,                   "MEDIUM"),
    "HIGH":     (Fore.RED,                      "HIGH"),
    "CRITICAL": (Fore.RED + Style.BRIGHT,       "CRITICAL"),
    "UNKNOWN":  (Fore.WHITE,                    "UNKNOWN"),
}


# ══════════════════════════════════════════════════════════════════
#  LOW-LEVEL DRAWING HELPERS
# ══════════════════════════════════════════════════════════════════

def _divider(colour: str = "") -> None:
    """Print a full-width horizontal section divider."""
    print(f"{colour}{DIVIDER_CHAR * REPORT_WIDTH}{Style.RESET_ALL}")


def _box_top(title: str = "", colour: str = "") -> None:
    """
    Print the top border of a double-line box, optionally with a
    centred title padded to REPORT_WIDTH.
    """
    if title:
        # Pad title to fit inside the box borders (subtract 2 for ║ chars)
        inner = title.center(REPORT_WIDTH - 2)
        print(f"{colour}{BOX_TL}{BOX_H * (REPORT_WIDTH - 2)}{BOX_TR}")
        print(f"{BOX_SIDE}{inner}{BOX_SIDE}")
        print(f"{BOX_BL}{BOX_H * (REPORT_WIDTH - 2)}{BOX_BR}{Style.RESET_ALL}")
    else:
        print(f"{colour}{BOX_TL}{BOX_H * (REPORT_WIDTH - 2)}{BOX_TR}{Style.RESET_ALL}")


def _box_bottom(colour: str = "") -> None:
    """Print the bottom border of a double-line box."""
    print(f"{colour}{BOX_BL}{BOX_H * (REPORT_WIDTH - 2)}{BOX_BR}{Style.RESET_ALL}")


def _section_header(title: str, colour: str = "") -> None:
    """Print a divider-wrapped section header."""
    _divider(colour)
    print(f"{colour}{Style.BRIGHT}{title}{Style.RESET_ALL}")
    _divider(colour)


def _blank() -> None:
    """Print an empty line for breathing room."""
    print()


def _wrap_print(text: str, indent: str = "  ", colour: str = "") -> None:
    """
    Word-wrap text to CONTENT_WIDTH and print with optional indent
    and colour.  Handles None gracefully.
    """
    if not text:
        print(f"{colour}{indent}(no data){Style.RESET_ALL}")
        return
    lines = textwrap.wrap(str(text), width=CONTENT_WIDTH)
    for line in lines:
        print(f"{colour}{indent}{line}{Style.RESET_ALL}")


def _strip_markdown(text: str) -> str:
    """
    Lightly strip common Markdown syntax so the full_report renders
    cleanly in a plain terminal without raw **, ##, `` cluttering output.
    We preserve indentation and list structure.
    """
    if not text:
        return ""
    # Remove bold/italic markers
    text = re.sub(r"\*{1,3}(.+?)\*{1,3}", r"\1", text)
    # Remove inline code backticks
    text = re.sub(r"`(.+?)`", r"\1", text)
    # Convert ## Heading → HEADING (capitalised, no hash)
    text = re.sub(r"^#{1,6}\s*(.+)$", lambda m: m.group(1).upper(), text, flags=re.MULTILINE)
    # Remove horizontal rules (--- or ***)
    text = re.sub(r"^[-\*]{3,}\s*$", DIVIDER_CHAR * 40, text, flags=re.MULTILINE)
    return text


# ══════════════════════════════════════════════════════════════════
#  RISK BAR RENDERER
# ══════════════════════════════════════════════════════════════════

def _risk_bar(score: int, level: str) -> str:
    """
    Build a colour-coded visual progress bar string for the risk score.

    Example outputs:
      LOW      [██░░░░░░░░]  25/100
      MEDIUM   [█████░░░░░]  50/100
      HIGH     [███████░░░]  75/100
      CRITICAL [██████████]  95/100

    Args:
        score: Integer 0–100.
        level: Risk level string (LOW / MEDIUM / HIGH / CRITICAL).

    Returns:
        A coloured string ready to print.
    """
    # Clamp score to valid range
    score = max(0, min(100, int(score)))

    # How many filled blocks out of BAR_LENGTH?
    filled = round((score / 100) * BAR_LENGTH)
    empty  = BAR_LENGTH - filled

    bar_body = BLOCK_FILLED * filled + BLOCK_EMPTY * empty

    # Pick colour from RISK_STYLES; default to magenta for bar itself
    risk_colour, label = RISK_STYLES.get(level.upper(), (Fore.MAGENTA, level))

    bar_str = (
        f"{Fore.MAGENTA}[{risk_colour}{Style.BRIGHT}{bar_body}"
        f"{Fore.MAGENTA}]{Style.RESET_ALL} "
        f"{risk_colour}{Style.BRIGHT}{label:<8}{Style.RESET_ALL} "
        f"{Fore.WHITE}{score}/100{Style.RESET_ALL}"
    )
    return bar_str


# ══════════════════════════════════════════════════════════════════
#  SECTION RENDERERS
# ══════════════════════════════════════════════════════════════════

def _render_header(report: dict) -> None:
    """
    Print the top banner box with the report title.
    Always CYAN regardless of risk level.
    """
    _blank()
    _box_top("RECONMIND THREAT INTELLIGENCE REPORT", Fore.CYAN)


def _render_meta(report: dict) -> None:
    """
    Print the target metadata block:
    TARGET, SCAN DATE, RISK SCORE, RISK LEVEL (with bar).
    """
    target     = report.get("target", "Unknown")
    risk_score = report.get("risk_score", 0)
    risk_level = report.get("risk_level", "UNKNOWN").upper()
    scan_date  = datetime.now().strftime("%Y-%m-%d  %H:%M UTC")

    _blank()
    # Each metadata line: label in bright cyan, value in white
    print(
        f"  {Fore.CYAN}{Style.BRIGHT}{'TARGET':<12}{Style.RESET_ALL}"
        f": {Fore.WHITE}{target}{Style.RESET_ALL}"
    )
    print(
        f"  {Fore.CYAN}{Style.BRIGHT}{'SCAN DATE':<12}{Style.RESET_ALL}"
        f": {Fore.WHITE}{scan_date}{Style.RESET_ALL}"
    )
    print(
        f"  {Fore.CYAN}{Style.BRIGHT}{'RISK SCORE':<12}{Style.RESET_ALL}"
        f": {_risk_bar(risk_score, risk_level)}"
    )
    _blank()


def _render_summary(report: dict) -> None:
    """
    Print the Executive Summary section.
    Colour depends on risk level — calm cyan for LOW, escalates to RED.
    """
    level   = report.get("risk_level", "UNKNOWN").upper()
    colour  = RISK_STYLES.get(level, (Fore.CYAN,))[0]
    summary = report.get("summary", "")

    _section_header("  EXECUTIVE SUMMARY", Fore.CYAN)
    _blank()
    _wrap_print(summary, indent="  ", colour=Fore.WHITE)
    _blank()


def _render_findings(report: dict) -> None:
    """
    Print the Key Findings section.
    Each finding is numbered and coloured YELLOW (moderate attention).
    """
    findings = report.get("findings") or []

    _section_header("  KEY FINDINGS", Fore.CYAN)
    _blank()

    if not findings:
        print(f"  {Fore.WHITE}No findings recorded.{Style.RESET_ALL}")
    else:
        for i, item in enumerate(findings, start=1):
            # Zero-padded index  [01], [02] …
            label = f"[{i:02d}]"
            print(
                f"  {Fore.YELLOW}{Style.BRIGHT}{label}{Style.RESET_ALL} "
                f"{Fore.YELLOW}{item}{Style.RESET_ALL}"
            )
    _blank()


def _render_threats(report: dict) -> None:
    """
    Print the Threats Identified section.
    Each threat gets a ⚠ warning symbol and RED colouring to signal danger.
    """
    threats = report.get("threats") or []
    level   = report.get("risk_level", "UNKNOWN").upper()

    # Use CRITICAL bright-red for critical threats, plain red otherwise
    threat_colour = Fore.RED + Style.BRIGHT if level == "CRITICAL" else Fore.RED

    _section_header("  THREATS IDENTIFIED", Fore.CYAN)
    _blank()

    if not threats:
        print(f"  {Fore.GREEN}No active threats identified.{Style.RESET_ALL}")
    else:
        for item in threats:
            print(
                f"  {threat_colour}⚠  {item}{Style.RESET_ALL}"
            )
    _blank()


def _render_recommendations(report: dict) -> None:
    """
    Print the Recommendations section.
    Numbered with a ✓ checkmark and GREEN colouring — these are positive actions.
    """
    recs = report.get("recommendations") or []

    _section_header("  RECOMMENDATIONS", Fore.CYAN)
    _blank()

    if not recs:
        print(f"  {Fore.WHITE}No recommendations available.{Style.RESET_ALL}")
    else:
        for i, item in enumerate(recs, start=1):
            label = f"[{i:02d}]"
            print(
                f"  {Fore.GREEN}{Style.BRIGHT}{label} ✓{Style.RESET_ALL} "
                f"{Fore.GREEN}{item}{Style.RESET_ALL}"
            )
    _blank()


def _render_full_report(report: dict) -> None:
    """
    Print the Full Report section.

    The full_report value is a Markdown string produced by the AI.
    We lightly strip Markdown syntax, then render it with smart
    colour rules:
      - Lines that look like headings (ALL CAPS after strip) → CYAN BRIGHT
      - Lines starting with  - or * or numbers  → WHITE (list items)
      - Everything else → dim white body text
    """
    full_report = report.get("full_report", "")

    _section_header("  FULL INTELLIGENCE REPORT", Fore.CYAN)
    _blank()

    if not full_report:
        print(f"  {Fore.WHITE}(Full report not available){Style.RESET_ALL}")
        _blank()
        return

    cleaned = _strip_markdown(full_report)

    for raw_line in cleaned.splitlines():
        line = raw_line.rstrip()

        # ── Blank lines → blank output ──────────────────────
        if not line.strip():
            print()
            continue

        stripped = line.strip()

        # ── Section dividers (━━━━…) → cyan ─────────────────
        if set(stripped) <= {DIVIDER_CHAR, "-", "=", "*", " "}:
            print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
            continue

        # ── ALL-CAPS headings → bright cyan ──────────────────
        # A heading is stripped line that's mostly uppercase letters/spaces
        words = stripped.split()
        if (
            len(words) >= 1
            and all(w.isupper() or not w.isalpha() for w in words)
            and len(stripped) <= 60
        ):
            print(f"{Fore.CYAN}{Style.BRIGHT}{line}{Style.RESET_ALL}")
            continue

        # ── TLP / classification / date lines → magenta ──────
        if any(kw in stripped.upper() for kw in ("TLP:", "CLASSIFICATION", "PREPARED BY", "DATE:")):
            print(f"{Fore.MAGENTA}{line}{Style.RESET_ALL}")
            continue

        # ── CVE references → red ─────────────────────────────
        if re.search(r"CVE-\d{4}-\d+", stripped, re.IGNORECASE):
            # Highlight the CVE token in bright red, rest in white
            highlighted = re.sub(
                r"(CVE-\d{4}-\d+)",
                f"{Fore.RED}{Style.BRIGHT}\\1{Style.RESET_ALL}{Fore.WHITE}",
                line
            )
            print(f"{Fore.WHITE}{highlighted}{Style.RESET_ALL}")
            continue

        # ── List items (-, *, numbered) → yellow ─────────────
        if re.match(r"^\s*([-*•]|\d+[.)]) ", line):
            print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
            continue

        # ── Risk / threat keywords → soft red ────────────────
        danger_words = (
            "critical", "high risk", "severe", "exploit", "breach",
            "vulnerability", "attack", "malicious", "unauthorized",
            "compromised", "exposed", "unauthenticated"
        )
        if any(dw in stripped.lower() for dw in danger_words):
            print(f"{Fore.RED}{line}{Style.RESET_ALL}")
            continue

        # ── Recommendation / positive keywords → soft green ──
        good_words = (
            "recommend", "patch", "update", "mitigate", "secure",
            "implement", "enable", "configure", "monitor", "protect"
        )
        if any(gw in stripped.lower() for gw in good_words):
            print(f"{Fore.GREEN}{line}{Style.RESET_ALL}")
            continue

        # ── Default → plain white body text ──────────────────
        print(f"{Fore.WHITE}{line}{Style.RESET_ALL}")

    _blank()


def _render_footer() -> None:
    """Print the closing box border."""
    _box_top("END OF REPORT", Fore.CYAN)
    _blank()


def _render_error(report: dict) -> None:
    """
    If the report contains an error key, print a prominent red
    error notice before the rest of the report.
    """
    error = report.get("error")
    if error:
        _blank()
        _divider(Fore.RED)
        print(f"{Fore.RED}{Style.BRIGHT}  ⚠  ANALYSIS ERROR DETECTED{Style.RESET_ALL}")
        _wrap_print(str(error), indent="  ", colour=Fore.RED)
        _divider(Fore.RED)
        _blank()


# ══════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════

def print_report(report: dict) -> None:
    """
    Render the full, multi-section threat intelligence report to stdout.

    Sections printed (in order):
      1. Header banner box
      2. Target metadata (target, date, risk score + bar)
      3. Error notice (only if report contains an error)
      4. Executive Summary
      5. Key Findings
      6. Threats Identified
      7. Recommendations
      8. Full Intelligence Report (AI-generated Markdown)
      9. Footer box

    Args:
        report: Dictionary produced by groq_analysis.analyze_target().
                Missing keys are handled gracefully.
    """
    if not isinstance(report, dict):
        print(f"{Fore.RED}[ERROR] print_report() expects a dict, got {type(report)}{Style.RESET_ALL}")
        return

    _render_header(report)
    _render_meta(report)
    _render_error(report)
    _render_summary(report)
    _render_findings(report)
    _render_threats(report)
    _render_recommendations(report)
    _render_full_report(report)
    _render_footer()


def print_summary(report: dict) -> None:
    """
    Render a concise one-page summary of the threat report to stdout.

    Includes: header, metadata, summary text, top-3 findings,
    top-3 threats, top-3 recommendations, and footer.
    Ideal for quick status checks or piped output.

    Args:
        report: Dictionary produced by groq_analysis.analyze_target().
    """
    if not isinstance(report, dict):
        print(f"{Fore.RED}[ERROR] print_summary() expects a dict, got {type(report)}{Style.RESET_ALL}")
        return

    # ── Header ──────────────────────────────────────────────────
    _blank()
    _box_top("RECONMIND  ·  THREAT SUMMARY", Fore.CYAN)

    # ── Meta ────────────────────────────────────────────────────
    target     = report.get("target", "Unknown")
    risk_score = report.get("risk_score", 0)
    risk_level = report.get("risk_level", "UNKNOWN").upper()
    scan_date  = datetime.now().strftime("%Y-%m-%d")

    _blank()
    print(f"  {Fore.CYAN}{Style.BRIGHT}{'TARGET':<12}{Style.RESET_ALL}: {Fore.WHITE}{target}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}{'DATE':<12}{Style.RESET_ALL}: {Fore.WHITE}{scan_date}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}{'RISK':<12}{Style.RESET_ALL}: {_risk_bar(risk_score, risk_level)}")
    _blank()

    # ── Error notice ────────────────────────────────────────────
    _render_error(report)

    # ── Summary (truncated to 3 wrapped lines) ──────────────────
    summary = report.get("summary", "")
    if summary:
        _divider(Fore.CYAN)
        print(f"{Fore.CYAN}{Style.BRIGHT}  SUMMARY{Style.RESET_ALL}")
        _divider(Fore.CYAN)
        _blank()
        # Limit to first 300 characters to keep it brief
        short = (summary[:300] + "…") if len(summary) > 300 else summary
        _wrap_print(short, indent="  ", colour=Fore.WHITE)
        _blank()

    # ── Top 3 findings ──────────────────────────────────────────
    findings = (report.get("findings") or [])[:3]
    if findings:
        _divider(Fore.CYAN)
        print(f"{Fore.CYAN}{Style.BRIGHT}  TOP FINDINGS{Style.RESET_ALL}")
        _divider(Fore.CYAN)
        _blank()
        for i, item in enumerate(findings, 1):
            print(f"  {Fore.YELLOW}[{i:02d}] {item}{Style.RESET_ALL}")
        _blank()

    # ── Top 3 threats ───────────────────────────────────────────
    threats = (report.get("threats") or [])[:3]
    if threats:
        _divider(Fore.CYAN)
        print(f"{Fore.CYAN}{Style.BRIGHT}  TOP THREATS{Style.RESET_ALL}")
        _divider(Fore.CYAN)
        _blank()
        for item in threats:
            print(f"  {Fore.RED}⚠  {item}{Style.RESET_ALL}")
        _blank()

    # ── Top 3 recommendations ───────────────────────────────────
    recs = (report.get("recommendations") or [])[:3]
    if recs:
        _divider(Fore.CYAN)
        print(f"{Fore.CYAN}{Style.BRIGHT}  TOP RECOMMENDATIONS{Style.RESET_ALL}")
        _divider(Fore.CYAN)
        _blank()
        for i, item in enumerate(recs, 1):
            print(f"  {Fore.GREEN}[{i:02d}] ✓ {item}{Style.RESET_ALL}")
        _blank()

    _box_top("END OF SUMMARY", Fore.CYAN)
    _blank()


# ══════════════════════════════════════════════════════════════════
#  DIRECT TEST / DEMO
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    Self-contained demo using realistic fake report data.
    Run directly:  python terminal_report.py
    """

    # ── Fake report simulating a HIGH-risk target ────────────────
    sample_report = {
        "target":     "192.168.100.50",
        "risk_score": 78,
        "risk_level": "HIGH",

        "summary": (
            "Target 192.168.100.50 (ACME Corp) presents a HIGH risk profile based on "
            "corroborated OSINT evidence. Multiple critical CVEs are present on exposed "
            "services, administrative credentials have appeared in three public breach "
            "databases, and an unauthenticated Redis instance is accessible from the "
            "internet. Immediate remediation is strongly advised."
        ),

        "findings": [
            "Redis 6.2.6 running on port 6379 with NO authentication — full read/write access",
            "CVE-2021-44228 (Log4Shell, CVSS 10.0) detected on Apache service (port 80)",
            "CVE-2022-0778 (OpenSSL infinite loop, CVSS 7.5) present on port 443",
            "admin@acmecorp.com found in 3 breach databases: Adobe, LinkedIn, RockYou2021",
            "GitHub repo 'api-keys-backup' publicly accessible — potential credential exposure",
            "Domain acmecorp.com expires in < 30 days — hijacking risk if not renewed",
            ".env file and SQL backup exposed via Google Dorks",
        ],

        "threats": [
            "Remote Code Execution via Log4Shell (CVE-2021-44228) — actively exploited in the wild",
            "Full Redis database compromise enabling data exfiltration and ransomware deployment",
            "Credential stuffing attack using breached admin passwords from RockYou2021",
            "Domain hijacking if acmecorp.com registration lapses before renewal",
            "Sensitive API key extraction from publicly visible GitHub repository",
            "Denial-of-Service via OpenSSL infinite loop (CVE-2022-0778)",
        ],

        "recommendations": [
            "URGENT: Patch Apache to mitigate CVE-2021-44228 — apply vendor hotfix within 24h",
            "URGENT: Add requirepass directive to Redis config and restrict port 6379 via firewall",
            "Rotate ALL credentials associated with admin@acmecorp.com immediately",
            "Renew acmecorp.com domain registration — set auto-renew to prevent lapse",
            "Archive or make private the 'api-keys-backup' GitHub repository; rotate any exposed keys",
            "Remove or restrict .env file and backup.sql.gz from public web root",
            "Update OpenSSL to 1.1.1n+ or 3.0.2+ to remediate CVE-2022-0778",
        ],

        "full_report": """\
# Threat Intelligence Report — 192.168.100.50
**Classification:** TLP:AMBER | **Date:** 2026-05-25 | **Prepared by:** ReconMind AI Engine

---

## Executive Summary

Target 192.168.100.50, attributed to ACME Corp (US), presents a HIGH threat profile
based on multi-source OSINT analysis conducted by the ReconMind intelligence engine.

Active exploitation vectors exist via two critical CVEs on internet-facing services.
Credential intelligence confirms admin-level email addresses are present in major breach
repositories, substantially elevating the risk of account takeover.

Immediate containment and remediation action is required within 24–48 hours.

---

## Target Overview

- **IP Address:** 192.168.100.50
- **Organisation:** ACME Corp
- **Country:** United States
- **Open Ports:** 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 6379 (Redis)
- **Domain:** acmecorp.com | Registrar: GoDaddy LLC | Expires: 2025-03-22

---

## Key Findings

1. **Log4Shell (CVE-2021-44228)** — Apache 2.4.6 on port 80 is vulnerable to one of the
   most critical RCE vulnerabilities ever discovered. Exploits are freely available.

2. **Unauthenticated Redis** — Redis 6.2.6 on port 6379 accepts connections without a
   password. An attacker can dump the entire database, write arbitrary files, or use
   the instance as a pivot point.

3. **Credential Breach** — admin@acmecorp.com appears in Adobe (2013), LinkedIn (2016),
   and RockYou2021 datasets. Password reuse is a high-probability attack vector.

4. **Exposed .env and SQL Backup** — Google Dork results reveal a publicly accessible
   .env file containing database credentials and a compressed SQL backup file.

---

## Threat Analysis

### Remote Code Execution (CVE-2021-44228)
Log4Shell allows unauthenticated remote code execution via a crafted JNDI lookup string
injected into any logged HTTP header. CVSS score: 10.0 (Critical). Exploit kits are
widely available and exploitation has been observed as early as 2021-12-10.

### Data Exfiltration via Redis
An unauthenticated Redis instance is a textbook initial access and lateral movement
vector. Threat actors commonly use it to deploy webshells, establish persistence via
cron job injection, and exfiltrate in-memory session tokens and cached credentials.

### Credential Stuffing
With plaintext passwords available in RockYou2021 (8.4B+ entries) and LinkedIn (117M),
automated tools such as Hydra or Burp Intruder can perform credential stuffing attacks
against the SSH service (port 22) and any web login pages in minutes.

---

## Vulnerability Assessment

| CVE              | CVSS  | Service         | Exploitability |
|------------------|-------|-----------------|----------------|
| CVE-2021-44228   | 10.0  | Apache 2.4.6    | CRITICAL — PoC public |
| CVE-2022-0778    |  7.5  | OpenSSL (443)   | HIGH — DoS vector |

---

## Digital Footprint Analysis

- **Social Presence:** acmecorp found on Twitter, LinkedIn, Instagram, GitHub, Reddit
- **GitHub Exposure:** Public repo 'api-keys-backup' suggests historical secrets leak
- **Dork Results:** .env file and .sql.gz backup accessible without authentication
- **Domain Risk:** acmecorp.com expires 2025-03-22 — less than 30 days from scan date

---

## Recommendations

1. Patch CVE-2021-44228 immediately — upgrade Log4j to 2.17.1+ or apply WAF mitigation
2. Authenticate Redis — set requirepass, bind to 127.0.0.1, block external port 6379
3. Rotate all credentials for admin@acmecorp.com across all platforms
4. Remove or restrict .env and backup files from public web root
5. Renew acmecorp.com domain and enable auto-renewal
6. Make 'api-keys-backup' GitHub repo private; rotate any exposed secrets
7. Upgrade OpenSSL to 3.0.2+ to mitigate CVE-2022-0778

---

## Conclusion

ACME Corp's internet-facing infrastructure demonstrates multiple critical security gaps
that represent an immediate and material risk of compromise. The combination of an
exploitable RCE vulnerability, unauthenticated data store, and publicly breached
credentials creates a high-probability attack scenario.

**Recommended action timeline:** 24h for CVE patching and Redis hardening, 48h for
credential rotation and secret cleanup, 7 days for full infrastructure security review.
""",

        "error": None,
    }

    # ── Demo: full report ────────────────────────────────────────
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}  ══ DEMO: FULL REPORT ══{Style.RESET_ALL}")
    print_report(sample_report)

    # ── Demo: summary ────────────────────────────────────────────
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}  ══ DEMO: QUICK SUMMARY ══{Style.RESET_ALL}")
    print_summary(sample_report)

    # ── Demo: CRITICAL risk level ────────────────────────────────
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}  ══ DEMO: CRITICAL RISK BAR ══{Style.RESET_ALL}\n")
    for score, level in [(15, "LOW"), (48, "MEDIUM"), (73, "HIGH"), (92, "CRITICAL")]:
        label = f"  {level:<8}"
        bar   = _risk_bar(score, level)
        print(f"{Fore.CYAN}{label}{Style.RESET_ALL} {bar}")
    print()
