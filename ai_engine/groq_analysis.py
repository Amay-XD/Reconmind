"""
╔══════════════════════════════════════════════════════════════════╗
║          ReconMind — AI-Powered OSINT Intelligence Engine        ║
║                     groq_analysis.py                             ║
║   AI Brain: Sends OSINT data to Groq and returns threat report   ║
╚══════════════════════════════════════════════════════════════════╝

This module is the core intelligence layer of ReconMind.
It receives a compiled OSINT dictionary from 6 data sources
(Shodan, HaveIBeenPwned, WhoisXML, GitHub, Google Dorks, Social Scan),
constructs a professional analyst prompt, calls the Groq API using
the llama-3.1-70b-versatile model, and parses the response into a
structured threat-intelligence report dictionary.

Author  : ReconMind Project
Module  : groq_analysis.py
Requires: groq, colorama
"""

# ──────────────────────────────────────────────────────────────────
# Standard library imports
# ──────────────────────────────────────────────────────────────────
import sys
import os
import json
import re
import textwrap
from datetime import datetime

# ──────────────────────────────────────────────────────────────────
# Third-party imports
# ──────────────────────────────────────────────────────────────────
try:
    from groq import Groq
except ImportError:
    print("[FATAL] 'groq' package not found. Run: pip install groq")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)  # Reset colour after every print automatically
except ImportError:
    print("[FATAL] 'colorama' package not found. Run: pip install colorama")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────
# Project config import — API key lives in config.py at repo root
# ──────────────────────────────────────────────────────────────────
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from config import GROQ_API_KEY
except ImportError:
    print(
        f"{Fore.RED}[ERROR] config.py not found or GROQ_API_KEY missing. "
        "Create config.py at the project root with GROQ_API_KEY = 'your-key'."
    )
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")  # Fallback to env var

# ──────────────────────────────────────────────────────────────────
# Module-level constants
# ──────────────────────────────────────────────────────────────────
MODEL_ID        = "llama3-70b-8192"   # Groq model to use
MAX_TOKENS      = 4096                          # Max tokens for the AI response
TEMPERATURE     = 0.3                           # Lower = more deterministic / analytical

# Risk-level thresholds (score out of 100)
RISK_THRESHOLDS = {
    "CRITICAL": 80,
    "HIGH":     60,
    "MEDIUM":   35,
    "LOW":       0,
}

# ──────────────────────────────────────────────────────────────────
# Helper: Coloured status printers
# ──────────────────────────────────────────────────────────────────

def _print_section(msg: str) -> None:
    """Print a cyan section-header message."""
    print(f"{Fore.CYAN}{Style.BRIGHT}[*] {msg}{Style.RESET_ALL}")


def _print_success(msg: str) -> None:
    """Print a green success message."""
    print(f"{Fore.GREEN}[✓] {msg}{Style.RESET_ALL}")


def _print_warning(msg: str) -> None:
    """Print a yellow warning message."""
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")


def _print_error(msg: str) -> None:
    """Print a red error message."""
    print(f"{Fore.RED}[✗] {msg}{Style.RESET_ALL}")


def _print_ai(msg: str) -> None:
    """Print a magenta AI-progress message."""
    print(f"{Fore.MAGENTA}[AI] {msg}{Style.RESET_ALL}")


def _print_risk(score: int, level: str) -> None:
    """Print risk score with colour-coded level."""
    colour_map = {
        "LOW":      Fore.GREEN,
        "MEDIUM":   Fore.YELLOW,
        "HIGH":     Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }
    colour = colour_map.get(level, Fore.WHITE)
    print(f"{colour}[RISK] Score: {score}/100  |  Level: {level}{Style.RESET_ALL}")


# ──────────────────────────────────────────────────────────────────
# Helper: Build the analyst prompt from OSINT data
# ──────────────────────────────────────────────────────────────────

def _build_prompt(osint_data: dict) -> str:
    """
    Construct a detailed analyst prompt from the raw OSINT dictionary.

    The prompt instructs the model to behave as a professional threat
    intelligence analyst, walks it through every data source that was
    collected, and asks for a strictly structured JSON + Markdown reply
    that we can reliably parse downstream.

    Args:
        osint_data: The compiled OSINT dictionary from all sources.

    Returns:
        A fully formed prompt string ready to send to Groq.
    """

    target = osint_data.get("target", "Unknown Target")

    # ── Shodan section ──────────────────────────────────────────
    shodan = osint_data.get("shodan", {})
    if shodan and not shodan.get("error"):
        shodan_block = f"""
SHODAN (IP Intelligence):
  - IP Address : {shodan.get('ip', 'N/A')}
  - Country    : {shodan.get('country', 'N/A')}
  - Organisation: {shodan.get('org', 'N/A')}
  - Open Ports : {shodan.get('open_ports', [])}
  - CVEs Found : {shodan.get('vulnerabilities', [])}
  - Services   : {json.dumps(shodan.get('services', []), indent=4)}
"""
    else:
        shodan_block = f"SHODAN: No data available (error: {shodan.get('error', 'not queried')})\n"

    # ── HaveIBeenPwned section ──────────────────────────────────
    hibp = osint_data.get("hibp", {})
    if hibp and not hibp.get("error"):
        hibp_block = f"""
HAVEIBEENPWNED (Breach Intelligence):
  - Email       : {hibp.get('email', 'N/A')}
  - Breached?   : {hibp.get('breached', False)}
  - Breach Count: {hibp.get('breach_count', 0)}
  - Breaches    : {hibp.get('breaches', [])}
"""
    else:
        hibp_block = f"HAVEIBEENPWNED: No data available (error: {hibp.get('error', 'not queried')})\n"

    # ── WHOIS section ───────────────────────────────────────────
    whois = osint_data.get("whois", {})
    if whois and not whois.get("error"):
        whois_block = f"""
WHOIS (Domain Intelligence):
  - Domain       : {whois.get('domain', 'N/A')}
  - Registrar    : {whois.get('registrar', 'N/A')}
  - Created      : {whois.get('creation_date', 'N/A')}
  - Expires      : {whois.get('expiry_date', 'N/A')}
  - Country      : {whois.get('country', 'N/A')}
"""
    else:
        whois_block = f"WHOIS: No data available (error: {whois.get('error', 'not queried')})\n"

    # ── GitHub section ──────────────────────────────────────────
    github = osint_data.get("github", {})
    if github and not github.get("error"):
        github_block = f"""
GITHUB (Developer Intelligence):
  - Username    : {github.get('username', 'N/A')}
  - Public Repos: {github.get('public_repos', 0)}
  - Followers   : {github.get('followers', 0)}
  - Repositories: {json.dumps(github.get('repos', []), indent=4)}
"""
    else:
        github_block = f"GITHUB: No data available (error: {github.get('error', 'not queried')})\n"

    # ── Google Dorks section ────────────────────────────────────
    dorks = osint_data.get("google_dorks", {})
    if dorks and not dorks.get("error"):
        dorks_block = f"""
GOOGLE DORKS (Exposed Content):
  - Target : {dorks.get('target', 'N/A')}
  - Results: {json.dumps(dorks.get('results', []), indent=4)}
"""
    else:
        dorks_block = f"GOOGLE DORKS: No data available (error: {dorks.get('error', 'not queried')})\n"

    # ── Social Scan section ─────────────────────────────────────
    social = osint_data.get("social_scan", {})
    if social and not social.get("error"):
        social_block = f"""
SOCIAL SCAN (Digital Footprint):
  - Username        : {social.get('username', 'N/A')}
  - Platforms Found : {social.get('platforms_found', [])}
"""
    else:
        social_block = f"SOCIAL SCAN: No data available (error: {social.get('error', 'not queried')})\n"

    # ── Assemble the full prompt ────────────────────────────────
    prompt = f"""You are an elite cybersecurity threat intelligence analyst with 15+ years of experience in OSINT, penetration testing, and digital forensics. You have been engaged by a client to produce a comprehensive threat intelligence report.

TASK:
Analyse the following OSINT data collected for target "{target}" and produce a professional threat intelligence assessment.

═══════════════════════════════════════════
COLLECTED OSINT DATA
═══════════════════════════════════════════
{shodan_block}
{hibp_block}
{whois_block}
{github_block}
{dorks_block}
{social_block}
═══════════════════════════════════════════

INSTRUCTIONS:
1. Evaluate ALL data sources holistically.
2. Assign a numeric RISK SCORE from 0 to 100 based on:
   - Number and severity of CVEs (high weight)
   - Credential breach presence and count (high weight)
   - Number of exposed services and open ports (medium weight)
   - Digital footprint breadth and social exposure (medium weight)
   - Domain age, registrar trust, expiry proximity (low weight)
   - GitHub exposure of sensitive or infrastructure code (low weight)
3. Map the score to a RISK LEVEL: LOW (0-34), MEDIUM (35-59), HIGH (60-79), CRITICAL (80-100).
4. Identify specific, real-world threats — not generic statements.
5. Provide concrete, prioritised, actionable recommendations.
6. Write a detailed professional report in clean Markdown.

OUTPUT FORMAT:
Return your response in exactly the following structure — first a JSON block, then the full Markdown report:

```json
{{
  "risk_score": <integer 0-100>,
  "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<2-3 sentence executive summary>",
  "findings": [
    "<finding 1>",
    "<finding 2>",
    "<finding 3>"
  ],
  "threats": [
    "<threat 1>",
    "<threat 2>",
    "<threat 3>"
  ],
  "recommendations": [
    "<recommendation 1>",
    "<recommendation 2>",
    "<recommendation 3>"
  ]
}}
```

```markdown
# Threat Intelligence Report — {target}
**Classification:** TLP:AMBER | **Date:** {datetime.now().strftime('%Y-%m-%d')} | **Prepared by:** ReconMind AI Engine

## Executive Summary
<2-3 paragraphs>

## Target Overview
<IP/domain/username context, ownership, geography>

## Key Findings
<Numbered list of significant findings with detail>

## Threat Analysis
<Deep-dive on each identified threat, attack vectors, real-world impact>

## Vulnerability Assessment
<CVE analysis, CVSS scores if known, exploitability context>

## Digital Footprint Analysis
<Social presence, exposed credentials, public code, dork results>

## Recommendations
<Numbered, prioritised, specific — include tooling/process suggestions>

## Conclusion
<Overall risk posture, urgency, next steps>
```

Important: Return ONLY the JSON block and the Markdown block as shown above. Do not add any commentary outside these two blocks.
"""

    return prompt


# ──────────────────────────────────────────────────────────────────
# Helper: Parse Groq response into structured dict
# ──────────────────────────────────────────────────────────────────

def _parse_response(raw_text: str, target: str) -> dict:
    """
    Extract structured fields and the full Markdown report from the
    raw text returned by the Groq model.

    The model is instructed to return a JSON block followed by a
    Markdown block. This function uses regex to locate and parse both.

    Falls back to safe defaults if any field is missing or malformed.

    Args:
        raw_text: The raw string content from the Groq API response.
        target  : The original scan target (used for fallback labelling).

    Returns:
        A dictionary with keys: target, risk_score, risk_level, summary,
        findings, threats, recommendations, full_report, error.
    """

    # ── Default / fallback result ───────────────────────────────
    result = {
        "target":          target,
        "risk_score":      0,
        "risk_level":      "UNKNOWN",
        "summary":         "Analysis could not be fully parsed.",
        "findings":        [],
        "threats":         [],
        "recommendations": [],
        "full_report":     raw_text,  # Always preserve the raw text
        "error":           None,
    }

    # ── Extract JSON block ──────────────────────────────────────
    json_match = re.search(
        r"```json\s*(.*?)\s*```",
        raw_text,
        re.DOTALL | re.IGNORECASE
    )

    if json_match:
        try:
            parsed_json = json.loads(json_match.group(1))

            result["risk_score"]      = int(parsed_json.get("risk_score", 0))
            result["risk_level"]      = str(parsed_json.get("risk_level", "UNKNOWN")).upper()
            result["summary"]         = str(parsed_json.get("summary", ""))
            result["findings"]        = list(parsed_json.get("findings", []))
            result["threats"]         = list(parsed_json.get("threats", []))
            result["recommendations"] = list(parsed_json.get("recommendations", []))

        except (json.JSONDecodeError, ValueError) as json_err:
            _print_warning(f"JSON parsing partially failed: {json_err} — using raw text fallback.")
    else:
        _print_warning("No JSON block found in AI response — attempting heuristic extraction.")

        # Heuristic fallback: try to scrape risk score from text
        score_match = re.search(r"risk[_\s]*score[:\s]+(\d{1,3})", raw_text, re.IGNORECASE)
        if score_match:
            result["risk_score"] = int(score_match.group(1))

        level_match = re.search(r"risk[_\s]*level[:\s]+(LOW|MEDIUM|HIGH|CRITICAL)", raw_text, re.IGNORECASE)
        if level_match:
            result["risk_level"] = level_match.group(1).upper()

    # ── Validate and clamp risk score ───────────────────────────
    result["risk_score"] = max(0, min(100, result["risk_score"]))

    # ── Derive risk level from score if model gave bad level ────
    if result["risk_level"] not in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"):
        score = result["risk_score"]
        if score >= RISK_THRESHOLDS["CRITICAL"]:
            result["risk_level"] = "CRITICAL"
        elif score >= RISK_THRESHOLDS["HIGH"]:
            result["risk_level"] = "HIGH"
        elif score >= RISK_THRESHOLDS["MEDIUM"]:
            result["risk_level"] = "MEDIUM"
        else:
            result["risk_level"] = "LOW"

    # ── Extract Markdown report block ───────────────────────────
    md_match = re.search(
        r"```markdown\s*(.*?)\s*```",
        raw_text,
        re.DOTALL | re.IGNORECASE
    )
    if md_match:
        result["full_report"] = md_match.group(1).strip()
    else:
        # If no markdown fence, use everything after the JSON block
        # (strip the json portion from the full text)
        if json_match:
            after_json = raw_text[json_match.end():].strip()
            if after_json:
                result["full_report"] = after_json

    return result


# ──────────────────────────────────────────────────────────────────
# Helper: Determine risk level from score (standalone utility)
# ──────────────────────────────────────────────────────────────────

def score_to_level(score: int) -> str:
    """
    Convert a numeric risk score (0–100) to a string risk level.

    Args:
        score: Integer between 0 and 100.

    Returns:
        One of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'.
    """
    if score >= RISK_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    elif score >= RISK_THRESHOLDS["HIGH"]:
        return "HIGH"
    elif score >= RISK_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


# ──────────────────────────────────────────────────────────────────
# Main public function
# ──────────────────────────────────────────────────────────────────

def analyze_target(osint_data: dict) -> dict:
    """
    Core entry point for AI-powered threat analysis.

    Accepts the compiled OSINT dictionary, builds a professional analyst
    prompt, calls the Groq LLM API, parses the structured response, and
    returns a complete threat-intelligence report as a Python dictionary.

    Args:
        osint_data: Dictionary containing OSINT results from all sources.
                    Expected keys: target, shodan, hibp, whois, github,
                    google_dorks, social_scan.

    Returns:
        Dictionary with keys:
            target          (str)   – original scan target
            risk_score      (int)   – 0-100 risk score
            risk_level      (str)   – LOW / MEDIUM / HIGH / CRITICAL
            summary         (str)   – 2-3 sentence executive summary
            findings        (list)  – key findings from OSINT data
            threats         (list)  – identified threats
            recommendations (list)  – actionable recommendations
            full_report     (str)   – complete Markdown report
            error           (any)   – None on success, error string on failure
    """

    target = osint_data.get("target", "Unknown Target")

    # ── Guard: API key must be present ──────────────────────────
    if not GROQ_API_KEY:
        _print_error("GROQ_API_KEY is not set. Cannot contact Groq API.")
        return {
            "target":          target,
            "risk_score":      0,
            "risk_level":      "UNKNOWN",
            "summary":         "",
            "findings":        [],
            "threats":         [],
            "recommendations": [],
            "full_report":     "",
            "error":           "GROQ_API_KEY not configured.",
        }

    # ── Progress: start ─────────────────────────────────────────
    print()
    _print_section("═" * 55)
    _print_section(f"ReconMind AI Analysis Engine — Target: {target}")
    _print_section("═" * 55)

    # ── Step 1: Build the prompt ─────────────────────────────────
    _print_section("Compiling OSINT data into analyst prompt …")
    try:
        prompt = _build_prompt(osint_data)
        _print_success(f"Prompt constructed ({len(prompt):,} characters).")
    except Exception as prompt_err:
        _print_error(f"Failed to build prompt: {prompt_err}")
        return {
            "target":          target,
            "risk_score":      0,
            "risk_level":      "UNKNOWN",
            "summary":         "",
            "findings":        [],
            "threats":         [],
            "recommendations": [],
            "full_report":     "",
            "error":           f"Prompt construction failed: {prompt_err}",
        }

    # ── Step 2: Initialise Groq client ───────────────────────────
    _print_section("Connecting to Groq API …")
    try:
        client = Groq(api_key=GROQ_API_KEY)
        _print_success("Groq client initialised successfully.")
    except Exception as client_err:
        _print_error(f"Groq client initialisation failed: {client_err}")
        return {
            "target":          target,
            "risk_score":      0,
            "risk_level":      "UNKNOWN",
            "summary":         "",
            "findings":        [],
            "threats":         [],
            "recommendations": [],
            "full_report":     "",
            "error":           f"Groq client error: {client_err}",
        }

    # ── Step 3: Call the API ─────────────────────────────────────
    _print_ai(f"Sending OSINT data to {MODEL_ID} for threat analysis …")
    _print_ai("This may take 15–45 seconds depending on data volume …")

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an elite cybersecurity threat intelligence analyst. "
                        "You produce precise, evidence-based threat assessments from OSINT data. "
                        "You always respond with a JSON block followed by a Markdown report block, "
                        "exactly as specified in the user prompt. No deviations."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            model=MODEL_ID,
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
        )
        _print_success("Groq API responded successfully.")
    except Exception as api_err:
        _print_error(f"Groq API call failed: {api_err}")
        return {
            "target":          target,
            "risk_score":      0,
            "risk_level":      "UNKNOWN",
            "summary":         "",
            "findings":        [],
            "threats":         [],
            "recommendations": [],
            "full_report":     "",
            "error":           f"Groq API error: {api_err}",
        }

    # ── Step 4: Extract raw text from response ───────────────────
    try:
        raw_text = chat_completion.choices[0].message.content
        if not raw_text or not raw_text.strip():
            raise ValueError("Empty response from Groq API.")
        _print_success(f"Received AI response ({len(raw_text):,} characters).")
    except (IndexError, AttributeError, ValueError) as extract_err:
        _print_error(f"Could not extract content from Groq response: {extract_err}")
        return {
            "target":          target,
            "risk_score":      0,
            "risk_level":      "UNKNOWN",
            "summary":         "",
            "findings":        [],
            "threats":         [],
            "recommendations": [],
            "full_report":     "",
            "error":           f"Response extraction failed: {extract_err}",
        }

    # ── Step 5: Parse into structured report ────────────────────
    _print_section("Parsing AI response into structured threat report …")
    try:
        report = _parse_response(raw_text, target)
        _print_success("Threat report parsed and structured successfully.")
    except Exception as parse_err:
        _print_error(f"Response parsing failed: {parse_err}")
        return {
            "target":          target,
            "risk_score":      0,
            "risk_level":      "UNKNOWN",
            "summary":         "",
            "findings":        [],
            "threats":         [],
            "recommendations": [],
            "full_report":     raw_text,
            "error":           f"Parse error: {parse_err}",
        }

    # ── Step 6: Pretty-print summary to terminal ─────────────────
    print()
    _print_section("── ANALYSIS COMPLETE ─────────────────────────────────")
    _print_risk(report["risk_score"], report["risk_level"])

    if report["summary"]:
        wrapped = textwrap.fill(report["summary"], width=72, initial_indent="    ", subsequent_indent="    ")
        print(f"{Fore.CYAN}[SUMMARY]\n{wrapped}{Style.RESET_ALL}")

    if report["findings"]:
        print(f"{Fore.CYAN}[KEY FINDINGS]{Style.RESET_ALL}")
        for i, finding in enumerate(report["findings"], 1):
            print(f"  {Fore.WHITE}{i}. {finding}{Style.RESET_ALL}")

    if report["threats"]:
        print(f"{Fore.RED}[THREATS IDENTIFIED]{Style.RESET_ALL}")
        for i, threat in enumerate(report["threats"], 1):
            print(f"  {Fore.YELLOW}{i}. {threat}{Style.RESET_ALL}")

    if report["recommendations"]:
        print(f"{Fore.GREEN}[RECOMMENDATIONS]{Style.RESET_ALL}")
        for i, rec in enumerate(report["recommendations"], 1):
            print(f"  {Fore.GREEN}{i}. {rec}{Style.RESET_ALL}")

    print()
    _print_success("ReconMind AI analysis pipeline complete.")
    _print_section("═" * 55)
    print()

    return report


# ──────────────────────────────────────────────────────────────────
# Direct test / demo block
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Self-contained test using realistic fake OSINT data.
    Run directly:  python groq_analysis.py
    """

    print(f"\n{Fore.CYAN}{Style.BRIGHT}")
    print("  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗")
    print("  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║")
    print("  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║")
    print("  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║")
    print("  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║")
    print("  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝")
    print(f"  ███╗   ███╗██╗███╗   ██╗██████╗")
    print(f"  ████╗ ████║██║████╗  ██║██╔══██╗")
    print(f"  ██╔████╔██║██║██╔██╗ ██║██║  ██║")
    print(f"  ██║╚██╔╝██║██║██║╚██╗██║██║  ██║")
    print(f"  ██║ ╚═╝ ██║██║██║ ╚████║██████╔╝")
    print(f"  ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝")
    print(f"{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  AI-Powered OSINT Intelligence Engine — groq_analysis.py test{Style.RESET_ALL}\n")

    # ── Realistic fake OSINT data ────────────────────────────────
    sample_osint = {
        "target": "192.168.100.50",

        "shodan": {
            "ip":              "192.168.100.50",
            "country":         "United States",
            "org":             "ACME Corp",
            "open_ports":      [22, 80, 443, 3306, 6379],
            "vulnerabilities": ["CVE-2021-44228", "CVE-2022-0778"],
            "services": [
                {"port": 22,   "banner": "OpenSSH 7.4",           "product": "OpenSSH",   "version": "7.4"},
                {"port": 80,   "banner": "Apache httpd 2.4.6",    "product": "Apache",    "version": "2.4.6"},
                {"port": 3306, "banner": "MySQL 5.7.38",           "product": "MySQL",     "version": "5.7.38"},
                {"port": 6379, "banner": "Redis 6.2.6 (no auth)",  "product": "Redis",     "version": "6.2.6"},
            ],
            "error": None,
        },

        "hibp": {
            "email":        "admin@acmecorp.com",
            "breached":     True,
            "breach_count": 3,
            "breaches":     ["Adobe", "LinkedIn", "RockYou2021"],
            "error":        None,
        },

        "whois": {
            "domain":        "acmecorp.com",
            "registrar":     "GoDaddy LLC",
            "creation_date": "2005-03-22",
            "expiry_date":   "2025-03-22",   # <-- Expiring soon!
            "country":       "US",
            "error":         None,
        },

        "github": {
            "username":     "acme-devops",
            "public_repos": 14,
            "followers":    42,
            "repos": [
                {"name": "infra-scripts",  "description": "Internal server scripts",    "language": "Python"},
                {"name": "aws-terraform",  "description": "Terraform configs for AWS",  "language": "HCL"},
                {"name": "api-keys-backup","description": "DO NOT USE — legacy",        "language": None},
            ],
            "error": None,
        },

        "google_dorks": {
            "target": "acmecorp.com",
            "results": [
                {"title": "ACME Corp Login Portal",   "url": "https://acmecorp.com/admin/login",        "snippet": "Admin panel login"},
                {"title": "ACME Corp Config Exposed", "url": "https://acmecorp.com/.env",               "snippet": "DB_PASSWORD=..."},
                {"title": "ACME Corp Backup File",    "url": "https://acmecorp.com/backup_2023.sql.gz", "snippet": "Database backup"},
            ],
            "error": None,
        },

        "social_scan": {
            "username":         "acmecorp",
            "platforms_found":  ["twitter", "linkedin", "instagram", "github", "reddit"],
            "error":            None,
        },
    }

    # ── Run the analysis ─────────────────────────────────────────
    report = analyze_target(sample_osint)

    # ── Display result summary ───────────────────────────────────
    if report.get("error"):
        _print_error(f"Analysis returned an error: {report['error']}")
    else:
        _print_success("Analysis completed. Report preview (first 1,500 chars of full_report):")
        print()
        print(f"{Fore.WHITE}{report['full_report'][:1500]}{Style.RESET_ALL}")
        if len(report["full_report"]) > 1500:
            print(f"{Fore.CYAN}… [truncated — full report is {len(report['full_report']):,} chars]{Style.RESET_ALL}")

    print()
    _print_section("Test run complete.")
