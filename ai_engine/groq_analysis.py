"""
╔══════════════════════════════════════════════════════════════════╗
║          ReconMind — AI-Powered OSINT Intelligence Engine        ║
║                     groq_analysis.py                             ║
║   AI Brain: Sends OSINT data to Groq and returns threat report   ║
╚══════════════════════════════════════════════════════════════════╝

Author  : Amay Jogdand 
Module  : groq_analysis.py
Requires: groq, colorama
"""

import sys
import os
import json
import re
import textwrap
from datetime import datetime

try:
    from groq import Groq
except ImportError:
    print("[FATAL] 'groq' package not found. Run: pip install groq")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("[FATAL] 'colorama' package not found. Run: pip install colorama")
    sys.exit(1)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from config import GROQ_API_KEY
except ImportError:
    print(f"{Fore.RED}[ERROR] config.py not found or GROQ_API_KEY missing.")
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

MODEL_ID = "llama-3.3-70b-versatile"
MAX_TOKENS  = 4096
TEMPERATURE = 0.3

RISK_THRESHOLDS = {
    "CRITICAL": 80,
    "HIGH":     60,
    "MEDIUM":   35,
    "LOW":       0,
}

# ── Terminal helpers ──────────────────────────────────────────────
def _print_section(msg):  print(f"{Fore.CYAN}{Style.BRIGHT}[*] {msg}{Style.RESET_ALL}")
def _print_success(msg):  print(f"{Fore.GREEN}[✓] {msg}{Style.RESET_ALL}")
def _print_warning(msg):  print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
def _print_error(msg):    print(f"{Fore.RED}[✗] {msg}{Style.RESET_ALL}")
def _print_ai(msg):       print(f"{Fore.MAGENTA}[AI] {msg}{Style.RESET_ALL}")

def _print_risk(score, level):
    colour_map = {
        "LOW": Fore.GREEN, "MEDIUM": Fore.YELLOW,
        "HIGH": Fore.RED,  "CRITICAL": Fore.RED + Style.BRIGHT,
    }
    print(f"{colour_map.get(level, Fore.WHITE)}[RISK] Score: {score}/100  |  Level: {level}{Style.RESET_ALL}")


# ── Prompt builder ────────────────────────────────────────────────
def _build_prompt(osint_data: dict) -> str:
    """
    Build the analyst prompt from OSINT data.
    FIX: Uses correct key names matching each collector's output.
    Also adds scan context so AI knows what type of target was scanned.
    """

    target     = osint_data.get("target", "Unknown Target")
    input_type = osint_data.get("input_type", "unknown")

    # Scan context — tells AI which collectors ran and why
    scan_context = (
        f"This is a {input_type.upper()} scan of target '{target}'. "
        f"Only collectors relevant to this target type were executed. "
        f"Some data sources will show 'not queried' — this is expected and normal."
    )

    # ── Shodan ────────────────────────────────────────────────────
    shodan = osint_data.get("shodan", {})
    if shodan and not shodan.get("error"):
        shodan_block = f"""
SHODAN (IP Intelligence):
  - IP Address   : {shodan.get('ip', 'N/A')}
  - Country      : {shodan.get('country', 'N/A')}
  - City         : {shodan.get('city', 'N/A')}
  - Organisation : {shodan.get('org', 'N/A')}
  - ISP          : {shodan.get('isp', 'N/A')}
  - ASN          : {shodan.get('asn', 'N/A')}
  - OS Detected  : {shodan.get('os', 'N/A')}
  - Open Ports   : {shodan.get('open_ports', [])}
  - CVEs Found   : {shodan.get('vulnerabilities', [])}
  - Tags         : {shodan.get('tags', [])}
  - Services     : {json.dumps(shodan.get('services', []), indent=2)}
"""
    else:
        shodan_block = f"SHODAN: Not queried for this target type (error: {shodan.get('error', 'not applicable')})\n"

    # ── HIBP ──────────────────────────────────────────────────────
    hibp = osint_data.get("hibp", {})
    if hibp and not hibp.get("error"):
        hibp_block = f"""
HAVEIBEENPWNED (Breach Intelligence):
  - Email        : {hibp.get('email', 'N/A')}
  - Breached?    : {hibp.get('breached', False)}
  - Breach Count : {hibp.get('breach_count', 0)}
  - Breaches     : {hibp.get('breaches', [])}
"""
    else:
        hibp_block = f"HAVEIBEENPWNED: Not queried for this target type (error: {hibp.get('error', 'not applicable')})\n"

    # ── WHOIS ─────────────────────────────────────────────────────
    # FIX: WhoisCollector returns 'expiration_date' not 'expiry_date'
    whois = osint_data.get("whois", {})
    if whois and not whois.get("error"):
        whois_block = f"""
WHOIS (Domain/IP Intelligence):
  - Domain          : {whois.get('domain', 'N/A')}
  - Registrar       : {whois.get('registrar', 'N/A')}
  - Organisation    : {whois.get('org', 'N/A')}
  - Country         : {whois.get('country', 'N/A')}
  - Created         : {whois.get('creation_date', 'N/A')}
  - Expires         : {whois.get('expiration_date', 'N/A')}
  - Updated         : {whois.get('updated_date', 'N/A')}
  - Age (days)      : {whois.get('age_days', 'N/A')}
  - Name Servers    : {whois.get('name_servers', [])}
  - Analyst Flags   : {whois.get('flags', [])}
"""
    else:
        whois_block = f"WHOIS: Not queried for this target type (error: {whois.get('error', 'not applicable')})\n"

    # ── GitHub ────────────────────────────────────────────────────
    # FIX: GitHubCollector returns nested profile dict, not flat keys
    github = osint_data.get("github", {})
    if github and not github.get("error") and github.get("found"):
        profile = github.get("profile") or {}
        github_block = f"""
GITHUB (Developer Intelligence):
  - Username       : {github.get('username', 'N/A')}
  - Found          : {github.get('found', False)}
  - Name           : {profile.get('name', 'N/A')}
  - Bio            : {profile.get('bio', 'N/A')}
  - Location       : {profile.get('location', 'N/A')}
  - Public Repos   : {profile.get('public_repos', 0)}
  - Followers      : {profile.get('followers', 0)}
  - Created        : {profile.get('created_at', 'N/A')}
  - Top Languages  : {github.get('top_languages', [])}
  - Organisations  : {github.get('organisations', [])}
  - Analyst Flags  : {github.get('flags', [])}
  - Repositories   : {json.dumps(github.get('repositories', [])[:5], indent=2)}
"""
    else:
        github_block = f"GITHUB: Not queried or user not found (error: {github.get('error', 'not applicable')})\n"

    # ── Google Dorks ──────────────────────────────────────────────
    dorks = osint_data.get("google_dorks", {})
    if dorks and not dorks.get("error"):
        dorks_block = f"""
GOOGLE DORKS (Exposed Content):
  - Target  : {dorks.get('target', 'N/A')}
  - Results : {json.dumps(dorks.get('results', []), indent=2)}
"""
    else:
        dorks_block = f"GOOGLE DORKS: Not queried for this target type (error: {dorks.get('error', 'not applicable')})\n"

    # ── Social Scan ───────────────────────────────────────────────
    social = osint_data.get("social_scan", {})
    if social and not social.get("error"):
        social_block = f"""
SOCIAL SCAN (Digital Footprint):
  - Username         : {social.get('username', 'N/A')}
  - Platforms Found  : {social.get('platforms_found', [])}
"""
    else:
        social_block = f"SOCIAL SCAN: Not queried for this target type (error: {social.get('error', 'not applicable')})\n"

    # ── Assemble full prompt ──────────────────────────────────────
    prompt = f"""You are an elite cybersecurity threat intelligence analyst with 15+ years of experience in OSINT, penetration testing, and digital forensics.

SCAN CONTEXT:
{scan_context}

TASK:
Analyse the following OSINT data collected for target "{target}" and produce a professional threat intelligence assessment. Focus only on data sources that returned actual results — ignore sources marked as "not queried".

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
1. Focus your analysis on the data sources that actually returned results.
2. Assign a RISK SCORE from 0 to 100:
   - CVEs present (CVSS 9+) → +30 points each
   - Open dangerous ports (Redis, MongoDB, Elasticsearch without auth) → +20
   - Credential breaches found → +25
   - Exposed secrets/configs via dorks → +20
   - Very new domain (< 30 days) → +15
   - Large social footprint → +5
3. Map score to RISK LEVEL: LOW (0-34), MEDIUM (35-59), HIGH (60-79), CRITICAL (80-100).
4. Identify specific, real-world threats with named attack vectors.
5. Give concrete, prioritised, actionable recommendations.
6. Write a detailed professional Markdown report.

OUTPUT FORMAT — return EXACTLY this structure, nothing else:

```json
{{
  "risk_score": <integer 0-100>,
  "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<2-3 sentence executive summary>",
  "findings": [
    "<specific finding 1>",
    "<specific finding 2>",
    "<specific finding 3>"
  ],
  "threats": [
    "<named threat 1>",
    "<named threat 2>",
    "<named threat 3>"
  ],
  "recommendations": [
    "<actionable recommendation 1>",
    "<actionable recommendation 2>",
    "<actionable recommendation 3>"
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

CRITICAL: Return ONLY the JSON block and Markdown block above. No other text.
"""

    return prompt


# ── Response parser ───────────────────────────────────────────────
def _parse_response(raw_text: str, target: str) -> dict:
    """
    Parse the Groq response into a structured dict.
    Handles missing JSON/markdown blocks gracefully.
    """
    result = {
        "target":          target,
        "risk_score":      0,
        "risk_level":      "UNKNOWN",
        "summary":         "Analysis could not be fully parsed.",
        "findings":        [],
        "threats":         [],
        "recommendations": [],
        "full_report":     raw_text,
        "error":           None,
    }

    # Extract JSON block
    json_match = re.search(r"```json\s*(.*?)\s*```", raw_text, re.DOTALL | re.IGNORECASE)
    if json_match:
        try:
            parsed_json = json.loads(json_match.group(1))
            result["risk_score"]      = int(parsed_json.get("risk_score", 0))
            result["risk_level"]      = str(parsed_json.get("risk_level", "UNKNOWN")).upper()
            result["summary"]         = str(parsed_json.get("summary", ""))
            result["findings"]        = list(parsed_json.get("findings", []))
            result["threats"]         = list(parsed_json.get("threats", []))
            result["recommendations"] = list(parsed_json.get("recommendations", []))
        except (json.JSONDecodeError, ValueError) as e:
            _print_warning(f"JSON parsing failed: {e}")
    else:
        _print_warning("No JSON block found — using heuristic extraction.")
        score_match = re.search(r"risk[_\s]*score[:\s]+(\d{1,3})", raw_text, re.IGNORECASE)
        if score_match:
            result["risk_score"] = int(score_match.group(1))
        level_match = re.search(r"risk[_\s]*level[:\s]+(LOW|MEDIUM|HIGH|CRITICAL)", raw_text, re.IGNORECASE)
        if level_match:
            result["risk_level"] = level_match.group(1).upper()

    # Clamp score
    result["risk_score"] = max(0, min(100, result["risk_score"]))

    # Derive level from score if invalid
    if result["risk_level"] not in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"):
        score = result["risk_score"]
        if score >= 80:   result["risk_level"] = "CRITICAL"
        elif score >= 60: result["risk_level"] = "HIGH"
        elif score >= 35: result["risk_level"] = "MEDIUM"
        else:             result["risk_level"] = "LOW"

    # Extract markdown block
    md_match = re.search(r"```markdown\s*(.*?)\s*```", raw_text, re.DOTALL | re.IGNORECASE)
    if md_match:
        result["full_report"] = md_match.group(1).strip()
    elif json_match:
        after = raw_text[json_match.end():].strip()
        if after:
            result["full_report"] = after

    return result


def score_to_level(score: int) -> str:
    if score >= 80:   return "CRITICAL"
    elif score >= 60: return "HIGH"
    elif score >= 35: return "MEDIUM"
    return "LOW"


# ── Main public function ──────────────────────────────────────────
def analyze_target(osint_data: dict) -> dict:
    """
    Core entry point. Takes compiled OSINT dict, calls Groq,
    returns structured threat intelligence report dict.
    """
    target = osint_data.get("target", "Unknown Target")

    if not GROQ_API_KEY:
        _print_error("GROQ_API_KEY is not set.")
        return {
            "target": target, "risk_score": 0, "risk_level": "UNKNOWN",
            "summary": "", "findings": [], "threats": [],
            "recommendations": [], "full_report": "",
            "error": "GROQ_API_KEY not configured.",
        }

    print()
    _print_section("═" * 55)
    _print_section(f"ReconMind AI Analysis Engine — Target: {target}")
    _print_section("═" * 55)

    # Step 1: Build prompt
    _print_section("Compiling OSINT data into analyst prompt …")
    try:
        prompt = _build_prompt(osint_data)
        _print_success(f"Prompt constructed ({len(prompt):,} characters).")
    except Exception as e:
        _print_error(f"Failed to build prompt: {e}")
        return {
            "target": target, "risk_score": 0, "risk_level": "UNKNOWN",
            "summary": "", "findings": [], "threats": [],
            "recommendations": [], "full_report": "",
            "error": f"Prompt construction failed: {e}",
        }

    # Step 2: Connect to Groq
    _print_section("Connecting to Groq API …")
    try:
        client = Groq(api_key=GROQ_API_KEY)
        _print_success("Groq client initialised.")
    except Exception as e:
        _print_error(f"Groq client failed: {e}")
        return {
            "target": target, "risk_score": 0, "risk_level": "UNKNOWN",
            "summary": "", "findings": [], "threats": [],
            "recommendations": [], "full_report": "",
            "error": f"Groq client error: {e}",
        }

    # Step 3: Call API
    _print_ai(f"Sending data to {MODEL_ID} …")
    _print_ai("This may take 15–45 seconds …")
    try:
        response = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an elite cybersecurity threat intelligence analyst. "
                        "You produce precise, evidence-based threat assessments. "
                        "Always respond with a JSON block followed by a Markdown block exactly as instructed."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            model=MODEL_ID,
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
        )
        _print_success("Groq API responded successfully.")
    except Exception as e:
        _print_error(f"Groq API call failed: {e}")
        return {
            "target": target, "risk_score": 0, "risk_level": "UNKNOWN",
            "summary": "", "findings": [], "threats": [],
            "recommendations": [], "full_report": "",
            "error": f"Groq API error: {e}",
        }

    # Step 4: Extract text
    try:
        raw_text = response.choices[0].message.content
        if not raw_text or not raw_text.strip():
            raise ValueError("Empty response from Groq.")
        _print_success(f"Received {len(raw_text):,} characters.")
    except Exception as e:
        _print_error(f"Response extraction failed: {e}")
        return {
            "target": target, "risk_score": 0, "risk_level": "UNKNOWN",
            "summary": "", "findings": [], "threats": [],
            "recommendations": [], "full_report": "",
            "error": f"Extraction failed: {e}",
        }

    # Step 5: Parse
    _print_section("Parsing AI response …")
    try:
        report = _parse_response(raw_text, target)
        _print_success("Report parsed successfully.")
    except Exception as e:
        _print_error(f"Parsing failed: {e}")
        return {
            "target": target, "risk_score": 0, "risk_level": "UNKNOWN",
            "summary": "", "findings": [], "threats": [],
            "recommendations": [], "full_report": raw_text,
            "error": f"Parse error: {e}",
        }

    # Step 6: Print summary
    print()
    _print_section("── ANALYSIS COMPLETE ─────────────────────────────────")
    _print_risk(report["risk_score"], report["risk_level"])

    if report["summary"]:
        print(f"{Fore.CYAN}[SUMMARY]\n{textwrap.fill(report['summary'], 72, initial_indent='    ')}{Style.RESET_ALL}")

    if report["findings"]:
        print(f"{Fore.CYAN}[KEY FINDINGS]{Style.RESET_ALL}")
        for i, f in enumerate(report["findings"], 1):
            print(f"  {Fore.WHITE}{i}. {f}{Style.RESET_ALL}")

    if report["threats"]:
        print(f"{Fore.RED}[THREATS]{Style.RESET_ALL}")
        for i, t in enumerate(report["threats"], 1):
            print(f"  {Fore.YELLOW}{i}. {t}{Style.RESET_ALL}")

    if report["recommendations"]:
        print(f"{Fore.GREEN}[RECOMMENDATIONS]{Style.RESET_ALL}")
        for i, r in enumerate(report["recommendations"], 1):
            print(f"  {Fore.GREEN}{i}. {r}{Style.RESET_ALL}")

    print()
    _print_success("ReconMind AI analysis complete.")
    _print_section("═" * 55)
    print()

    return report


# ── Direct test ───────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{Fore.CYAN}{Style.BRIGHT}  ReconMind — groq_analysis.py test{Style.RESET_ALL}\n")

    sample = {
        "target":     "8.8.8.8",
        "input_type": "ip",
        "shodan": {
            "ip": "8.8.8.8", "country": "United States",
            "org": "Google LLC", "isp": "Google LLC",
            "open_ports": [53, 443], "vulnerabilities": [],
            "services": [{"port": 53, "product": "DNS", "version": ""}],
            "tags": ["cloud"], "error": None,
        },
        "whois": {
            "domain": "8.8.8.8", "registrar": "ARIN",
            "creation_date": "1992-01-01", "expiration_date": "2030-01-01",
            "updated_date": "2023-01-01", "age_days": 11000,
            "country": "US", "org": "Google LLC",
            "name_servers": [], "flags": [], "error": None,
        },
    }

    result = analyze_target(sample)

    if result.get("error"):
        _print_error(f"Error: {result['error']}")
    else:
        _print_success("Test complete!")
        print(f"\n{Fore.WHITE}{result.get('full_report', '')[:800]}{Style.RESET_ALL}")
