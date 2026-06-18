"""
ReconMind — AI-Powered OSINT Intelligence Engine
Backend API (app.py)

Flask REST API that:
  - Classifies the target (IP / email / domain / username)
  - Routes the target to relevant OSINT collectors
  - Runs collectors concurrently via ThreadPoolExecutor
  - Passes aggregated data to the Groq AI analysis engine
  - Returns structured JSON reports or downloadable PDFs
  - Includes timeout protection, rate limiting, logging, and security headers
"""

# ─────────────────────────────────────────────────────────────────────────────
# STANDARD LIBRARY
# ─────────────────────────────────────────────────────────────────────────────
import logging
import os
import re
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from datetime import datetime, timezone
from typing import Any
from dotenv import load_dotenv

# Load .env file if it exists (for local development)
load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# THIRD-PARTY
# ─────────────────────────────────────────────────────────────────────────────
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL MODULES
# ─────────────────────────────────────────────────────────────────────────────
# Fix import paths for Railway deployment
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.shodan_collector import collect_shodan
from collectors.hibp_collector import HIBPCollector
from collectors.whois_collector import WhoisCollector
from collectors.github_collector import GitHubCollector
from collectors.google_collector import GoogleDorkCollector
from collectors.social_scan_collectors import SocialScanner

from ai_engine.groq_analysis import analyze_target
from output.pdf_export import export_pdf

# ─────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT VARIABLES & API KEYS
# ─────────────────────────────────────────────────────────────────────────────
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
FLASK_ENV = os.environ.get("FLASK_ENV", "development")

# Validate API keys on startup
if not GROQ_API_KEY:
    print("⚠️  WARNING: GROQ_API_KEY not set - AI analysis will not work")
if not SHODAN_API_KEY:
    print("⚠️  WARNING: SHODAN_API_KEY not set - Shodan collector will not work")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

logger = logging.getLogger("reconmind")

# ─────────────────────────────────────────────────────────────────────────────
# CREATE REQUIRED DIRECTORIES
# ─────────────────────────────────────────────────────────────────────────────
# Create output directory for PDF reports (at project root, not in Backend/)
os.makedirs(os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", "reports"), exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# FLASK APP
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Enable CORS - Allow all origins (frontend can be on any domain)
CORS(app, resources={
    r"/*": {
        "origins": "https://reconmind.vercel.app",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": False,
        "max_age": 3600
    }
})

# Security headers — force_https=False so Railway HTTP works fine
Talisman(app, content_security_policy=False, force_https=False)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20 per minute"]
)

# ─────────────────────────────────────────────────────────────────────────────
# REGEX CLASSIFIERS
# ─────────────────────────────────────────────────────────────────────────────
_RE_IPV4 = re.compile(
    r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$"
)

_RE_EMAIL = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

_RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# ─────────────────────────────────────────────────────────────────────────────
# INPUT CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────
def classify_target(target: str) -> str:
    """
    Classify target into: ip / email / domain / username
    """
    t = target.strip()
    if _RE_IPV4.match(t):   return "ip"
    if _RE_EMAIL.match(t):  return "email"
    if _RE_DOMAIN.match(t): return "domain"
    return "username"


# ─────────────────────────────────────────────────────────────────────────────
# COLLECTOR INITIALIZATION
# ─────────────────────────────────────────────────────────────────────────────
_hibp_collector   = HIBPCollector()
_whois_collector  = WhoisCollector()
_github_collector = GitHubCollector()
_social_scanner   = SocialScanner()
_google_collector = GoogleDorkCollector()


# ─────────────────────────────────────────────────────────────────────────────
# COLLECTOR ROUTING
# ─────────────────────────────────────────────────────────────────────────────
def _build_collector_tasks(input_type: str, target: str) -> dict[str, Any]:
    """
    Route target to only the relevant collectors for its type.

    ip       → shodan, whois
    email    → hibp, social_scan, google_dorks
    domain   → whois, shodan, google_dorks, github
    username → github, social_scan, google_dorks
    """
    tasks: dict[str, Any] = {}

    if input_type == "ip":
        tasks["shodan"] = lambda: collect_shodan(target)
        tasks["whois"]  = lambda: _whois_collector.collect(target)

    elif input_type == "email":
        tasks["hibp"]         = lambda: _hibp_collector.collect(target)
        tasks["social_scan"]  = lambda: _social_scanner.collect(target)
     #   tasks["google_dorks"] = lambda: _google_collector.collect(target)   # Disable Google Dorks to reduce memory pressure

    elif input_type == "domain":
        tasks["whois"]        = lambda: _whois_collector.collect(target)
        tasks["shodan"]       = lambda: collect_shodan(target)
        tasks["google_dorks"] = lambda: _google_collector.collect(target)
     #   tasks["github"]       = lambda: _github_collector.collect(target)   # Disable Google Dorks to reduce memory pressure

    elif input_type == "username":
        tasks["github"]       = lambda: _github_collector.collect(target)
        tasks["social_scan"]  = lambda: _social_scanner.collect(target)
      #  tasks["google_dorks"] = lambda: _google_collector.collect(target)   # Disable Google Dorks to reduce memory pressure

    return tasks


# ─────────────────────────────────────────────────────────────────────────────
# AI SANITIZATION
# ─────────────────────────────────────────────────────────────────────────────
def sanitize_for_ai(osint_data: dict[str, Any]) -> dict[str, Any]:
    """
    Trim very large responses before sending to Groq.
    Prevents token overflow and keeps API costs down.
    """
    cleaned = {}
    for key, value in osint_data.items():
        if isinstance(value, str):
            cleaned[key] = value[:5000]
        elif isinstance(value, list):
            cleaned[key] = value[:25]
        else:
            cleaned[key] = value
    return cleaned


# ─────────────────────────────────────────────────────────────────────────────
# RUN COLLECTORS
# ─────────────────────────────────────────────────────────────────────────────
def run_collectors(input_type: str, target: str) -> dict[str, Any]:
    """
    Execute all relevant collectors concurrently.
    One broken collector never aborts the full scan.
    """
    tasks = _build_collector_tasks(input_type, target)

    if not tasks:
        raise ValueError(f"No collectors available for input type: {input_type}")

    osint_data: dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=2) as executor:  
        future_to_key = {executor.submit(fn): key for key, fn in tasks.items()}

        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                result = future.result(timeout=59)
                osint_data[key] = result
                logger.info("Collector '%s' completed successfully.", key)
            except TimeoutError:
                logger.error("Collector '%s' timed out.", key)
                osint_data[key] = {"error": "collector timeout"}
            except Exception as exc:
                logger.error("Collector '%s' failed: %s\n%s", key, exc, traceback.format_exc())
                osint_data[key] = {"error": str(exc)}

    return osint_data


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health")
def health() -> Response:
    return jsonify({"status": "ok", "version": "2.0.0"}), 200


# ─────────────────────────────────────────────────────────────────────────────
# JSON SCAN ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────
@limiter.limit("5 per minute")
@app.post("/scan")
def scan() -> Response:

    body   = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()

    if not target:
        return jsonify({"error": "Missing 'target' field."}), 400

    if len(target) > 255:
        return jsonify({"error": "Target exceeds maximum allowed length."}), 400

    logger.info("New scan requested for: '%s'", target)
    input_type = classify_target(target)
    logger.info("Target '%s' classified as: %s", target, input_type)

    # ── Collect OSINT ─────────────────────────────────────────────
    try:
        osint_data = run_collectors(input_type, target)
    except Exception as exc:
        logger.error("Collection phase failed: %s\n%s", exc, traceback.format_exc())
        return jsonify({"error": f"Collection failed: {exc}"}), 500

    # ── Add metadata ──────────────────────────────────────────────
    osint_data["target"]     = target
    osint_data["input_type"] = input_type

    # ── Sanitize and analyse ──────────────────────────────────────
    ai_input = sanitize_for_ai(osint_data)

    try:
        report = analyze_target(ai_input)
    except Exception as exc:
        logger.error("Groq analysis failed: %s\n%s", exc, traceback.format_exc())
        return jsonify({"error": f"AI analysis failed: {exc}"}), 500

    logger.info("Scan completed for '%s'", target)

    return jsonify({
        "target":     target,
        "input_type": input_type,
        "osint_data": osint_data,
        "report":     report,
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# PDF SCAN ENDPOINT  ← BUG FIXED HERE
# ─────────────────────────────────────────────────────────────────────────────
@limiter.limit("3 per minute")
@app.post("/scan/pdf")
def scan_pdf() -> Response:

    body   = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()

    if not target:
        return jsonify({"error": "Missing 'target' field."}), 400

    if len(target) > 255:
        return jsonify({"error": "Target exceeds maximum allowed length."}), 400

    logger.info("PDF scan requested for '%s'", target)
    input_type = classify_target(target)
    logger.info("Target '%s' classified as: %s", target, input_type)

    # ── Collect ───────────────────────────────────────────────────
    try:
        osint_data = run_collectors(input_type, target)
    except Exception as exc:
        logger.error("Collection failed during PDF scan: %s\n%s", exc, traceback.format_exc())
        return jsonify({"error": f"Collection failed: {exc}"}), 500

    osint_data["target"]     = target
    osint_data["input_type"] = input_type
    ai_input = sanitize_for_ai(osint_data)

    # ── AI Analysis ───────────────────────────────────────────────
    try:
        report = analyze_target(ai_input)
    except Exception as exc:
        logger.error("AI analysis failed during PDF scan: %s\n%s", exc, traceback.format_exc())
        return jsonify({"error": f"AI analysis failed: {exc}"}), 500

    # ── Export PDF ────────────────────────────────────────────────
    # FIX: export_pdf() returns a FILE PATH (str), not bytes.
    # We must pass output_dir as keyword arg, then read the file.
    try:
        pdf_path = export_pdf(report, output_dir="output/reports")
        if not pdf_path:
            raise ValueError("export_pdf() returned empty path — PDF generation failed.")
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
    except Exception as exc:
        logger.error("PDF export failed: %s\n%s", exc, traceback.format_exc())
        return jsonify({"error": f"PDF export failed: {exc}"}), 500

    # ── Build filename and return ─────────────────────────────────
    safe_target = re.sub(r"[^\w.\-]", "_", target)
    timestamp   = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename    = f"reconmind_report_{safe_target}_{timestamp}.pdf"

    logger.info("PDF generated successfully: %s", filename)

    return Response(
        pdf_bytes,
        status=200,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port       = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info("Starting ReconMind API on 0.0.0.0:%d (debug=%s)", port, debug_mode)
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
