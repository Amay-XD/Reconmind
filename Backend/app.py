"""
ReconMind — AI-Powered OSINT Intelligence Engine
Backend API (app.py)

Complete working version with all imports and dependencies.
"""

import logging
import os
import re
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from datetime import datetime, timezone
from typing import Any

# Flask imports
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# Project imports
from collectors.shodan_collector import collect_shodan
from collectors.hibp_collector import HIBPCollector
from collectors.whois_collector import WhoisCollector
from collectors.github_collector import GitHubCollector
from collectors.google_collector import GoogleDorkCollector
from collectors.social_scan_collectors import SocialScanner

from ai_engine.groq_analysis import analyze_target
from output.pdf_export import export_pdf

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("reconmind")

# ─────────────────────────────────────────────────────────────────────────────
# FLASK APP INITIALIZATION
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Enable CORS for all routes
CORS(app)

# Security headers
Talisman(app, content_security_policy=False, force_https=False)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20 per minute"]
)

# ─────────────────────────────────────────────────────────────────────────────
# REGEX PATTERNS FOR INPUT CLASSIFICATION
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
# INPUT CLASSIFIER FUNCTION
# ─────────────────────────────────────────────────────────────────────────────
def classify_target(target: str) -> str:
    """
    Classify target string into one of four types:
    - ip:       IPv4 address (e.g., 192.168.1.1)
    - email:    Email address (e.g., user@example.com)
    - domain:   Domain name (e.g., example.com)
    - username: Everything else (e.g., john_doe)
    """
    t = target.strip()
    if _RE_IPV4.match(t):
        return "ip"
    if _RE_EMAIL.match(t):
        return "email"
    if _RE_DOMAIN.match(t):
        return "domain"
    return "username"

# ─────────────────────────────────────────────────────────────────────────────
# COLLECTOR INITIALIZATION (singleton instances)
# ─────────────────────────────────────────────────────────────────────────────
_hibp_collector   = HIBPCollector()
_whois_collector  = WhoisCollector()
_github_collector = GitHubCollector()
_social_scanner   = SocialScanner()
_google_collector = GoogleDorkCollector()

# ─────────────────────────────────────────────────────────────────────────────
# COLLECTOR ROUTING BY INPUT TYPE
# ─────────────────────────────────────────────────────────────────────────────
def _build_collector_tasks(input_type: str, target: str) -> dict[str, Any]:
    """
    Route the target to only the relevant collectors based on its type.
    
    Routing table:
    - ip       → shodan, whois
    - email    → hibp, social_scan, google_dorks
    - domain   → whois, shodan, google_dorks, github
    - username → github, social_scan, google_dorks
    """
    tasks: dict[str, Any] = {}

    if input_type == "ip":
        tasks["shodan"] = lambda: collect_shodan(target)
        tasks["whois"]  = lambda: _whois_collector.collect(target)

    elif input_type == "email":
        tasks["hibp"]         = lambda: _hibp_collector.collect(target)
        tasks["social_scan"]  = lambda: _social_scanner.collect(target)
        tasks["google_dorks"] = lambda: _google_collector.collect(target)

    elif input_type == "domain":
        tasks["whois"]        = lambda: _whois_collector.collect(target)
        tasks["shodan"]       = lambda: collect_shodan(target)
        tasks["google_dorks"] = lambda: _google_collector.collect(target)
        tasks["github"]       = lambda: _github_collector.collect(target)

    elif input_type == "username":
        tasks["github"]       = lambda: _github_collector.collect(target)
        tasks["social_scan"]  = lambda: _social_scanner.collect(target)
        tasks["google_dorks"] = lambda: _google_collector.collect(target)

    return tasks

# ─────────────────────────────────────────────────────────────────────────────
# DATA SANITIZATION FOR AI
# ─────────────────────────────────────────────────────────────────────────────
def sanitize_for_ai(osint_data: dict[str, Any]) -> dict[str, Any]:
    """
    Trim very large responses before sending to Groq API.
    Prevents token overflow and keeps API costs reasonable.
    """
    cleaned = {}
    for key, value in osint_data.items():
        if isinstance(value, str):
            # Limit strings to 5000 characters
            cleaned[key] = value[:5000]
        elif isinstance(value, list):
            # Limit lists to 25 items
            cleaned[key] = value[:25]
        else:
            # Keep dicts and other types as-is
            cleaned[key] = value
    return cleaned

# ─────────────────────────────────────────────────────────────────────────────
# RUN COLLECTORS IN PARALLEL
# ─────────────────────────────────────────────────────────────────────────────
def run_collectors(input_type: str, target: str) -> dict[str, Any]:
    """
    Execute all relevant collectors concurrently using ThreadPoolExecutor.
    One broken collector never aborts the entire scan.
    """
    tasks = _build_collector_tasks(input_type, target)

    if not tasks:
        raise ValueError(f"No collectors available for input type: {input_type}")

    osint_data: dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        # Submit all tasks
        future_to_key = {executor.submit(fn): key for key, fn in tasks.items()}

        # Process completed tasks as they finish
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                result = future.result(timeout=20)
                osint_data[key] = result
                logger.info("✓ Collector '%s' completed successfully.", key)
            except TimeoutError:
                logger.error("✗ Collector '%s' timed out (20s limit).", key)
                osint_data[key] = {"error": "collector timeout"}
            except Exception as exc:
                logger.error("✗ Collector '%s' failed: %s", key, str(exc))
                osint_data[key] = {"error": str(exc)}

    return osint_data

# ─────────────────────────────────────────────────────────────────────────────
# HEALTH CHECK ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health")
def health() -> Response:
    """Health check endpoint for monitoring."""
    return jsonify({
        "status": "ok",
        "version": "2.0.0",
        "timestamp": datetime.now(tz=timezone.utc).isoformat()
    }), 200

# ─────────────────────────────────────────────────────────────────────────────
# JSON SCAN ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────
@limiter.limit("5 per minute")
@app.post("/scan")
def scan() -> Response:
    """
    Main scan endpoint.
    Accepts: POST /scan with JSON body { "target": "..." }
    Returns: Full scan results with osint_data and AI report
    """
    body   = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()

    # Validation
    if not target:
        return jsonify({"error": "Missing 'target' field."}), 400

    if len(target) > 255:
        return jsonify({"error": "Target exceeds maximum allowed length (255 chars)."}), 400

    logger.info("=" * 70)
    logger.info("NEW SCAN REQUESTED: '%s'", target)
    logger.info("=" * 70)

    # Classify target
    input_type = classify_target(target)
    logger.info("Target type detected: %s", input_type.upper())

    # Run collectors
    try:
        logger.info("Starting collectors...")
        osint_data = run_collectors(input_type, target)
        logger.info("✓ All collectors completed")
    except Exception as exc:
        logger.error("✗ Collection phase FAILED: %s", str(exc))
        return jsonify({"error": f"Collection failed: {exc}"}), 500

    # Add metadata
    osint_data["target"]     = target
    osint_data["input_type"] = input_type

    # Sanitize for AI
    ai_input = sanitize_for_ai(osint_data)

    # AI Analysis
    try:
        logger.info("Sending to Groq for AI analysis...")
        report = analyze_target(ai_input)
        logger.info("✓ AI analysis complete")
        logger.info("Risk Score: %s/100 | Risk Level: %s",
                    report.get("risk_score"), report.get("risk_level"))
    except Exception as exc:
        logger.error("✗ AI analysis FAILED: %s", str(exc))
        return jsonify({"error": f"AI analysis failed: {exc}"}), 500

    logger.info("=" * 70)
    logger.info("SCAN COMPLETED SUCCESSFULLY")
    logger.info("=" * 70)

    return jsonify({
        "target":     target,
        "input_type": input_type,
        "osint_data": osint_data,
        "report":     report,
    }), 200

# ─────────────────────────────────────────────────────────────────────────────
# PDF EXPORT ENDPOINT (FIXED VERSION)
# ─────────────────────────────────────────────────────────────────────────────
@limiter.limit("3 per minute")
@app.post("/scan/pdf")
def scan_pdf() -> Response:
    """
    PDF export endpoint.
    Accepts: POST /scan/pdf with JSON body containing:
      - target (required): the target string
      - report (optional): pre-computed report from frontend
      - osint_data (optional): pre-collected OSINT data from frontend
    
    If report is provided, uses it directly (no re-scan).
    If not, runs a fresh scan (fallback).
    
    Returns: PDF file as attachment
    """
    body       = request.get_json(silent=True) or {}
    target     = (body.get("target") or "").strip()
    report     = body.get("report")      # Pre-existing report from frontend
    osint_data = body.get("osint_data")  # Pre-existing OSINT data from frontend

    # Validation
    if not target:
        return jsonify({"error": "Missing 'target' field."}), 400

    if len(target) > 255:
        return jsonify({"error": "Target exceeds maximum allowed length (255 chars)."}), 400

    logger.info("=" * 70)
    logger.info("PDF EXPORT REQUESTED: '%s'", target)
    logger.info("=" * 70)

    # ── KEY FIX: Use existing report if frontend provided it ──────
    if report:
        logger.info("✓ USING EXISTING SCAN DATA FROM FRONTEND (no re-scan)")
        logger.info("  Risk Score: %s/100 | Risk Level: %s",
                    report.get("risk_score"), report.get("risk_level"))
    else:
        logger.info("⚠ NO REPORT PROVIDED — RUNNING FRESH SCAN")

        input_type = classify_target(target)
        logger.info("Target type: %s", input_type.upper())

        try:
            logger.info("Starting collectors...")
            osint_data = run_collectors(input_type, target)
            logger.info("✓ Collectors complete")
        except Exception as exc:
            logger.error("✗ Collection failed: %s", str(exc))
            return jsonify({"error": f"Collection failed: {exc}"}), 500

        osint_data["target"]     = target
        osint_data["input_type"] = input_type
        ai_input = sanitize_for_ai(osint_data)

        try:
            logger.info("Running AI analysis...")
            report = analyze_target(ai_input)
            logger.info("✓ AI analysis complete")
            logger.info("Risk Score: %s/100 | Risk Level: %s",
                        report.get("risk_score"), report.get("risk_level"))
        except Exception as exc:
            logger.error("✗ AI analysis failed: %s", str(exc))
            return jsonify({"error": f"AI analysis failed: {exc}"}), 500

    # ── Export PDF from the report dict ────────────────────────────
    try:
        logger.info("Exporting PDF...")
        logger.info("  Risk Score: %s/100", report.get("risk_score"))
        logger.info("  Risk Level: %s", report.get("risk_level"))

        pdf_path = export_pdf(report, output_dir="output/reports")

        if not pdf_path or not os.path.exists(pdf_path):
            logger.error("✗ export_pdf() failed or returned invalid path")
            raise ValueError("export_pdf() returned invalid path")

        logger.info("✓ PDF created at: %s", pdf_path)

        # Read the PDF file
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        if not pdf_bytes:
            logger.error("✗ PDF file is empty!")
            raise ValueError("PDF file is empty")

        logger.info("✓ PDF read successfully: %d bytes", len(pdf_bytes))

    except Exception as exc:
        logger.error("✗ PDF export failed: %s", str(exc))
        return jsonify({"error": f"PDF export failed: {exc}"}), 500

    # ── Build filename and return ─────────────────────────────────
    safe_target = re.sub(r"[^\w.\-]", "_", target)
    timestamp   = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename    = f"reconmind_report_{safe_target}_{timestamp}.pdf"

    logger.info("=" * 70)
    logger.info("PDF EXPORT SUCCESSFUL: %s", filename)
    logger.info("=" * 70)

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
# APPLICATION ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Get port from environment (Railway sets PORT automatically)
    port = int(os.environ.get("PORT", 5000))

    # Get debug mode from environment
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    logger.info("=" * 70)
    logger.info("RECONMIND API SERVER STARTING")
    logger.info("=" * 70)
    logger.info("Host: 0.0.0.0")
    logger.info("Port: %d", port)
    logger.info("Debug: %s", debug_mode)
    logger.info("=" * 70)

    # Start Flask app
    app.run(host="0.0.0.0", port=port, debug=debug_mode)

# ─────────────────────────────────────────────────────────────────────────────
# REQUIRED DEPENDENCIES (pip install these):
# ─────────────────────────────────────────────────────────────────────────────
# flask>=3.0.0
# flask-cors>=4.0.0
# flask-limiter>=3.5.0
# flask-talisman>=1.1.0
# groq>=0.5.0
# shodan>=1.30.0
# python-whois>=0.8.0
# PyGithub>=2.1.1
# requests>=2.31.0
# beautifulsoup4>=4.12.0
# colorama>=0.4.6
# reportlab>=4.0.0
