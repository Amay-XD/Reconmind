"""
ReconMind — Backend API (app.py)
Flask REST API — connects all collectors, AI engine, and PDF export.
"""

import logging
import os
import re
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request
from flask_cors import CORS

# ── Collector imports — matched to actual class/function names ────
from collectors.shodan_collector import collect_shodan
from collectors.hibp_collector import HIBPCollector
from collectors.whois_collector import WhoisCollector
from collectors.github_collector import GitHubCollector
from collectors.google_collector import GoogleDorkCollector
from collectors.social_scan_collectors import SocialScanner

# ── AI engine — function is called analyze_target() not analyse_with_groq
from ai_engine.groq_analysis import analyze_target

# ── PDF export
from output.pdf_export import export_pdf

# ── Logging ───────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("reconmind")

# ── Flask app ─────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ── Regex classifiers ─────────────────────────────────────────────
_RE_IPV4   = re.compile(r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$")
_RE_EMAIL  = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

def classify_target(target: str) -> str:
    t = target.strip()
    if _RE_IPV4.match(t):   return "ip"
    if _RE_EMAIL.match(t):  return "email"
    if _RE_DOMAIN.match(t): return "domain"
    return "username"

# ── Instantiate collectors once ───────────────────────────────────
_hibp    = HIBPCollector()
_whois   = WhoisCollector()
_github  = GitHubCollector()
_google  = GoogleDorkCollector()
_social  = SocialScanner()

def _build_tasks(input_type: str, target: str) -> dict:
    """Route target to relevant collectors based on type."""
    tasks = {}

    if input_type == "ip":
        tasks["shodan"] = lambda: collect_shodan(target)
        tasks["whois"]  = lambda: _whois.collect(target)

    elif input_type == "email":
        tasks["hibp"]         = lambda: _hibp.collect(target)
        tasks["social_scan"]  = lambda: _social.collect(target)
        tasks["google_dorks"] = lambda: _google.collect(target)

    elif input_type == "domain":
        tasks["whois"]        = lambda: _whois.collect(target)
        tasks["shodan"]       = lambda: collect_shodan(target)
        tasks["google_dorks"] = lambda: _google.collect(target)
        tasks["github"]       = lambda: _github.collect(target)

    elif input_type == "username":
        tasks["github"]       = lambda: _github.collect(target)
        tasks["social_scan"]  = lambda: _social.collect(target)
        tasks["google_dorks"] = lambda: _google.collect(target)

    return tasks

def run_collectors(input_type: str, target: str) -> dict:
    """Run all relevant collectors concurrently."""
    tasks     = _build_tasks(input_type, target)
    osint_data = {}

    with ThreadPoolExecutor(max_workers=len(tasks) or 1) as executor:
        future_to_key = {executor.submit(fn): key for key, fn in tasks.items()}
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                osint_data[key] = future.result()
                logger.info("Collector '%s' done.", key)
            except Exception as exc:
                logger.error("Collector '%s' failed: %s", key, exc)
                osint_data[key] = {"error": str(exc)}

    return osint_data

# ── Routes ────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0"}), 200


@app.post("/scan")
def scan():
    body   = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()

    if not target:
        return jsonify({"error": "Missing 'target' field."}), 400

    logger.info("Scan: %s", target)
    input_type = classify_target(target)

    try:
        osint_data = run_collectors(input_type, target)
    except Exception as exc:
        return jsonify({"error": f"Collection failed: {exc}"}), 500

    # Add target to osint_data so groq_analysis knows what was scanned
    osint_data["target"] = target

    try:
        report = analyze_target(osint_data)
    except Exception as exc:
        return jsonify({"error": f"AI analysis failed: {exc}"}), 500

    return jsonify({
        "target":     target,
        "input_type": input_type,
        "osint_data": osint_data,
        "report":     report,
    }), 200


@app.post("/scan/pdf")
def scan_pdf():
    body   = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()

    if not target:
        return jsonify({"error": "Missing 'target' field."}), 400

    input_type = classify_target(target)
    osint_data = run_collectors(input_type, target)
    osint_data["target"] = target
    report     = analyze_target(osint_data)

    try:
        pdf_path = export_pdf(report)
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
    except Exception as exc:
        return jsonify({"error": f"PDF export failed: {exc}"}), 500

    safe_target = re.sub(r"[^\w.\-]", "_", target)
    timestamp   = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename    = f"reconmind_report_{safe_target}_{timestamp}.pdf"

    return Response(
        pdf_bytes,
        status=200,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Entry point ───────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
  
    logger.info("Starting ReconMind API on 0.0.0.0:%d  (debug=%s)", port, debug_mode)
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
 
 
# ═════════════════════════════════════════════════════════════════════════════
# REQUIREMENTS  (pip install)
# ═════════════════════════════════════════════════════════════════════════════
#
# flask>=3.0.0
# flask-cors>=4.0.0
#
# All collector / AI / export dependencies are expected to be declared in
# their own modules.  At a minimum you will also need:
#
# requests          — used by most collectors for HTTP calls
# shodan            — shodan_collector.py
# python-whois      — whois_collector.py
# PyGithub          — github_collector.py
# groq              — groq_analysis.py
# reportlab         — pdf_export.py  (or fpdf2 / weasyprint depending on impl.)
#
# For Railway deployment, make sure all of the above are in requirements.txt.
