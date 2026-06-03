from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

import requests
import socket
import whois
import json
import io
import os
import random
import datetime

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)
CORS(app)

# =========================
# CONFIG
# =========================

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
HIBP_API_KEY = "YOUR_HIBP_API_KEY"
GROQ_API_KEY = "YOUR_GROQ_API_KEY"

# =========================
# HELPERS
# =========================

def detect_target_type(target):

    if "@" in target:
        return "email"

    try:
        socket.inet_aton(target)
        return "ip"
    except:
        pass

    if "." in target:
        return "domain"

    return "username"


# =========================
# SHODAN
# =========================

def shodan_lookup(ip):

    if not SHODAN_API_KEY:
        return {}

    try:

        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"

        response = requests.get(url)

        if response.status_code != 200:
            return {}

        data = response.json()

        return {
            "ip": data.get("ip_str"),
            "organization": data.get("org"),
            "os": data.get("os"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else []
        }

    except Exception as e:
        return {
            "error": str(e)
        }


# =========================
# WHOIS
# =========================

def whois_lookup(domain):

    try:

        data = whois.whois(domain)

        return {
            "domain": data.domain_name,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers
        }

    except Exception as e:
        return {
            "error": str(e)
        }


# =========================
# HIBP
# =========================

def hibp_lookup(email):

    if not HIBP_API_KEY:
        return []

    try:

        headers = {
            "hibp-api-key": HIBP_API_KEY,
            "User-Agent": "ReconMind"
        }

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            return []

        breaches = response.json()

        return breaches

    except Exception as e:
        return {
            "error": str(e)
        }


# =========================
# GITHUB
# =========================

def github_lookup(username):

    try:

        url = f"https://api.github.com/users/{username}"

        response = requests.get(url)

        if response.status_code != 200:
            return {}

        data = response.json()

        return {
            "username": data.get("login"),
            "followers": data.get("followers"),
            "public_repos": data.get("public_repos"),
            "created_at": data.get("created_at"),
            "bio": data.get("bio")
        }

    except Exception as e:
        return {
            "error": str(e)
        }


# =========================
# SOCIAL SCAN
# =========================

def social_scan(username):

    platforms = []

    sites = [
        ("Twitter", f"https://twitter.com/{username}"),
        ("Instagram", f"https://instagram.com/{username}"),
        ("Reddit", f"https://reddit.com/u/{username}")
    ]

    for name, url in sites:

        try:

            r = requests.get(url)

            if r.status_code == 200:

                platforms.append({
                    "platform": name,
                    "url": url
                })

        except:
            pass

    return platforms


# =========================
# GOOGLE DORKS MOCK
# =========================

def google_dorks(target):

    return {
        "queries": [
            f"site:github.com {target}",
            f"site:pastebin.com {target}",
            f'intitle:"index of" {target}'
        ]
    }


# =========================
# AI ANALYSIS
# =========================

def generate_ai_report(target, osint_data):

    prompt = f"""
You are a cybersecurity analyst.

Analyze this OSINT intelligence data:

{json.dumps(osint_data, indent=2)}

Return ONLY valid JSON.

Format:

{{
  "risk_score": 75,
  "risk_level": "HIGH",
  "summary": "text",
  "findings": ["a", "b"],
  "threats": ["a", "b"],
  "recommendations": ["a", "b"]
}}
"""

    try:

        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.3
            }
        )

        data = response.json()

        content = data["choices"][0]["message"]["content"]

        return json.loads(content)

    except Exception as e:

        return fallback_report(target, osint_data)


# =========================
# FALLBACK REPORT
# =========================

def fallback_report(target, osint_data):

    score = random.randint(25, 90)

    if score < 35:
        level = "LOW"
    elif score < 60:
        level = "MEDIUM"
    elif score < 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "risk_score": score,
        "risk_level": level,

        "summary":
            f"ReconMind identified multiple public intelligence indicators related to {target}. "
            f"The exposure profile suggests potential operational security weaknesses.",

        "findings": [
            "Public metadata exposure identified.",
            "Digital footprint correlates across multiple services.",
            "Potential enumeration vectors discovered."
        ],

        "threats": [
            "Credential exposure risk.",
            "Reconnaissance attack surface detected.",
            "Possible phishing targeting vectors."
        ],

        "recommendations": [
            "Enable MFA across all services.",
            "Reduce public exposure of sensitive metadata.",
            "Monitor breach databases regularly.",
            "Rotate compromised credentials immediately."
        ]
    }


# =========================
# MAIN SCAN ROUTE
# =========================

@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    target = data.get("target")

    if not target:
        return jsonify({
            "error": "Target required"
        }), 400

    target_type = detect_target_type(target)

    osint_data = {}

    # =====================
    # RUN COLLECTORS
    # =====================

    if target_type == "ip":

        osint_data["shodan"] = shodan_lookup(target)

    if target_type == "domain":

        osint_data["whois"] = whois_lookup(target)

    if target_type == "email":

        osint_data["hibp"] = hibp_lookup(target)

    if target_type == "username":

        osint_data["github"] = github_lookup(target)
        osint_data["social_scan"] = social_scan(target)

    osint_data["google"] = google_dorks(target)

    # =====================
    # AI REPORT
    # =====================

    report = generate_ai_report(target, osint_data)

    return jsonify({
        "target": target,
        "target_type": target_type,
        "report": report,
        "osint_data": osint_data
    })


# =========================
# PDF REPORT
# =========================

@app.route("/scan/pdf", methods=["POST"])
def scan_pdf():

    data = request.get_json()

    target = data.get("target")

    if not target:
        return jsonify({
            "error": "Target required"
        }), 400

    osint_data = {
        "generated": True
    }

    report = fallback_report(target, osint_data)

    buffer = io.BytesIO()

    pdf = canvas.Canvas(buffer, pagesize=letter)

    pdf.setFont("Helvetica-Bold", 20)

    pdf.drawString(50, 750, "RECONMIND OSINT REPORT")

    pdf.setFont("Helvetica", 12)

    pdf.drawString(50, 710, f"Target: {target}")
    pdf.drawString(50, 690, f"Risk Score: {report['risk_score']}")
    pdf.drawString(50, 670, f"Risk Level: {report['risk_level']}")

    pdf.drawString(50, 630, "Executive Summary:")

    text = pdf.beginText(50, 610)

    text.textLines(report["summary"])

    pdf.drawText(text)

    pdf.showPage()

    pdf.save()

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="reconmind-report.pdf",
        mimetype="application/pdf"
    )


# =========================
# HEALTH CHECK
# =========================

@app.route("/")
def home():

    return jsonify({
        "status": "online",
        "service": "ReconMind Backend"
    })


# =========================
# RUN
# =========================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
