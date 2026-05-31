# ReconMind — AI-Powered OSINT Intelligence Engine

> Built by Amay Jogdand & Atharva Tavaskar · May 2026

---

I got tired of manually checking 5 different websites every time I wanted to investigate a domain, IP, or username. So I built something that does it all at once — and then has AI make sense of it.

ReconMind takes any target (IP address, email, domain, or username), pulls data from 6 different sources simultaneously, feeds all of it into an AI analysis engine, and spits out a proper threat intelligence report. The kind that actually tells you what's wrong and what to do about it — not just raw data dumps.

This is a real tool. Not a tutorial project, not a fake CRUD app. Something I'd actually use.

---

## What it does

You type in a target. It figures out what kind of target it is (IP? email? domain? username?) and automatically runs the right collectors. Everything runs in parallel so it's fast. Then Groq's Llama 3 70B model analyses everything together and produces a structured report with a risk score, key findings, identified threats, and recommendations.

The output comes in three forms — a live web dashboard, a colored terminal report, and a downloadable PDF that looks like something a real security firm would produce.

---

## The stack

**Collectors (what gathers the data)**
- Shodan — open ports, running services, known CVEs on any IP
- HaveIBeenPwned — checks if an email appears in breach databases
- WHOIS — domain registration data, age, registrar, expiry
- GitHub API — public repos, activity, potential exposed secrets
- Google Dorks — finds exposed files, configs, login pages
- Social Scan — checks username presence across platforms

**Analysis**
- Groq API (Llama 3 70B) — the AI that reads all the data and writes the actual report

**Backend**
- Python + Flask — REST API with rate limiting and security headers
- ThreadPoolExecutor — all collectors run concurrently

**Frontend**
- HTML, CSS, vanilla JavaScript
- Chart.js for the threat distribution chart
- Hosted on Vercel

**Deployment**
- Backend → Railway
- Frontend → Vercel

---

## Why I built this

There are websites that let you check one thing at a time. There are expensive enterprise tools that do everything but cost money. There's nothing in the middle that's free, open source, and actually useful.

Also I wanted to understand how real OSINT investigations work — not just theory, but actually building the pipeline from data collection to AI analysis to professional reporting. This project taught me more about cybersecurity tooling in 2 weeks than any course I've taken.

---

## Running it locally

**Clone it**
```bash
git clone https://github.com/Amay-XD/Reconmind.git
cd Reconmind
```

**Install dependencies**
```bash
pip install -r requirements.txt
```

**Set your API keys**

Copy `.env.example` to `.env` and fill in your keys:
```
SHODAN_API_KEY=your_key_here
GITHUB_TOKEN=your_key_here
WHOIS_API_KEY=your_key_here
GROQ_API_KEY=your_key_here
```

All keys are free tier — you don't need to pay for anything to run this.

**Start the backend**
```bash
cd Backend
python app.py
```

**Open the frontend**

Just open `Frontend/index.html` in your browser, or serve it with any static server.

---

## API

Two endpoints:

```
POST /scan
Body: { "target": "8.8.8.8" }
Returns: full JSON report with OSINT data + AI analysis
```

```
POST /scan/pdf
Body: { "target": "8.8.8.8" }
Returns: downloadable PDF report
```

```
GET /health
Returns: { "status": "ok", "version": "2.0.0" }
```

---

## Project structure

```
Reconmind/
├── collectors/
│   ├── shodan_collector.py
│   ├── hibp_collector.py
│   ├── whois_collector.py
│   ├── github_collector.py
│   ├── google_collector.py
│   └── social_scan_collectors.py
├── ai_engine/
│   └── groq_analysis.py
├── output/
│   ├── terminal_report.py
│   └── pdf_export.py
├── Backend/
│   └── app.py
├── Frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
├── .env.example
├── requirements.txt
└── README.md
```

---

## What I learned building this

Honestly a lot. I'd never built something where multiple APIs run simultaneously before — getting ThreadPoolExecutor working properly took a while. The PDF export was the most annoying part (ReportLab is not fun). Writing prompts for the AI that consistently return structured JSON took more iteration than I expected.

The most important thing I learned: API key security. I pushed a live Shodan key to GitHub on day one. Revoked it within 5 minutes once GitHub's secret scanner flagged it. Now everything is in `.env` files that never touch the repo. Lesson learned the fast way.

---

## Limitations

- Shodan free tier is 100 queries/month — don't spam it
- HaveIBeenPwned per-email check requires a paid API key (£3.50/month) — without it the breach collector skips the email check
- Google Dorks uses search scraping — aggressive use will get you temporarily blocked by Google
- Groq free tier is generous (14,400 requests/day) but the 70B model is slower than smaller models

---

## Ethical use

This tool is for legitimate security research, investigating your own infrastructure, and educational purposes. Don't use it on targets you don't have permission to scan. OSINT doesn't mean consequence-free — there are legal and ethical boundaries.

---

## Built with

- Python 3.13
- Flask 3.x
- Groq API (Llama 3 70B)
- ReportLab
- Shodan, HIBP, WHOIS, GitHub, Google, Social Scan APIs
- A lot of late nights

---

*If you're reading this and want to talk cybersecurity, connect with me on LinkedIn.*[www.linkedin.com/in/amay-jogdand-794758347]
