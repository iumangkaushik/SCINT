# SCINT — Scam Cyber Intelligence Tool

> **GPCSSI 2026 · Gurugram Police Cyber Security Internship**
> A command-line cyber-intelligence prototype that profiles a phone number, IP, or domain for fraud risk — combining simulated case databases with **live public threat-intelligence APIs**.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Status](https://img.shields.io/badge/status-demo-orange)
![Data](https://img.shields.io/badge/personal%20data-100%25%20synthetic-success)

---

> ## ⚠️ Disclaimer — read first
> All Aadhaar, banking, telecom, and CCTNS records in this project are **dummy data**, randomly generated for demonstration. They do **not** correspond to any real person, account, or case. SCINT does **not** connect to UIDAI, any bank, any telecom carrier, or the real CCTNS network — those feeds are restricted to authorised law-enforcement and government use. The only live data SCINT fetches is **public IP reputation**, from APIs that are free and legal for anyone to use. This tool is for **education and portfolio demonstration only.**

---

## What it does

Give SCINT an identifier and it builds a single risk picture by pulling every linked record together and scoring it 0–100:

- **Phone number** → looks across four linked local databases (Aadhaar, banking/UPI, telecom/CDR, CCTNS crime records), flags suspicious signals, and assigns a risk band.
- **IP address** → checks a local threat DB **and** queries live public APIs (geolocation, abuse reports, malware verdicts).
- **Domain / URL** → resolves it to an IP, then runs the full IP intelligence pipeline.
- **Bulk CSV** → scans a whole list at once and produces a triage table sorted highest-risk first.

Every lookup can also emit a polished **HTML report** for screenshots or sharing.

## Architecture — simulated vs. live

This split is the whole point of the design: simulate the feeds you can't legally touch, integrate the ones that are genuinely public.

| Data type | Source | Why |
|---|---|---|
| Aadhaar / CCTNS / banking / telecom (CDR) | **Dummy CSV** | Real access is restricted to police / UIDAI / banks |
| IP geolocation & ISP | **Live — ip-api.com** | Public, no key required |
| IP abuse reports | **Live — AbuseIPDB** | Public, free API key |
| IP malware/threat verdicts | **Live — VirusTotal** | Public, free API key |

## Features

- Four cross-linked local databases keyed on phone number, so one lookup returns a complete profile
- Transparent, weighted risk scoring with a human-readable factor breakdown
- Live IP threat intelligence from three public sources, aggregated into one score
- Bulk scanning with a sorted triage summary and an exported results CSV
- Optional HTML reports for every query
- API keys loaded from a local `.env` (git-ignored) — never hard-coded, never committed

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Optional, for live IP intel) add your free API keys
cp .env.example .env        # Windows: copy .env.example .env
# then edit .env and paste your VirusTotal / AbuseIPDB keys
```

Free keys: [VirusTotal](https://www.virustotal.com) (Profile → API Key) · [AbuseIPDB](https://www.abuseipdb.com) (Account → API). The phone lookups work fully **without** any keys — keys only enrich the IP/domain side.

## Usage

```bash
# Profile a phone number (local linked databases)
python scint.py --phone 9898329822

# Profile an IP (local DB + live APIs)
python scint.py --ip 45.133.1.98

# Profile a domain (auto-resolves to IP, then runs IP intel)
python scint.py --domain example.com

# Bulk-scan a CSV with a 'phone', 'ip', or 'domain' column
python scint.py --bulk sample_phones.csv

# Add --html to any lookup for a shareable report
python scint.py --phone 9898329822 --html
```

### Try these demo values

| Identifier | Type | Expected result |
|---|---|---|
| `9898329822` | phone | 🔴 HIGH — flagged Aadhaar, suspicious banking, scam calls, multiple CCTNS cases |
| `9009897600` | phone | 🟢 LOW — clean across all databases |
| `45.133.1.98` | ip | 🔴 HIGH — datacenter IP, phishing/brute-force history |
| `8.8.8.8` | ip | 🟢 LOW — clean public resolver |

## Web dashboard (browser UI)

Prefer a visual demo over the terminal? SCINT ships with a browser dashboard built on the same engine.

```bash
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000**. You get a dark "cyber" UI with three tabs — **Phone**, **IP / Domain**, and **Bulk Scan** — each showing a colored risk gauge, the detected risk factors, and the full linked profile. One-click demo buttons (e.g. `9898329822` for a high-risk hit) make it easy to present. Phone lookups need no API keys; the live IP intel uses your `.env` keys if present.

## How scoring works

Each signal contributes a fixed weight; the total is capped at 100 and bucketed into bands.

- **Phone:** flagged Aadhaar (+25), >5 suspicious transactions (+20), >2 complaints (+15), >10 scam calls (+20), VOIP usage (+10), prior CCTNS cases (+15 each, capped +30)
- **IP (live):** AbuseIPDB confidence (+20/+40), VirusTotal malicious engines (+20/+35), hosting/datacenter (+8), proxy/VPN (+10 Tor / +7 proxy)
- **Bands:** `0–39` 🟢 LOW · `40–74` 🟡 MEDIUM · `75–100` 🔴 HIGH

## Investigation methodology

Fraudsters fake the phone, the Aadhaar, and the bank account — so SCINT never *trusts* those fields. Its real job is correlating weak signals to surface the operator behind many fake identities, so a human investigator knows where to point the lawful tools. Real cases are then built by pursuing the four things a criminal can't fake: **the money cash-out, the device IMEI, reused patterns, and the physical point of sale** — all through legal process (§94 BNSS notices, CDR/IPDR, NCRP/I4C/CEIR, MLAT for foreign servers). The full breakdown is in **[INVESTIGATION_GUIDE.md](INVESTIGATION_GUIDE.md)**, and a summary lives in the dashboard's **Investigation** tab.

## Project structure

```
project1_scint/
├── scint.py            # Main CLI — lookups, scoring, bulk scan
├── app.py              # Web dashboard server (Flask)
├── templates/          # Dashboard HTML/UI
├── live_intel.py       # Live IP threat-intel API wrappers
├── report_html.py      # HTML report generator
├── generate_dataset.py # Regenerates the 100-record dummy dataset
├── data/               # Dummy CSV databases (Aadhaar, banking, telecom, CCTNS, IP)
├── sample_phones.csv   # 100 demo numbers for bulk scanning
├── sample_ips.csv      # Demo IPs for bulk scanning
├── reports/            # Generated JSON / HTML / CSV reports
├── requirements.txt
├── INVESTIGATION_GUIDE.md # How real investigators trace fraudsters
├── .env.example        # Template for API keys (copy to .env)
└── SETUP.md            # Detailed setup guide
```

The dataset ships with 100 fully-linked records in a realistic spread (~10 high-risk, ~25 medium, ~65 clean). Regenerate fresh data anytime with `python generate_dataset.py`.

## Tech stack

Python 3 · `requests` · `python-dotenv` · ip-api.com · AbuseIPDB · VirusTotal

## Legal & ethics

SCINT was built to demonstrate technical capability **and** an understanding of the legal boundaries around sensitive data. Restricted government feeds (Aadhaar, CCTNS, CDR, banking) are simulated rather than accessed; only genuinely public, legal intelligence sources are queried live. Do not point this tool at real personal records, and do not use the risk scores to make real accusations — they are illustrative outputs over fake data.

---

*Built for GPCSSI 2026, Gurugram Police Cyber Security Internship. Dummy data only.*
