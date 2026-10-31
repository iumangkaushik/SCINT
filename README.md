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

**Live demo:** https://scint-3x72.onrender.com/ (free hosting, may take 30–60 s to wake on first load)

## Security problem

Cyber-fraud investigations (UPI scams, "digital arrest" calls, fake-loan apps) start with a handful of identifiers: a phone number, a UPI ID, an IP, a website. Each lives in a different silo (identity, bank, telecom, crime records, public threat feeds), so an investigator spends hours cross-checking by hand and can still miss that ten "different" suspects share one SIM box or one VPS. SCINT correlates those silos in one lookup, scores the result with a **transparent, explainable** 0–100 risk score, and — just as important — avoids the classic false positives that would point an investigator at an innocent person (see [False-positive handling](#false-positive-handling)).

## Intended users

- Cyber-cell investigators and analysts triaging fraud complaints (the GPCSSI use case)
- SOC / fraud-team analysts who need a quick reputation check on IPs and domains
- Students learning how threat-intel correlation and risk scoring work, using safe synthetic data

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

- **Phone:** flagged Aadhaar (+25), >5 suspicious transactions (+20), >2 complaints (+15), >10 scam calls (+20), VOIP usage (+10), prior CCTNS cases (+15 each, capped +30), IP shared with flagged numbers (+5 each, capped +15 — only when the IP is *not* a shared gateway), 3+ databases agreeing (+10)
- **IP (live):** AbuseIPDB confidence ≥25% (+20) / ≥75% (+40), VirusTotal malicious engines ≥2 (+20) / ≥5 (+35), hosting/datacenter (+8), Tor (+10), proxy/VPN (+7)
- **Bands:** `0–39` 🟢 LOW · `40–74` 🟡 MEDIUM · `75–100` 🔴 HIGH

## False-positive handling

A fraud tool that flags innocent people is worse than useless, so SCINT deliberately refuses to score three signals that look suspicious but usually aren't:

| Looks suspicious | Why it's usually innocent | What SCINT does |
|---|---|---|
| **1 VirusTotal engine** flags an IP as malicious | Single-vendor detections are a well-known false-positive pattern (one stale blocklist, a previously-dirty reassigned IP) | Needs **≥2 engines** to add risk. A lone hit is shown as an informational note, scored 0 |
| A phone **shares an IP** with a flagged number | Indian mobile carriers put thousands of subscribers behind one public IP (carrier-grade NAT); public Wi-Fi does the same | If more than 10 numbers share the IP, or it is in the CGNAT range `100.64.0.0/10`, the link is reported as a "shared gateway" and **not scored**. Small clusters (e.g. 3 numbers on one VPS) are still flagged |
| A **private / CGNAT / loopback IP** is entered | `192.168.x.x`, `10.x.x.x`, `100.64.x.x` identify no one on the internet | Rejected before any API call: never scored, never sent to third parties |

Each rule has a unit test in [`tests/test_scoring.py`](tests/test_scoring.py), alongside true-positive tests proving real rings are still caught.

## Running the tests

```bash
python -m unittest -v
```

10 tests, no network or API keys needed (external APIs are mocked). Expected output: [`samples/output_tests.txt`](samples/output_tests.txt).

## Sample input and output

All outputs below were produced by real runs and saved with colours stripped.

| Input | Command | Expected output |
|---|---|---|
| Known fraud number | `python scint.py --phone 9898329822` | [`output_phone_high_risk.txt`](samples/output_phone_high_risk.txt) — 100/100 HIGH |
| Clean number | `python scint.py --phone 9009897600` | [`output_phone_clean.txt`](samples/output_phone_clean.txt) — LOW |
| [`sample_phones.csv`](sample_phones.csv) (100 numbers) | `python scint.py --bulk sample_phones.csv` | [`output_bulk_phones.txt`](samples/output_bulk_phones.txt) — 13 HIGH / 10 MEDIUM / 77 LOW |
| Private IP (false-positive guard) | `python scint.py --ip 192.168.1.10` | [`output_ip_private_rejected.txt`](samples/output_ip_private_rejected.txt) — rejected, no API calls |

## Investigation methodology

Fraudsters fake the phone, the Aadhaar, and the bank account — so SCINT never *trusts* those fields. Its real job is correlating weak signals to surface the operator behind many fake identities, so a human investigator knows where to point the lawful tools. Real cases are then built by pursuing the four things a criminal can't fake: **the money cash-out, the device IMEI, reused patterns, and the physical point of sale** — all through legal process (§94 BNSS notices, CDR/IPDR, NCRP/I4C/CEIR, MLAT for foreign servers). The full breakdown is in **[INVESTIGATION_GUIDE.md](INVESTIGATION_GUIDE.md)**, and a summary lives in the dashboard's **Investigation** tab.

## Project structure

```
SCINT/
├── scint.py            # Main CLI — lookups, scoring, bulk scan
├── app.py              # Web dashboard server (Flask)
├── templates/          # Dashboard HTML/UI
├── live_intel.py       # Live IP threat-intel API wrappers + IP validation
├── db.py               # SQLite layer for dashboard analytics
├── report_html.py      # HTML report generator
├── report_pdf.py       # PDF case report generator
├── generate_dataset.py # Regenerates the 100-record dummy dataset
├── data/               # Dummy CSV databases (Aadhaar, banking, telecom, CCTNS, IP)
├── tests/              # Unit tests (scoring + false-positive rules)
├── samples/            # Expected outputs from real runs
├── sample_phones.csv   # 100 demo numbers for bulk scanning
├── sample_ips.csv      # Demo IPs for bulk scanning
├── reports/            # Generated JSON / HTML / CSV reports (git-ignored)
├── requirements.txt
├── INVESTIGATION_GUIDE.md # How real investigators trace fraudsters
├── AI_USAGE.md         # How AI was used, and how its output was checked
├── .env.example        # Template for API keys (copy to .env)
└── SETUP.md            # Detailed setup guide
```

The dataset ships with 100 fully-linked records in a realistic spread (~10 high-risk, ~25 medium, ~65 clean). Regenerate fresh data anytime with `python generate_dataset.py`.

## Tech stack

Python 3 · Flask · SQLite · `requests` · `python-dotenv` · `phonenumbers` · `reportlab` · `feedparser` · `unittest` · ip-api.com · AbuseIPDB · VirusTotal · XposedOrNot · RDAP

## Security considerations

- **Secrets:** API keys are read from a git-ignored `.env`; nothing is hard-coded. The full git history has been checked — no key or `.env` was ever committed.
- **No real personal data:** every Aadhaar / bank / telecom / CCTNS record is generated by `generate_dataset.py` (fixed seed). Don't load real PII into it.
- **Input validation:** IPs are parsed with Python's `ipaddress` module before they are placed in any API URL, so input like `8.8.8.8/../users` can't alter the request path. Report filenames keep only digits/`+` from the phone number, so input can't write outside `reports/`.
- **Third-party disclosure:** looking up an IP on VirusTotal/AbuseIPDB tells those services what you are investigating. Private and CGNAT addresses are never sent.
- **Web dashboard:** all dynamic values are HTML-escaped before rendering (XSS). The Werkzeug debugger (which allows code execution) is off unless `SCINT_DEBUG=1` is set.
- **Transport:** ip-api.com's free tier is HTTP-only, so geolocation lookups are not encrypted in transit. AbuseIPDB and VirusTotal use HTTPS.
- **Lawful use:** SCINT only queries public, lawful sources. It performs no scanning, exploitation or access to anyone's systems.

## Known limitations

- **Phone format must match exactly.** `9898329822` scores 100, but `+91 9898329822` or `+919898329822` score **0** — a false negative. Numbers are not yet normalised.
- **Scores are illustrative.** Weights are hand-chosen heuristics over synthetic data, not calibrated against real case outcomes. A score is a triage hint, never evidence.
- **The shared-gateway threshold (10 numbers) is a heuristic.** A large ring behind one VPS would be treated as a gateway (missed), and a small office NAT could still link unrelated people.
- **Ignoring single-engine VirusTotal hits trades some recall for precision.** A genuinely new malicious IP seen by only one vendor will not raise the score.
- **Domains resolve to one IP.** CDN-fronted sites (Cloudflare etc.) resolve to the CDN, so the IP score describes the CDN, not the scam site.
- **Free API limits.** VirusTotal's free tier allows ~4 requests/minute, so bulk IP scans will hit rate limits.
- **The dashboard has no login, CSRF protection or rate limiting.** It is a demo; the public instance stores whatever visitors type.
- **Two scoring paths.** The detailed `--phone` view and the bulk/dashboard scorer (`score_phone_quiet`) share weights, but only the latter adds the shared-IP and cross-database bonuses, so a number can score slightly differently in each.

## Future improvements

- Normalise phone numbers to E.164 with `phonenumbers` before matching (fixes the `+91` false negative)
- Add authentication, CSRF tokens, rate limiting and an audit log to the dashboard
- Cache API responses and back off on rate limits
- Resolve all A/AAAA records and recognise CDN ranges for domain lookups
- Calibrate weights on labelled data and report a confidence alongside the score
- Extend tests to the Flask API endpoints

## Legal & ethics

SCINT was built to demonstrate technical capability **and** an understanding of the legal boundaries around sensitive data. Restricted government feeds (Aadhaar, CCTNS, CDR, banking) are simulated rather than accessed; only genuinely public, legal intelligence sources are queried live. Do not point this tool at real personal records, and do not use the risk scores to make real accusations — they are illustrative outputs over fake data.

## License

This project is licensed under the [MIT License](LICENSE).

---

*Built for GPCSSI 2026, Gurugram Police Cyber Security Internship. Dummy data only.*
