# SCINT v2 — Setup Guide

**Scam Cyber Intelligence Tool** | GPCSSI 2026 | Gurugram Police

Combines local case databases (dummy: Aadhaar, CCTNS, banking, telecom)
with **live, real threat intelligence** from public APIs.

---

## What's new in v6

- Live IP geolocation via **ip-api.com** (no key needed)
- Live abuse reports via **AbuseIPDB** (free key)
- Live malware/threat verdicts via **VirusTotal** (free key)
- API keys loaded safely from a `.env` file — never hard-coded, never on GitHub

---

## One-time setup (10 minutes)

### 1. Install Python dependencies
Open a terminal **inside the project folder** and run:

```bash
pip install -r requirements.txt
```

### 2. Create your secrets file
Make a copy of the template:

```bash
# Mac / Linux
cp .env.example .env

# Windows (PowerShell)
copy .env.example .env
```

### 3. Paste your API keys into `.env`
Open `.env` in any text editor and fill in:

```
VIRUSTOTAL_API_KEY=your_real_virustotal_key
ABUSEIPDB_API_KEY=your_real_abuseipdb_key
```

> Get them free at:
> - VirusTotal: https://www.virustotal.com (Profile → API Key)
> - AbuseIPDB: https://www.abuseipdb.com (Account → API)

**Important:** the `.env` file stays on your computer. The included
`.gitignore` makes sure it never gets uploaded to GitHub.

---

## Running it

```bash
# Look up a phone number (uses local case databases)
python scint.py --phone 9876543210

# Look up an IP address (uses local DB + LIVE APIs)
python scint.py --ip 45.133.1.98

# Try a real malicious IP to see live data in action:
python scint.py --ip 185.220.101.45
```

---

## How it stays legal & professional

| Data type            | Source            | Why                                  |
|----------------------|-------------------|--------------------------------------|
| Aadhaar / CCTNS / CDR| Dummy CSV         | Real access is police/UIDAI-only     |
| IP reputation        | **Live APIs**     | Public, free, legal for anyone       |

This is exactly how a real prototype works: simulate the restricted
government feeds, integrate the genuinely-public intelligence sources.
Say that in your interview — it shows you understand both the tech
*and* the legal boundaries.

---

## Troubleshooting

- **"No API key configured"** → your `.env` is missing or the key line is blank.
- **`ModuleNotFoundError`** → run `pip install -r requirements.txt` again.
- **Colors look weird on Windows** → use Windows Terminal or PowerShell, not old cmd.exe.
