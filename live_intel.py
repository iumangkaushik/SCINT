#!/usr/bin/env python3
"""
live_intel.py - Real-world threat intelligence for SCINT
GPCSSI 2026 | Gurugram Police Cyber Security Internship

LIVE, free, public sources:
  - ip-api.com      (IP geolocation + ISP, no key)
  - AbuseIPDB       (IP abuse reports, free key)
  - VirusTotal      (IP malware verdicts, free key)
  - XposedOrNot     (email breach check, FREE, no key, real emails)
  - RDAP            (domain age / WHOIS, no key)
  - libphonenumber  (phone carrier/region/line-type, offline, no key)

API keys are loaded from a local .env file and NEVER hard-coded.
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()

TIMEOUT = 10  # seconds
UA = "SCINT-GPCSSI-2026"


# --- ip-api.com - geolocation (no key required) ---
def geolocate_ip(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting,query"
        r = requests.get(url, timeout=TIMEOUT)
        data = r.json()
        if data.get("status") == "success":
            return {
                "ok": True,
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "is_proxy": data.get("proxy", False),
                "is_hosting": data.get("hosting", False),
            }
        return {"ok": False, "error": data.get("message", "lookup failed")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# --- AbuseIPDB - abuse reports ---
def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return {"ok": False, "error": "No AbuseIPDB API key configured"}
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
        data = r.json().get("data", {})
        return {
            "ok": True,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor", False),
            "last_reported": data.get("lastReportedAt"),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# --- VirusTotal - IP reputation ---
def check_virustotal_ip(ip):
    if not VIRUSTOTAL_API_KEY:
        return {"ok": False, "error": "No VirusTotal API key configured"}
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "ok": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country"),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# --- Combined live IP scoring ---
def live_ip_score(ip):
    results = {
        "geo": geolocate_ip(ip),
        "abuseipdb": check_abuseipdb(ip),
        "virustotal": check_virustotal_ip(ip),
    }
    score = 0
    factors = []

    abuse = results["abuseipdb"]
    if abuse.get("ok"):
        s = abuse["abuse_score"]
        if s >= 75:
            score += 40
            factors.append(f"AbuseIPDB confidence {s}% (high)")
        elif s >= 25:
            score += 20
            factors.append(f"AbuseIPDB confidence {s}%")
        if abuse.get("is_tor"):
            score += 10
            factors.append("Tor exit node")

    vt = results["virustotal"]
    if vt.get("ok"):
        mal = vt["malicious"]
        if mal >= 5:
            score += 35
            factors.append(f"VirusTotal: {mal} engines flag malicious")
        elif mal >= 1:
            score += 20
            factors.append(f"VirusTotal: {mal} engine(s) flag malicious")

    geo = results["geo"]
    if geo.get("ok"):
        if geo.get("is_hosting"):
            score += 8
            factors.append("Hosting/datacenter IP (not residential)")
        if geo.get("is_proxy"):
            score += 7
            factors.append("Proxy/VPN detected")

    return results, min(score, 100), factors


# --- XposedOrNot - FREE email breach check (no key, real emails) ---
def check_email_breach(email):
    """Check if a real email appears in known breaches. Free, no key needed."""
    email = (email or "").strip()
    if "@" not in email:
        return {"ok": False, "error": "Not a valid email"}
    try:
        url = "https://api.xposedornot.com/v1/check-email/" + email
        r = requests.get(url, headers={"user-agent": UA}, timeout=TIMEOUT)
        if r.status_code == 404:
            return {"ok": True, "breached": False, "count": 0, "breaches": [], "source": "XposedOrNot"}
        if r.status_code == 200:
            data = r.json()
            names = []
            b = data.get("breaches")
            if isinstance(b, list) and b and isinstance(b[0], list):
                names = b[0]
            elif isinstance(b, list):
                names = [x for x in b if isinstance(x, str)]
            return {
                "ok": True,
                "breached": bool(names),
                "count": len(names),
                "breaches": [{"name": n, "title": n} for n in names],
                "source": "XposedOrNot",
            }
        return {"ok": False, "error": f"XposedOrNot HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# --- HaveIBeenPwned - email breach (PAID; kept as an option) ---
def check_hibp(email):
    email = (email or "").strip()
    if "@" not in email:
        return {"ok": False, "error": "Not a valid email"}
    if not HIBP_API_KEY:
        return {"ok": False, "error": "No HIBP API key configured (add HIBP_API_KEY to .env)"}
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        headers = {"hibp-api-key": HIBP_API_KEY, "user-agent": UA}
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code == 404:
            return {"ok": True, "breached": False, "count": 0, "breaches": []}
        if r.status_code == 200:
            data = r.json()
            return {
                "ok": True, "breached": True, "count": len(data),
                "breaches": [{
                    "name": b.get("Name"), "title": b.get("Title"),
                    "date": b.get("BreachDate"), "data": b.get("DataClasses", []),
                } for b in data],
            }
        if r.status_code == 401:
            return {"ok": False, "error": "HIBP key rejected (401)"}
        return {"ok": False, "error": f"HIBP HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# --- RDAP - domain age / registration (no key required) ---
def domain_intel(domain):
    from datetime import datetime, timezone

    clean = (domain or "").strip().lower()
    for prefix in ("https://", "http://"):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
    clean = clean.split("/")[0].split(":")[0]

    out = {"domain": clean, "factors": []}
    if not clean or "." not in clean:
        return {"ok": False, "error": "Not a valid domain", "domain": clean, "factors": []}
    try:
        r = requests.get(f"https://rdap.org/domain/{clean}", timeout=TIMEOUT)
        if r.status_code == 404:
            return {"ok": True, "registered": None, "domain": clean,
                    "note": "No RDAP record (may be unregistered or a ccTLD without RDAP)", "factors": []}
        if r.status_code != 200:
            return {"ok": False, "error": f"RDAP HTTP {r.status_code}", "domain": clean, "factors": []}
        d = r.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
        reg = events.get("registration")
        out["registered"] = reg
        out["expires"] = events.get("expiration")
        out["last_changed"] = events.get("last changed")
        out["status"] = d.get("status", [])

        for ent in d.get("entities", []):
            if "registrar" in (ent.get("roles") or []):
                try:
                    for item in ent["vcardArray"][1]:
                        if item[0] == "fn":
                            out["registrar"] = item[3]
                except Exception:
                    pass

        if reg:
            try:
                dt = datetime.fromisoformat(reg.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - dt).days
                out["age_days"] = age_days
                out["age_years"] = round(age_days / 365.0, 1)
                out["new_domain"] = age_days < 180
                if age_days < 180:
                    out["factors"].append(f"Newly registered ({age_days} days old) - common scam signal")
            except Exception:
                pass
        out["ok"] = True
        return out
    except Exception as e:
        return {"ok": False, "error": str(e), "domain": clean, "factors": []}


# --- libphonenumber - real phone metadata (offline, no key) ---
_LINE_TYPES = {
    0: "Fixed line", 1: "Mobile", 2: "Fixed line or mobile", 3: "Toll-free",
    4: "Premium rate", 5: "Shared cost", 6: "VoIP", 7: "Personal number",
    8: "Pager", 9: "UAN", 10: "Voicemail",
}


def phone_intel(number, region="IN"):
    """Real carrier / region / line-type via Google's libphonenumber. Offline."""
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone as pntz
    except Exception:
        return {"ok": False, "error": "phonenumbers library not installed"}
    try:
        n = phonenumbers.parse(number, region)
        valid = phonenumbers.is_valid_number(n)
        t = phonenumbers.number_type(n)
        return {
            "ok": True,
            "valid": valid,
            "e164": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164),
            "carrier": carrier.name_for_number(n, "en") or "Unknown",
            "region": geocoder.description_for_number(n, "en") or "Unknown",
            "line_type": _LINE_TYPES.get(t, "Unknown"),
            "timezones": list(pntz.time_zones_for_number(n)),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


if __name__ == "__main__":
    import sys, json
    test_ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(f"Testing live intel on {test_ip}...\n")
    res, score, factors = live_ip_score(test_ip)
    print(json.dumps(res, indent=2))
    print(f"\nLive risk contribution: {score}/100")
    print("Factors:", factors or "none")
    print("\nPhone intel 9898329822:", json.dumps(phone_intel("9898329822"), indent=2))
