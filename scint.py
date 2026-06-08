#!/usr/bin/env python3
"""
SCINT - Scam Cyber Intelligence Tool
GPCSSI 2026 | Gurugram Police Cyber Security Internship
Built for educational/demonstration purposes using dummy data only.
"""

import csv
import argparse
import json
import os
from datetime import datetime

# Live intelligence module (real APIs) — fails loud so we never hide errors
try:
    import live_intel
    LIVE_AVAILABLE = True
    LIVE_IMPORT_ERROR = None
except Exception as _e:
    LIVE_AVAILABLE = False
    LIVE_IMPORT_ERROR = str(_e)

# Live intelligence module (real APIs)
try:
    import live_intel
    LIVE_AVAILABLE = True
except Exception:
    LIVE_AVAILABLE = False

# ─── ANSI Colors ────────────────────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

# ─── Helpers ────────────────────────────────────────────────────────────────

def load_csv(filename):
    path = os.path.join(DATA_DIR, filename)
    rows = []
    try:
        with open(path, newline='', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError:
        print(f"{RED}[!] Data file not found: {filename}{RESET}")
    return rows

def risk_color(score):
    score = int(score)
    if score >= 75:
        return f"{RED}{BOLD}{score}/100 🔴 HIGH RISK{RESET}"
    elif score >= 40:
        return f"{YELLOW}{score}/100 🟡 MEDIUM RISK{RESET}"
    else:
        return f"{GREEN}{score}/100 🟢 LOW RISK{RESET}"

def banner():
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║         ███████╗ ██████╗██╗███╗   ██╗████████╗             ║
║         ██╔════╝██╔════╝██║████╗  ██║╚══██╔══╝             ║
║         ███████╗██║     ██║██╔██╗ ██║   ██║                ║
║         ╚════██║██║     ██║██║╚██╗██║   ██║                ║
║         ███████║╚██████╗██║██║ ╚████║   ██║                ║
║         ╚══════╝ ╚═════╝╚═╝╚═╝  ╚═══╝   ╚═╝                ║
║                                                              ║
║       Scam Cyber Intelligence Tool  v1.0                    ║
║       GPCSSI 2026 | Gurugram Police                         ║
║       ⚠  DUMMY DATA — FOR DEMONSTRATION ONLY ⚠             ║
╚══════════════════════════════════════════════════════════════╝
{RESET}""")

def section(title):
    print(f"\n{CYAN}{'━'*62}{RESET}")
    print(f"{BOLD}{WHITE} {title}{RESET}")
    print(f"{CYAN}{'━'*62}{RESET}")

def field(label, value, alert=False):
    color = RED if alert else WHITE
    print(f"  {DIM}{label:<28}{RESET}{color}{value}{RESET}")

# ─── Lookup Modules ─────────────────────────────────────────────────────────

def lookup_phone(phone, make_html=False):
    print(f"\n{BOLD}{CYAN}[*] Analyzing phone number: {phone}{RESET}")
    print(f"{DIM}    Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")

    risk_factors = []
    total_score = 0

    # ── Aadhaar ──────────────────────────────────────────────────────────────
    section("AADHAAR INTELLIGENCE  [DUMMY DATA]")
    aadhaar_rows = load_csv("aadhaar_db.csv")
    aadhaar_match = next((r for r in aadhaar_rows if r['phone'] == phone), None)
    if aadhaar_match:
        flagged = aadhaar_match['flagged'] == 'True'
        field("Name",         aadhaar_match['name'])
        field("Aadhaar ID",   aadhaar_match['aadhaar_id'])
        field("Date of Birth",aadhaar_match['dob'])
        field("Address",      aadhaar_match['address'])
        field("Flagged",      "⚠️  YES — Known fraud identity" if flagged else "✅ No flags", alert=flagged)
        if flagged:
            risk_factors.append("Flagged Aadhaar identity")
            total_score += 25
    else:
        print(f"  {YELLOW}No Aadhaar record found.{RESET}")

    # ── Banking ──────────────────────────────────────────────────────────────
    section("BANKING & UPI INTELLIGENCE  [DUMMY DATA]")
    bank_rows = load_csv("banking_db.csv")
    bank_match = next((r for r in bank_rows if r['phone'] == phone), None)
    if bank_match:
        complaints = int(bank_match['linked_complaints'])
        transactions = int(bank_match['suspicious_transactions'])
        field("UPI ID",                   bank_match['upi_id'])
        field("Bank",                     bank_match['bank'])
        field("Account Type",             bank_match['account_type'])
        field("Suspicious Transactions",  bank_match['suspicious_transactions'], alert=transactions > 5)
        field("Suspicious Amount",        bank_match['total_amount_suspicious'], alert=transactions > 5)
        field("Linked Complaints",        bank_match['linked_complaints'], alert=complaints > 2)
        if transactions > 5:
            risk_factors.append(f"{transactions} suspicious transactions")
            total_score += 20
        if complaints > 2:
            risk_factors.append(f"{complaints} banking complaints")
            total_score += 15
    else:
        print(f"  {YELLOW}No banking record found.{RESET}")

    # ── Telecom ──────────────────────────────────────────────────────────────
    section("TELECOM / CDR / IPDR  [DUMMY DATA]")
    telecom_rows = load_csv("telecom_db.csv")
    tel_match = next((r for r in telecom_rows if r['phone'] == phone), None)
    if tel_match:
        flagged = tel_match['flagged'] == 'True'
        scam_calls = int(tel_match['calls_to_scam_numbers'])
        voip = tel_match['voip_usage'] == 'Yes'
        field("Carrier",                  tel_match['carrier'])
        field("SIM Type",                 tel_match['sim_type'])
        field("Calls to Scam Numbers",    tel_match['calls_to_scam_numbers'], alert=scam_calls > 10)
        field("International Calls",      tel_match['international_calls'])
        field("VOIP Usage",               "⚠️  YES — Suspicious" if voip else "No", alert=voip)
        field("Linked IP Address",        tel_match['linked_ips'])
        field("Last Known Location",      tel_match['last_location'])
        if scam_calls > 10:
            risk_factors.append(f"{scam_calls} calls to known scam numbers")
            total_score += 20
        if voip:
            risk_factors.append("VOIP usage detected")
            total_score += 10
    else:
        print(f"  {YELLOW}No telecom record found.{RESET}")

    # ── CCTNS ────────────────────────────────────────────────────────────────
    section("CCTNS — CRIME RECORDS  [DUMMY DATA]")
    cctns_rows = load_csv("cctns_db.csv")
    cctns_matches = [r for r in cctns_rows if r['phone'] == phone]
    if cctns_matches:
        for case in cctns_matches:
            print(f"\n  {RED}▸ Case: {case['case_number']}{RESET}")
            field("  Year",         case['year'])
            field("  Crime Type",   case['crime_type'], alert=True)
            field("  Police Station", case['police_station'])
            field("  Status",       case['status'])
            field("  Victims",      case['victim_count'])
        risk_factors.append(f"{len(cctns_matches)} prior criminal case(s)")
        total_score += min(len(cctns_matches) * 15, 30)
    else:
        print(f"  {GREEN}✅ No prior criminal record found.{RESET}")

    # ── Risk Score ───────────────────────────────────────────────────────────
    section("RISK ASSESSMENT")
    total_score = min(total_score, 100)
    print(f"\n  {BOLD}Overall Risk Score   : {risk_color(total_score)}{RESET}")

    if risk_factors:
        print(f"\n  {YELLOW}Risk Factors Detected:{RESET}")
        for f_ in risk_factors:
            print(f"    {RED}→ {f_}{RESET}")

    if total_score >= 75:
        print(f"\n  {RED}{BOLD}RECOMMENDED ACTION:{RESET}")
        print(f"  {RED}→ File Section 94 BNSS notice immediately")
        print(f"  → Freeze linked bank accounts")
        print(f"  → Coordinate with Cyber PS Gurugram{RESET}")
    elif total_score >= 40:
        print(f"\n  {YELLOW}RECOMMENDED ACTION:{RESET}")
        print(f"  {YELLOW}→ Flag for further monitoring")
        print(f"  → Cross-reference with active cases{RESET}")
    else:
        print(f"\n  {GREEN}→ No immediate action required. Continue monitoring.{RESET}")

    # ── Save Report ──────────────────────────────────────────────────────────
    report = {
        "query": phone,
        "type": "phone",
        "timestamp": datetime.now().isoformat(),
        "risk_score": total_score,
        "risk_factors": risk_factors,
        "aadhaar": aadhaar_match,
        "banking": bank_match,
        "telecom": tel_match,
        "cctns_cases": cctns_matches,
        "disclaimer": "DUMMY DATA — FOR DEMONSTRATION PURPOSES ONLY"
    }
    report_path = os.path.join(BASE_DIR, "reports", f"scint_{phone}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(report_path, 'w') as f_:
        json.dump(report, f_, indent=2)

    print(f"\n{DIM}{'─'*62}{RESET}")
    print(f"  {DIM}Report saved → {report_path}{RESET}")
    print(f"{DIM}{'─'*62}{RESET}\n")

    if make_html:
        _emit_html(report)


def lookup_ip(ip, make_html=False):
    print(f"\n{BOLD}{CYAN}[*] Analyzing IP address: {ip}{RESET}")
    print(f"{DIM}    Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")

    section("IP THREAT INTELLIGENCE  [DUMMY DATA]")
    ip_rows = load_csv("ip_threat_db.csv")
    match = next((r for r in ip_rows if r['ip'] == ip), None)

    local_score = 0
    if match:
        local_score = int(match['risk_score'])
        field("IP Address",      match['ip'])
        field("Country",         match['country'])
        field("City",            match['city'])
        field("ISP",             match['isp'])
        field("Type",            match['type'], alert=match['type'] != 'Residential')
        field("Abuse Reports",   match['abuse_reports'], alert=int(match['abuse_reports']) > 20)
        field("Attack Types",    match['attack_types'], alert=True)
        field("Last Reported",   match['last_reported'])

        section("RISK ASSESSMENT")
        print(f"\n  {BOLD}Overall Risk Score   : {risk_color(local_score)}{RESET}")

        if local_score >= 75:
            print(f"\n  {RED}{BOLD}RECOMMENDED ACTION:{RESET}")
            print(f"  {RED}→ Block IP at network/firewall level")
            print(f"  → File Section 94 BNSS notice to hosting provider")
            print(f"  → Cross-reference with active case indicators{RESET}")
    else:
        print(f"  {YELLOW}IP not found in local threat database.{RESET}")

    # ── LIVE THREAT INTELLIGENCE (real APIs) ─────────────────────────────────
    section("LIVE THREAT INTELLIGENCE  [REAL DATA]")
    live_results, live_score, live_factors = {}, 0, []
    if not LIVE_AVAILABLE:
        print(f"  {RED}Live module failed to load: {LIVE_IMPORT_ERROR}{RESET}")
    else:
        live_results, live_score, live_factors = live_intel.live_ip_score(ip)

        geo = live_results["geo"]
        if geo.get("ok"):
            field("Country (live)",   geo.get("country"))
            field("City (live)",      geo.get("city"))
            field("ISP (live)",       geo.get("isp"))
            field("Hosting/DC",       "YES" if geo.get("is_hosting") else "No", alert=geo.get("is_hosting"))
            field("Proxy/VPN",        "YES" if geo.get("is_proxy") else "No", alert=geo.get("is_proxy"))
        else:
            print(f"  {DIM}Geo lookup: {geo.get('error')}{RESET}")

        abuse = live_results["abuseipdb"]
        if abuse.get("ok"):
            field("AbuseIPDB Score",  f"{abuse['abuse_score']}%", alert=abuse['abuse_score'] >= 25)
            field("Total Reports",    abuse.get("total_reports"), alert=abuse.get("total_reports", 0) > 20)
            field("Usage Type",       abuse.get("usage_type"))
            field("Tor Exit Node",    "YES" if abuse.get("is_tor") else "No", alert=abuse.get("is_tor"))
        else:
            print(f"  {YELLOW}AbuseIPDB: {abuse.get('error')}{RESET}")

        vt = live_results["virustotal"]
        if vt.get("ok"):
            field("VirusTotal Malicious",  vt["malicious"],  alert=vt["malicious"] > 0)
            field("VirusTotal Suspicious", vt["suspicious"], alert=vt["suspicious"] > 0)
            field("VirusTotal Harmless",   vt["harmless"])
        else:
            print(f"  {YELLOW}VirusTotal: {vt.get('error')}{RESET}")

        if live_factors:
            print(f"\n  {YELLOW}Live Risk Factors:{RESET}")
            for lf in live_factors:
                print(f"    {RED}-> {lf}{RESET}")
        print(f"\n  {BOLD}Live Risk Score      : {risk_color(live_score)}{RESET}")

    print(f"\n{DIM}{'─'*62}{RESET}\n")

    # ── Optional HTML report ──────────────────────────────────────────────────
    if make_html:
        overall = max(local_score, live_score)
        report = {
            "query": ip,
            "type": "ip",
            "timestamp": datetime.now().isoformat(),
            "risk_score": overall,
            "risk_factors": live_factors,
            "local": match,
            "live": live_results,
        }
        _emit_html(report)


def _emit_html(report):
    """Generate and announce an HTML report, if the generator is available."""
    try:
        import report_html
        reports_dir = os.path.join(BASE_DIR, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        path = report_html.save_report(report, reports_dir)
        print(f"  {GREEN}📄 HTML report saved → {path}{RESET}")
        print(f"  {DIM}Open it in your browser to view / screenshot.{RESET}\n")
    except Exception as e:
        print(f"  {YELLOW}Could not generate HTML report: {e}{RESET}\n")


def lookup_domain(domain, make_html=False):
    """Resolve a domain/website to its IP, then run the full IP intelligence check."""
    import socket

    # Strip common prefixes so users can paste a full URL or a bare domain
    clean = domain.strip()
    for prefix in ("https://", "http://"):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
    clean = clean.split("/")[0]   # drop any path
    clean = clean.split(":")[0]   # drop any port

    print(f"\n{BOLD}{CYAN}[*] Resolving domain: {clean}{RESET}")
    try:
        ip = socket.gethostbyname(clean)
        print(f"  {GREEN}-> Resolved to IP: {ip}{RESET}")
    except socket.gaierror:
        print(f"  {RED}[!] Could not resolve '{clean}'. Check the spelling or your internet connection.{RESET}\n")
        return

    # Hand off to the existing IP intelligence pipeline
    lookup_ip(ip, make_html=make_html)


# ─── Bulk Scanning ────────────────────────────────────────────────────────────

def score_phone_quiet(phone):
    """Compute a phone risk score with NO printing. Returns (score, factors, summary)."""
    factors = []
    score = 0

    a = next((r for r in load_csv("aadhaar_db.csv") if r['phone'] == phone), None)
    if a and a.get('flagged') == 'True':
        factors.append("Flagged Aadhaar"); score += 25

    b = next((r for r in load_csv("banking_db.csv") if r['phone'] == phone), None)
    if b:
        tx = int(b.get('suspicious_transactions', 0) or 0)
        cp = int(b.get('linked_complaints', 0) or 0)
        if tx > 5: factors.append(f"{tx} susp. txns"); score += 20
        if cp > 2: factors.append(f"{cp} complaints"); score += 15

    t = next((r for r in load_csv("telecom_db.csv") if r['phone'] == phone), None)
    if t:
        sc = int(t.get('calls_to_scam_numbers', 0) or 0)
        if sc > 10: factors.append(f"{sc} scam calls"); score += 20
        if t.get('voip_usage') == 'Yes': factors.append("VOIP"); score += 10

    cases = [r for r in load_csv("cctns_db.csv") if r['phone'] == phone]
    if cases:
        factors.append(f"{len(cases)} case(s)"); score += min(len(cases) * 15, 30)

    # Network proximity — shared IP with flagged numbers
    if t and t.get('linked_ips'):
        linked_ip = t['linked_ips']
        shared_flagged = [r for r in load_csv("telecom_db.csv")
                          if r.get('linked_ips') == linked_ip
                          and r['phone'] != phone
                          and r.get('flagged') == 'True']
        if shared_flagged:
            factors.append(f"IP shared with {len(shared_flagged)} flagged number(s)")
            score += min(len(shared_flagged) * 5, 15)

    # Cross-database correlation bonus
    flagged_count = sum([
        bool(a and a.get('flagged') == 'True'),
        bool(b and int(b.get('suspicious_transactions', 0) or 0) > 5),
        bool(t and int(t.get('calls_to_scam_numbers', 0) or 0) > 10),
        bool(cases),
    ])
    if flagged_count >= 3:
        factors.append(f"Cross-DB correlation ({flagged_count} sources)")
        score += 10

    score = min(score, 100)
    return score, factors


def score_ip_quiet(ip):
    """Compute an IP risk score with NO section printing. Returns (score, factors)."""
    factors = []
    score = 0
    match = next((r for r in load_csv("ip_threat_db.csv") if r['ip'] == ip), None)
    if match:
        score = max(score, int(match.get('risk_score', 0) or 0))
        if match.get('attack_types'):
            factors.append(match['attack_types'])
    if LIVE_AVAILABLE:
        try:
            _, live_score, live_factors = live_intel.live_ip_score(ip)
            score = max(score, live_score)
            factors.extend(live_factors)
        except Exception:
            pass
    return min(score, 100), factors


def bulk_scan(csv_path):
    """
    Read a CSV with a column named 'phone', 'ip', or 'domain' and scan each row.
    Prints a summary table and saves results to reports/bulk_results_<timestamp>.csv.
    """
    import socket

    if not os.path.isfile(csv_path):
        print(f"{RED}[!] File not found: {csv_path}{RESET}")
        return

    rows = list(csv.DictReader(open(csv_path, newline='', encoding='utf-8')))
    if not rows:
        print(f"{RED}[!] No rows found in {csv_path}{RESET}")
        return

    cols = [c.lower() for c in rows[0].keys()]
    if "phone" in cols:
        kind = "phone"
    elif "ip" in cols:
        kind = "ip"
    elif "domain" in cols:
        kind = "domain"
    else:
        print(f"{RED}[!] CSV must have a 'phone', 'ip', or 'domain' column.{RESET}")
        print(f"{DIM}    Found columns: {', '.join(rows[0].keys())}{RESET}")
        return

    print(f"\n{BOLD}{CYAN}[*] Bulk scanning {len(rows)} {kind}(s) from {os.path.basename(csv_path)}{RESET}")
    print(f"{DIM}    This may take a moment for IP/domain lookups (live API calls)...{RESET}\n")

    results = []
    for i, row in enumerate(rows, 1):
        value = (row.get(kind) or row.get(kind.capitalize()) or "").strip()
        if not value:
            continue

        if kind == "phone":
            score, factors = score_phone_quiet(value)
            target = value
        else:
            target = value
            if kind == "domain":
                for pre in ("https://", "http://"):
                    if target.startswith(pre): target = target[len(pre):]
                target = target.split("/")[0].split(":")[0]
                try:
                    target = socket.gethostbyname(target)
                except socket.gaierror:
                    results.append((value, "ERR", "could not resolve"))
                    print(f"  {DIM}[{i}/{len(rows)}]{RESET} {value:<24} {YELLOW}resolve failed{RESET}")
                    continue
            score, factors = score_ip_quiet(target)

        band = "HIGH" if score >= 75 else ("MED" if score >= 40 else "LOW")
        col = RED if band == "HIGH" else (YELLOW if band == "MED" else GREEN)
        results.append((value, score, "; ".join(factors) or "—"))
        print(f"  {DIM}[{i}/{len(rows)}]{RESET} {value:<24} {col}{score:>3}/100  {band}{RESET}  {DIM}{'; '.join(factors[:2])}{RESET}")

    # Sort highest-risk first for the summary
    sortable = [r for r in results if isinstance(r[1], int)]
    sortable.sort(key=lambda r: r[1], reverse=True)

    section("BULK SCAN SUMMARY — sorted by risk")
    high = sum(1 for r in sortable if r[1] >= 75)
    med  = sum(1 for r in sortable if 40 <= r[1] < 75)
    low  = sum(1 for r in sortable if r[1] < 40)
    print(f"  {RED}HIGH: {high}{RESET}   {YELLOW}MEDIUM: {med}{RESET}   {GREEN}LOW: {low}{RESET}   Total: {len(results)}\n")
    for value, score, factors in sortable[:10]:
        col = RED if score >= 75 else (YELLOW if score >= 40 else GREEN)
        print(f"    {col}{score:>3}/100{RESET}  {value:<24} {DIM}{factors[:50]}{RESET}")
    if len(sortable) > 10:
        print(f"    {DIM}... and {len(sortable) - 10} more in the saved CSV{RESET}")

    # Save results CSV
    reports_dir = os.path.join(BASE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    out_path = os.path.join(reports_dir, f"bulk_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    with open(out_path, "w", newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow([kind, "risk_score", "risk_factors"])
        for r in results:
            w.writerow(r)
    print(f"\n  {GREEN}📊 Results saved → {out_path}{RESET}")
    print(f"  {DIM}Open in Excel to sort/filter all {len(results)} results.{RESET}\n")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="SCINT - Scam Cyber Intelligence Tool (GPCSSI 2026)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--phone",  help="Lookup a phone number\n  Example: --phone 9876543210")
    parser.add_argument("--ip",     help="Lookup an IP address\n  Example: --ip 45.133.1.98")
    parser.add_argument("--domain", help="Lookup a website/domain (auto-resolves IP)\n  Example: --domain github.com")
    parser.add_argument("--bulk",   help="Bulk-scan a CSV file (column: phone, ip, or domain)\n  Example: --bulk suspects.csv")
    parser.add_argument("--html",   action="store_true", help="Also generate a professional HTML report")

    args = parser.parse_args()

    if args.bulk:
        bulk_scan(args.bulk)
    elif args.phone:
        lookup_phone(args.phone, make_html=args.html)
    elif args.ip:
        lookup_ip(args.ip, make_html=args.html)
    elif args.domain:
        lookup_domain(args.domain, make_html=args.html)
    else:
        parser.print_help()
        print(f"\n{YELLOW}Example usage:{RESET}")
        print(f"  python3 scint.py --phone 9876543210")
        print(f"  python3 scint.py --ip 45.133.1.98")
        print(f"  python3 scint.py --domain github.com")
        print(f"  python3 scint.py --ip 45.133.1.98 --html  {DIM}(adds HTML report){RESET}\n")

if __name__ == "__main__":
    main()
