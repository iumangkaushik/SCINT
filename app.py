#!/usr/bin/env python3
"""
app.py - SCINT Web Dashboard
GPCSSI 2026 | Gurugram Police Cyber Security Internship

A browser UI for the SCINT engine. Reuses the exact scoring logic from
scint.py so the dashboard and the CLI always agree.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000 in your browser.

Aadhaar / banking / telecom / CCTNS data is DUMMY. Only IP / email / domain /
phone-metadata lookups are live.
"""

import socket
import csv
import io
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file

import scint  # reuse load_csv + scoring functions
import db      # SQLite layer for analytics

try:
    import live_intel
    LIVE_AVAILABLE = True
except Exception:
    LIVE_AVAILABLE = False

try:
    import report_pdf
    PDF_AVAILABLE = True
except Exception:
    PDF_AVAILABLE = False

CITY_COORDS = {
    "Gurugram": [28.46, 77.03], "Delhi": [28.61, 77.21], "Noida": [28.54, 77.39],
    "Faridabad": [28.41, 77.31], "Jaipur": [26.91, 75.79], "Kolkata": [22.57, 88.36],
    "Mumbai": [19.08, 72.88], "Pune": [18.52, 73.86], "Bengaluru": [12.97, 77.59],
    "Lucknow": [26.85, 80.95], "Chennai": [13.08, 80.27], "Hyderabad": [17.38, 78.49],
    "Ahmedabad": [23.02, 72.57], "Chandigarh": [30.73, 76.78], "Bhopal": [23.26, 77.41],
    "Indore": [22.72, 75.86], "Patna": [25.61, 85.14], "Ranchi": [23.34, 85.31],
    "Bhubaneswar": [20.30, 85.82], "Guwahati": [26.14, 91.74], "Dehradun": [30.32, 78.03],
    "Shimla": [31.10, 77.17], "Srinagar": [34.08, 74.80], "Thiruvananthapuram": [8.52, 76.94],
    "Kochi": [9.93, 76.27], "Coimbatore": [11.02, 76.96], "Nagpur": [21.15, 79.09],
    "Visakhapatnam": [17.69, 83.22], "Surat": [21.17, 72.83], "Vadodara": [22.31, 73.19],
    "Rajkot": [22.30, 70.80], "Agra": [27.18, 78.02], "Varanasi": [25.32, 83.01],
    "Kanpur": [26.45, 80.35], "Mysuru": [12.30, 76.65], "Jammu": [32.73, 74.87],
    "Amritsar": [31.63, 74.87], "Ludhiana": [30.90, 75.86], "Jalandhar": [31.33, 75.58],
    "Meerut": [28.98, 77.71], "Ghaziabad": [28.67, 77.44], "Raipur": [21.25, 81.63],
}

app = Flask(__name__)


def band_for(score):
    if score >= 75:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def build_phone_profile(phone):
    phone = (phone or "").strip()

    aadhaar = next((r for r in scint.load_csv("aadhaar_db.csv") if r["phone"] == phone), None)
    banking = next((r for r in scint.load_csv("banking_db.csv") if r["phone"] == phone), None)
    telecom = next((r for r in scint.load_csv("telecom_db.csv") if r["phone"] == phone), None)
    cctns = [r for r in scint.load_csv("cctns_db.csv") if r["phone"] == phone]

    score, factors = scint.score_phone_quiet(phone)
    found = any([aadhaar, banking, telecom, cctns])

    phone_intel = None
    if LIVE_AVAILABLE:
        try:
            phone_intel = live_intel.phone_intel(phone)
        except Exception as e:
            phone_intel = {"ok": False, "error": str(e)}

    return {
        "query": phone,
        "type": "phone",
        "found": found,
        "risk_score": score,
        "risk_band": band_for(score),
        "risk_factors": factors,
        "aadhaar": aadhaar,
        "banking": banking,
        "telecom": telecom,
        "cctns_cases": cctns,
        "phone_intel": phone_intel,
    }


def build_ip_profile(ip):
    ip = (ip or "").strip()
    local = next((r for r in scint.load_csv("ip_threat_db.csv") if r["ip"] == ip), None)
    score, factors = scint.score_ip_quiet(ip)

    live = {}
    live_error = None
    if LIVE_AVAILABLE:
        try:
            live, _, _ = live_intel.live_ip_score(ip)
        except Exception as e:
            live_error = str(e)
    else:
        live_error = "Live module not available"

    return {
        "query": ip, "type": "ip",
        "found": local is not None or bool(live),
        "risk_score": score, "risk_band": band_for(score),
        "risk_factors": factors,
        "local": local, "live": live, "live_error": live_error,
    }


def resolve_domain(domain):
    clean = (domain or "").strip()
    for prefix in ("https://", "http://"):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
    clean = clean.split("/")[0].split(":")[0]
    return clean, socket.gethostbyname(clean)


@app.route("/")
def index():
    return render_template("index.html", live_available=LIVE_AVAILABLE)


@app.route("/api/phone")
def api_phone():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Enter a phone number"}), 400
    return jsonify(build_phone_profile(q))


@app.route("/api/ip")
def api_ip():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Enter an IP address"}), 400
    return jsonify(build_ip_profile(q))


@app.route("/api/domain")
def api_domain():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Enter a domain"}), 400
    try:
        clean, ip = resolve_domain(q)
    except socket.gaierror:
        return jsonify({"error": f"Could not resolve '{q}'"}), 400
    profile = build_ip_profile(ip)
    profile["resolved_from"] = clean
    profile["type"] = "domain"
    return jsonify(profile)


@app.route("/api/bulk", methods=["POST"])
def api_bulk():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        text = f.read().decode("utf-8", errors="replace")
        rows = list(csv.DictReader(io.StringIO(text)))
    except Exception as e:
        return jsonify({"error": f"Could not read CSV: {e}"}), 400
    if not rows:
        return jsonify({"error": "CSV has no rows"}), 400

    cols = [c.lower() for c in rows[0].keys()]
    if "phone" in cols:
        kind = "phone"
    elif "ip" in cols:
        kind = "ip"
    elif "domain" in cols:
        kind = "domain"
    else:
        return jsonify({"error": "CSV must have a 'phone', 'ip', or 'domain' column"}), 400

    results = []
    for row in rows:
        value = (row.get(kind) or row.get(kind.capitalize()) or "").strip()
        if not value:
            continue
        if kind == "phone":
            score, factors = scint.score_phone_quiet(value)
        elif kind == "domain":
            try:
                _, ip = resolve_domain(value)
                score, factors = scint.score_ip_quiet(ip)
            except socket.gaierror:
                results.append({"value": value, "score": None, "band": "ERR",
                                "factors": ["could not resolve"]})
                continue
        else:
            score, factors = scint.score_ip_quiet(value)
        results.append({"value": value, "score": score, "band": band_for(score),
                        "factors": factors})

    scored = [r for r in results if isinstance(r["score"], int)]
    scored.sort(key=lambda r: r["score"], reverse=True)
    summary = {
        "total": len(results),
        "high": sum(1 for r in scored if r["score"] >= 75),
        "medium": sum(1 for r in scored if 40 <= r["score"] < 75),
        "low": sum(1 for r in scored if r["score"] < 40),
    }
    return jsonify({"kind": kind, "summary": summary, "results": scored})


# --- Link-analysis graph ---

def build_graph(phone):
    phone = (phone or "").strip()
    nodes, edges, seen = [], [], set()

    def add(nid, label, group, title=""):
        if nid in seen:
            return
        seen.add(nid)
        nodes.append({"id": nid, "label": label, "group": group, "title": title})

    score, _ = scint.score_phone_quiet(phone)
    add(phone, phone, "phone_high" if score >= 75 else "phone", "Phone - risk %s/100" % score)

    a = next((r for r in scint.load_csv("aadhaar_db.csv") if r["phone"] == phone), None)
    if a:
        add("name:" + a["name"], a["name"], "identity", "Aadhaar " + a["aadhaar_id"])
        edges.append({"from": phone, "to": "name:" + a["name"]})
        add("addr:" + a["address"], a["address"], "address", "Address")
        edges.append({"from": phone, "to": "addr:" + a["address"]})

    b = next((r for r in scint.load_csv("banking_db.csv") if r["phone"] == phone), None)
    if b:
        add("upi:" + b["upi_id"], b["upi_id"], "bank", b["bank"])
        edges.append({"from": phone, "to": "upi:" + b["upi_id"]})

    t = next((r for r in scint.load_csv("telecom_db.csv") if r["phone"] == phone), None)
    linked_ip = t["linked_ips"] if t else None
    if linked_ip:
        add("ip:" + linked_ip, linked_ip, "ip", "Linked IP - " + (t["carrier"] if t else ""))
        edges.append({"from": phone, "to": "ip:" + linked_ip})

    for c in [r for r in scint.load_csv("cctns_db.csv") if r["phone"] == phone]:
        add("case:" + c["case_number"], c["case_number"], "case",
            c["crime_type"] + " - " + c["status"])
        edges.append({"from": phone, "to": "case:" + c["case_number"]})

    ring = 0
    if linked_ip:
        others = [r for r in scint.load_csv("telecom_db.csv")
                  if r["linked_ips"] == linked_ip and r["phone"] != phone]
        others.sort(key=lambda r: r.get("flagged") != "True")
        for r in others[:8]:
            op = r["phone"]
            os_score, _ = scint.score_phone_quiet(op)
            add(op, op, "phone_high" if os_score >= 75 else "phone",
                "Shares IP - risk %s/100" % os_score)
            edges.append({"from": "ip:" + linked_ip, "to": op, "dashes": True})
            ring += 1

    return {"query": phone, "risk_score": score, "ring_size": ring,
            "nodes": nodes, "edges": edges}


@app.route("/api/graph")
def api_graph():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Enter a phone number"}), 400
    return jsonify(build_graph(q))


@app.route("/api/email")
def api_email():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Enter an email address"}), 400
    if not LIVE_AVAILABLE:
        return jsonify({"ok": False, "error": "Live module not available"})
    return jsonify(live_intel.check_email_breach(q))


@app.route("/api/osint-domain")
def api_osint_domain():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Enter a domain"}), 400
    if not LIVE_AVAILABLE:
        return jsonify({"ok": False, "error": "Live module not available"})
    return jsonify(live_intel.domain_intel(q))


@app.route("/api/stats")
def api_stats():
    try:
        stats = db.get_stats()
    except Exception as e:
        return jsonify({"error": f"Could not build stats: {e}"}), 500
    points = []
    for loc in stats["locations"]:
        city = (loc["label"] or "").split(",")[0].strip()
        if city in CITY_COORDS:
            points.append({"city": city, "count": loc["value"],
                           "lat": CITY_COORDS[city][0], "lng": CITY_COORDS[city][1]})
    stats["map_points"] = points
    return jsonify(stats)


@app.route("/api/mapdata")
def api_mapdata():
    """Rich geographic data for the operational map."""
    telecom = scint.load_csv("telecom_db.csv")
    cctns = scint.load_csv("cctns_db.csv")

    city_data = {}
    for t in telecom:
        loc = (t.get("last_location") or "").split(",")[0].strip()
        if loc not in CITY_COORDS:
            continue
        if loc not in city_data:
            city_data[loc] = {"city": loc, "lat": CITY_COORDS[loc][0],
                              "lng": CITY_COORDS[loc][1], "phones": 0,
                              "flagged": 0, "high_risk": 0, "cases": 0,
                              "crime_types": {}, "carriers": {}}
        city_data[loc]["phones"] += 1
        if t.get("flagged") == "True":
            city_data[loc]["flagged"] += 1
        score, _ = scint.score_phone_quiet(t["phone"])
        if score >= 75:
            city_data[loc]["high_risk"] += 1
        carrier = t.get("carrier", "Unknown")
        city_data[loc]["carriers"][carrier] = city_data[loc]["carriers"].get(carrier, 0) + 1

    for c in cctns:
        phone = c.get("phone", "")
        tel = next((r for r in telecom if r["phone"] == phone), None)
        if tel:
            loc = (tel.get("last_location") or "").split(",")[0].strip()
            if loc in city_data:
                city_data[loc]["cases"] += 1
                ct = c.get("crime_type", "Unknown")
                city_data[loc]["crime_types"][ct] = city_data[loc]["crime_types"].get(ct, 0) + 1

    for cd in city_data.values():
        cd["top_crimes"] = sorted(cd["crime_types"].items(), key=lambda x: -x[1])[:3]
        cd["top_carrier"] = max(cd["carriers"].items(), key=lambda x: x[1])[0] if cd["carriers"] else "—"
        del cd["crime_types"], cd["carriers"]

    return jsonify({"cities": list(city_data.values())})


@app.route("/report/phone/<phone>.pdf")
def report_phone_pdf(phone):
    if not PDF_AVAILABLE:
        return "PDF generator not available (pip install reportlab)", 500
    profile = build_phone_profile(phone)
    pdf = report_pdf.build_phone_pdf(profile)
    return send_file(pdf, mimetype="application/pdf", as_attachment=True,
                     download_name=f"SCINT_{phone}.pdf")


# ── Palantir-style intelligence endpoints ──────────────────────────────────


@app.route("/api/search")
def api_search():
    """Unified search — auto-detects phone / IP / email / domain."""
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Enter a query"}), 400

    if q.replace(".", "").replace(":", "").isdigit() and (q.count(".") == 3 or ":" in q):
        result = build_ip_profile(q)
    elif q.isdigit() and len(q) >= 7:
        result = build_phone_profile(q)
    elif "@" in q:
        if not LIVE_AVAILABLE:
            return jsonify({"ok": False, "error": "Live module not available"})
        result = live_intel.check_email_breach(q)
        result["type"] = "email"
        result["query"] = q
        result["risk_score"] = 0
        result["risk_band"] = "LOW"
    else:
        try:
            clean, ip = resolve_domain(q)
        except socket.gaierror:
            return jsonify({"error": f"Could not resolve '{q}'"}), 400
        result = build_ip_profile(ip)
        result["resolved_from"] = clean
        result["type"] = "domain"

    db.log_activity(
        result.get("type", "unknown"), q,
        result.get("risk_score", 0), result.get("risk_band", "LOW"))
    db.update_watchlist_score(q, result.get("risk_score", 0))
    return jsonify(result)


@app.route("/api/watchlist", methods=["GET"])
def api_watchlist_get():
    return jsonify(db.get_watchlist())


@app.route("/api/watchlist", methods=["POST"])
def api_watchlist_add():
    data = request.get_json(force=True)
    value = (data.get("value") or "").strip()
    if not value:
        return jsonify({"error": "value required"}), 400
    wid = db.add_to_watchlist(
        data.get("type", "phone"), value,
        data.get("priority", "medium"), data.get("notes", ""))
    if wid is None:
        return jsonify({"error": "Already on watchlist"}), 409
    return jsonify({"id": wid})


@app.route("/api/watchlist", methods=["DELETE"])
def api_watchlist_remove():
    data = request.get_json(force=True)
    db.remove_from_watchlist(data.get("id"))
    return jsonify({"ok": True})


@app.route("/api/activity")
def api_activity():
    limit = request.args.get("limit", 50, type=int)
    return jsonify(db.get_recent_activity(limit))


@app.route("/api/threat-level")
def api_threat_level():
    return jsonify(db.get_threat_level())


# ── Golden Hour ──────────────────────────────────────────────────────────────

@app.route("/api/golden-hour", methods=["GET"])
def api_golden_hour_list():
    return jsonify(db.get_active_golden_hours())


@app.route("/api/golden-hour", methods=["POST"])
def api_golden_hour_start():
    data = request.get_json(force=True)
    if not data.get("victim_name") or not data.get("victim_phone"):
        return jsonify({"error": "Victim name and phone required"}), 400
    gid = db.start_golden_hour(
        data["victim_name"], data["victim_phone"],
        data.get("suspect_phone", ""), data.get("suspect_upi", ""),
        data.get("suspect_bank", ""), data.get("suspect_account", ""),
        data.get("scam_type", "UPI Fraud"),
        float(data.get("amount_lost", 0) or 0),
        data.get("description", ""))
    # Auto-scan suspect identifiers
    scan = {}
    sp = (data.get("suspect_phone") or "").strip()
    if sp:
        s, f = scint.score_phone_quiet(sp)
        scan["phone"] = {"value": sp, "score": s, "factors": f}
    return jsonify({"id": gid, "scan": scan})


@app.route("/api/golden-hour/<int:gid>")
def api_golden_hour_get(gid):
    row = db.get_golden_hour(gid)
    if not row:
        return jsonify({"error": "Not found"}), 404
    import json
    row["steps"] = json.loads(row["steps"] or "{}")
    row["scan_results"] = json.loads(row["scan_results"] or "{}")
    return jsonify(row)


@app.route("/api/golden-hour/<int:gid>/step", methods=["POST"])
def api_golden_hour_step(gid):
    data = request.get_json(force=True)
    db.update_golden_step(gid, data.get("step"), data.get("done", True))
    return jsonify({"ok": True})


@app.route("/api/golden-hour/<int:gid>/scan", methods=["POST"])
def api_golden_hour_scan(gid):
    row = db.get_golden_hour(gid)
    if not row:
        return jsonify({"error": "Not found"}), 404
    scan = {}
    sp = (row["suspect_phone"] or "").strip()
    if sp:
        s, f = scint.score_phone_quiet(sp)
        profile = build_phone_profile(sp)
        scan["phone"] = {"value": sp, "score": s, "factors": f,
                         "aadhaar": profile.get("aadhaar"),
                         "banking": profile.get("banking"),
                         "cctns": profile.get("cctns_cases")}
    su = (row["suspect_upi"] or "").strip()
    if su:
        bank_rows = scint.load_csv("banking_db.csv")
        match = next((r for r in bank_rows if r.get("upi_id") == su), None)
        scan["upi"] = {"value": su, "found": match is not None, "details": match}
    import json
    db.update_golden_scan(gid, scan)
    db.update_golden_step(gid, "scan_suspect", True)
    return jsonify(scan)


@app.route("/api/golden-hour/<int:gid>/close", methods=["POST"])
def api_golden_hour_close(gid):
    db.close_golden_hour(gid)
    return jsonify({"ok": True})


@app.route("/api/golden-hour/<int:gid>/notice")
def api_golden_hour_notice(gid):
    row = db.get_golden_hour(gid)
    if not row:
        return jsonify({"error": "Not found"}), 404
    import json
    scan = json.loads(row["scan_results"] or "{}")
    notice = generate_sec94_notice(row, scan)
    return jsonify({"notice": notice, "case": row})


def generate_sec94_notice(case, scan):
    """Generate a Section 94 BNSS freeze notice text."""
    phone_info = scan.get("phone", {})
    return {
        "type": "Section 94 BNSS — Requisition for Information",
        "to": f"The Nodal Officer, {case.get('suspect_bank') or 'Concerned Bank'}",
        "subject": f"Urgent: Freeze of account linked to cyber fraud — "
                   f"Phone: {case.get('suspect_phone', 'N/A')} / "
                   f"UPI: {case.get('suspect_upi', 'N/A')}",
        "body": (
            f"Sir/Madam,\n\n"
            f"Under Section 94 of Bharatiya Nagarik Suraksha Sanhita (BNSS) 2023, "
            f"you are hereby directed to immediately freeze the following account(s) "
            f"and furnish the details to the undersigned:\n\n"
            f"SUSPECT DETAILS:\n"
            f"  Phone Number  : {case.get('suspect_phone', 'N/A')}\n"
            f"  UPI ID        : {case.get('suspect_upi', 'N/A')}\n"
            f"  Bank          : {case.get('suspect_bank', 'N/A')}\n"
            f"  Account No    : {case.get('suspect_account', 'N/A')}\n\n"
            f"VICTIM DETAILS:\n"
            f"  Name          : {case.get('victim_name', 'N/A')}\n"
            f"  Phone         : {case.get('victim_phone', 'N/A')}\n"
            f"  Amount Lost   : ₹{case.get('amount_lost', 0):,.2f}\n"
            f"  Scam Type     : {case.get('scam_type', 'N/A')}\n\n"
            f"INTELLIGENCE ASSESSMENT:\n"
            f"  SCINT Risk Score : {phone_info.get('score', 'N/A')}/100\n"
            f"  Risk Factors     : {', '.join(phone_info.get('factors', ['None']))}\n"
            f"  CCTNS Cases      : {len(phone_info.get('cctns', []))}\n\n"
            f"REQUIRED ACTIONS:\n"
            f"  1. Immediately freeze all accounts linked to the above identifiers\n"
            f"  2. Provide KYC details of account holder\n"
            f"  3. Provide last 6 months transaction statement\n"
            f"  4. Provide IP logs of last 30 days\n"
            f"  5. Preserve all related CCTV footage\n\n"
            f"This matter is URGENT as the complaint is within the Golden Hour "
            f"window. Delay may result in loss of recoverable funds.\n\n"
            f"Kindly treat this as MOST IMMEDIATE.\n\n"
            f"Yours faithfully,\n"
            f"[Investigating Officer Name]\n"
            f"[Designation]\n"
            f"Cyber Crime Police Station, Gurugram\n"
            f"Generated by: SCINT Intelligence Platform v2.0"
        ),
        "section_91": (
            f"Section 91 BNSS — Summons to Produce Document\n\n"
            f"To: {case.get('suspect_bank') or 'Telecom Service Provider'}\n\n"
            f"You are directed to produce the following documents:\n"
            f"  1. CDR/IPDR of {case.get('suspect_phone', 'N/A')} for last 90 days\n"
            f"  2. Tower location dumps for relevant dates\n"
            f"  3. KYC documents used for SIM activation\n"
            f"  4. IMEI numbers associated with the SIM\n\n"
            f"Non-compliance is punishable under Section 229 BNS.\n"
        ),
    }


# ── Complaint Clustering ─────────────────────────────────────────────────────

@app.route("/api/complaints", methods=["GET"])
def api_complaints_list():
    return jsonify(db.get_complaints())


@app.route("/api/complaints", methods=["POST"])
def api_complaints_add():
    data = request.get_json(force=True)
    if not data.get("victim_name"):
        return jsonify({"error": "Victim name required"}), 400
    cid = db.add_complaint(
        data.get("victim_name", ""), data.get("victim_phone", ""),
        data.get("suspect_indicators", ""), data.get("scam_type", ""),
        float(data.get("amount", 0) or 0),
        data.get("description", ""), data.get("state", ""))
    return jsonify({"id": cid})


@app.route("/api/complaints/cluster", methods=["POST"])
def api_complaints_cluster():
    import re, json
    complaints = db.get_complaints(500)
    if len(complaints) < 2:
        return jsonify({"error": "Need at least 2 complaints to cluster"}), 400

    def extract_iocs(text):
        text = str(text)
        phones = set(re.findall(r'\b[6-9]\d{9}\b', text))
        upis = set(re.findall(r'\b[\w.]+@[\w]+\b', text))
        ips = set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text))
        accounts = set(re.findall(r'\b\d{9,18}\b', text))
        return phones | upis | ips | accounts

    complaint_iocs = {}
    for c in complaints:
        blob = f"{c.get('suspect_indicators','')} {c.get('description','')} {c.get('victim_phone','')}"
        complaint_iocs[c["id"]] = extract_iocs(blob)

    # Union-find clustering
    parent = {c["id"]: c["id"] for c in complaints}
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        parent[find(a)] = find(b)

    ids = list(complaint_iocs.keys())
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            if complaint_iocs[ids[i]] & complaint_iocs[ids[j]]:
                union(ids[i], ids[j])

    clusters_map = {}
    for cid in ids:
        root = find(cid)
        clusters_map.setdefault(root, []).append(cid)

    multi_clusters = {k: v for k, v in clusters_map.items() if len(v) > 1}
    singles = [v[0] for v in clusters_map.values() if len(v) == 1]

    cluster_list = list(multi_clusters.values())
    db.update_cluster_ids(cluster_list)

    result = []
    for idx, cluster_ids in enumerate(cluster_list, 1):
        members = [c for c in complaints if c["id"] in cluster_ids]
        shared = set()
        for cid in cluster_ids:
            shared |= complaint_iocs.get(cid, set())
        total_amount = sum(float(m.get("amount", 0) or 0) for m in members)
        states = list(set(m.get("state", "") for m in members if m.get("state")))
        result.append({
            "cluster_id": idx,
            "count": len(members),
            "shared_iocs": list(shared)[:20],
            "total_amount": total_amount,
            "states": states,
            "scam_types": list(set(m.get("scam_type", "") for m in members if m.get("scam_type"))),
            "complaints": members,
        })

    result.sort(key=lambda c: c["count"], reverse=True)
    return jsonify({
        "total_complaints": len(complaints),
        "clusters_found": len(result),
        "unclustered": len(singles),
        "clusters": result,
    })


# ── Digital Arrest Detector ──────────────────────────────────────────────────

DIGITAL_ARREST_PATTERNS = {
    "authority_impersonation": {
        "keywords": ["cbi", "police", "customs", "narcotics", "ncrb", "crime branch",
                     "enforcement directorate", "ed officer", "income tax", "nia",
                     "trai", "rbi", "reserve bank", "telecom authority", "cyber cell",
                     "supreme court", "high court", "judge", "magistrate"],
        "weight": 25, "label": "Authority Impersonation"
    },
    "arrest_threat": {
        "keywords": ["arrest warrant", "non-bailable", "arrest", "jail", "fir registered",
                     "case filed", "criminal case", "money laundering", "hawala",
                     "drug trafficking", "terrorism", "national security"],
        "weight": 25, "label": "Arrest/Legal Threat"
    },
    "video_pressure": {
        "keywords": ["video call", "skype", "whatsapp video", "keep camera on",
                     "do not disconnect", "stay on call", "do not hang up",
                     "digital arrest", "virtual arrest", "online arrest"],
        "weight": 20, "label": "Video Call Coercion"
    },
    "financial_demand": {
        "keywords": ["transfer money", "safe account", "rbi account", "verification account",
                     "refundable deposit", "security deposit", "send money", "upi",
                     "bank transfer", "neft", "rtgs", "imps", "google pay", "phonepe",
                     "paytm", "crypto", "bitcoin"],
        "weight": 20, "label": "Financial Demand"
    },
    "isolation_tactics": {
        "keywords": ["do not tell anyone", "confidential", "secret operation",
                     "don't inform family", "tell no one", "under surveillance",
                     "phone is tapped", "being monitored", "classified"],
        "weight": 15, "label": "Isolation Tactics"
    },
    "identity_claim": {
        "keywords": ["aadhaar linked", "your phone number", "your name found",
                     "parcel in your name", "fedex", "courier", "drugs found",
                     "passport", "sim card used", "bank account misused"],
        "weight": 15, "label": "False Identity Link"
    },
    "urgency": {
        "keywords": ["immediately", "right now", "within one hour", "urgent",
                     "time is running out", "last chance", "today only",
                     "before we proceed", "cooperate or"],
        "weight": 10, "label": "Artificial Urgency"
    },
}


@app.route("/api/detect-digital-arrest", methods=["POST"])
def api_detect_digital_arrest():
    data = request.get_json(force=True)
    text = (data.get("text") or "").strip()
    if not text or len(text) < 10:
        return jsonify({"error": "Provide a description of the call/interaction"}), 400

    text_lower = text.lower()
    total_score = 0
    flags = []
    matched_keywords = []

    for cat_key, cat in DIGITAL_ARREST_PATTERNS.items():
        hits = [kw for kw in cat["keywords"] if kw in text_lower]
        if hits:
            score_contrib = min(cat["weight"], cat["weight"] * len(hits) // 2 + cat["weight"] // 2)
            total_score += score_contrib
            flags.append({
                "category": cat["label"],
                "score": score_contrib,
                "max": cat["weight"],
                "matched": hits[:5],
            })
            matched_keywords.extend(hits)

    total_score = min(total_score, 100)

    if total_score >= 80:
        verdict = "CONFIRMED DIGITAL ARREST SCAM"
        severity = "CRITICAL"
        action = "STOP ALL COMMUNICATION. DO NOT TRANSFER ANY MONEY. Contact local police immediately."
    elif total_score >= 50:
        verdict = "HIGHLY LIKELY DIGITAL ARREST SCAM"
        severity = "HIGH"
        action = "Strongly suspected scam. Do not send money. Verify caller identity through official channels."
    elif total_score >= 25:
        verdict = "POSSIBLE SCAM — VERIFY"
        severity = "MEDIUM"
        action = "Some red flags detected. Independently verify the caller's identity through official websites."
    else:
        verdict = "LOW RISK"
        severity = "LOW"
        action = "Few scam indicators detected, but remain cautious with unsolicited calls."

    import re
    phones = list(set(re.findall(r'\b[6-9]\d{9}\b', text)))
    upis = list(set(re.findall(r'\b[\w.]+@[a-z]{2,}\b', text_lower)))
    accounts = list(set(re.findall(r'\b\d{9,18}\b', text)))

    return jsonify({
        "score": total_score,
        "verdict": verdict,
        "severity": severity,
        "action": action,
        "flags": flags,
        "total_flags": len(flags),
        "matched_keywords": list(set(matched_keywords)),
        "extracted": {"phones": phones, "upis": upis, "accounts": accounts},
        "advisory": [
            "No legitimate law enforcement agency conducts 'digital arrest' via video call",
            "CBI/Police/ED will never ask you to transfer money to any account",
            "Real police will summon you to a police station, not demand money online",
            "TRAI/RBI will never call you to threaten SIM deactivation or account freeze",
            "If in doubt, call 1930 (National Cyber Crime Helpline) immediately",
        ],
    })


# ── Scam SMS Classifier ─────────────────────────────────────────────────────

SMS_PATTERNS = [
    {"type": "KYC Fraud", "keywords": ["kyc", "kyc update", "kyc expire", "pan card", "pan link",
        "aadhaar update", "bank account block", "account suspend", "verify identity"],
     "severity": "HIGH"},
    {"type": "Lottery / Prize Scam", "keywords": ["lottery", "winner", "prize", "congratulations",
        "won", "lucky draw", "selected", "claim your", "reward"],
     "severity": "HIGH"},
    {"type": "Job Scam", "keywords": ["work from home", "earn daily", "part time job",
        "earn money", "income opportunity", "hiring", "₹5000", "₹10000", "per day",
        "telegram join", "whatsapp group"],
     "severity": "MEDIUM"},
    {"type": "Loan / Credit Scam", "keywords": ["instant loan", "pre-approved loan",
        "credit limit", "loan approved", "low interest", "no documents required", "apply now"],
     "severity": "MEDIUM"},
    {"type": "Phishing", "keywords": ["click here", "click below", "verify now", "update now",
        "login here", "confirm your", "bit.ly", "tinyurl", "short.url"],
     "severity": "HIGH"},
    {"type": "Investment Scam", "keywords": ["guaranteed return", "double your money",
        "invest now", "stock tip", "crypto", "trading profit", "100% profit"],
     "severity": "HIGH"},
    {"type": "Sextortion", "keywords": ["your video", "your photo", "morphed", "viral",
        "leaked", "private", "send money or"],
     "severity": "CRITICAL"},
    {"type": "OTP / Card Fraud", "keywords": ["otp", "cvv", "card number", "expiry date",
        "share otp", "verify otp", "credit card", "debit card"],
     "severity": "CRITICAL"},
    {"type": "Delivery Scam", "keywords": ["package", "delivery failed", "reschedule delivery",
        "tracking", "customs fee", "courier", "india post"],
     "severity": "MEDIUM"},
]


@app.route("/api/classify-sms", methods=["POST"])
def api_classify_sms():
    import re
    data = request.get_json(force=True)
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Provide SMS text"}), 400

    text_lower = text.lower()
    matches = []
    for pat in SMS_PATTERNS:
        hits = [kw for kw in pat["keywords"] if kw in text_lower]
        if hits:
            matches.append({
                "type": pat["type"],
                "severity": pat["severity"],
                "matched": hits,
                "confidence": min(100, len(hits) * 25 + 25),
            })

    matches.sort(key=lambda m: m["confidence"], reverse=True)
    primary = matches[0] if matches else None

    # Extract IOCs
    phones = list(set(re.findall(r'\b[6-9]\d{9}\b', text)))
    urls = list(set(re.findall(r'https?://[^\s<>"\']+', text, re.I)))
    short_urls = list(set(re.findall(r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|rb\.gy|cutt\.ly)/\S+', text, re.I)))
    upis = list(set(re.findall(r'\b[\w.]+@(?:ybl|upi|oksbi|okaxis|okicici|paytm|apl|ibl|sbi|axl)\b', text_lower)))
    accounts = list(set(re.findall(r'\b\d{10,18}\b', text)))
    emails = list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)))

    total_iocs = len(phones) + len(urls) + len(short_urls) + len(upis) + len(accounts) + len(emails)

    risk_score = 0
    if primary:
        base = {"CRITICAL": 85, "HIGH": 65, "MEDIUM": 40}.get(primary["severity"], 20)
        risk_score = min(100, base + total_iocs * 5)

    return jsonify({
        "classification": primary["type"] if primary else "Unknown / Legitimate",
        "severity": primary["severity"] if primary else "LOW",
        "risk_score": risk_score,
        "all_matches": matches,
        "iocs": {
            "phones": phones, "urls": urls + short_urls, "upis": upis,
            "accounts": accounts, "emails": emails, "total": total_iocs,
        },
        "is_scam": risk_score >= 40,
    })


# ── Financial Flow Visualizer ────────────────────────────────────────────────

@app.route("/api/financial-flow", methods=["POST"])
def api_financial_flow():
    data = request.get_json(force=True)
    transactions = data.get("transactions", [])
    if not transactions or len(transactions) < 1:
        return jsonify({"error": "Provide at least one transaction"}), 400

    nodes_set = set()
    edges = []
    node_inflow = {}
    node_outflow = {}
    node_txn_count = {}

    for txn in transactions:
        sender = (txn.get("from") or txn.get("sender") or "").strip()
        receiver = (txn.get("to") or txn.get("receiver") or "").strip()
        amount = float(txn.get("amount") or 0)
        if not sender or not receiver:
            continue

        nodes_set.add(sender)
        nodes_set.add(receiver)
        edges.append({"from": sender, "to": receiver, "amount": amount,
                       "label": "₹{:,.0f}".format(amount)})

        node_outflow[sender] = node_outflow.get(sender, 0) + amount
        node_inflow[receiver] = node_inflow.get(receiver, 0) + amount
        node_txn_count[sender] = node_txn_count.get(sender, 0) + 1
        node_txn_count[receiver] = node_txn_count.get(receiver, 0) + 1

    # Classify nodes
    nodes = []
    mule_suspects = []
    for n in nodes_set:
        inflow = node_inflow.get(n, 0)
        outflow = node_outflow.get(n, 0)
        txn_count = node_txn_count.get(n, 0)
        net = inflow - outflow

        if inflow > 0 and outflow > 0 and outflow >= inflow * 0.7:
            role = "mule"
            mule_suspects.append({
                "account": n, "inflow": inflow, "outflow": outflow,
                "pass_through_pct": round(outflow / inflow * 100, 1) if inflow else 0,
            })
        elif outflow > 0 and inflow == 0:
            role = "source"
        elif inflow > 0 and outflow == 0:
            role = "sink"
        else:
            role = "intermediate"

        nodes.append({
            "id": n, "label": n, "role": role,
            "inflow": inflow, "outflow": outflow, "net": net,
            "txn_count": txn_count,
        })

    total_flow = sum(e["amount"] for e in edges)

    return jsonify({
        "nodes": nodes,
        "edges": edges,
        "total_flow": total_flow,
        "total_accounts": len(nodes),
        "total_transactions": len(edges),
        "mule_suspects": sorted(mule_suspects, key=lambda m: -m["pass_through_pct"]),
    })


# ── Investigation Playbook ───────────────────────────────────────────────────

PLAYBOOKS = {
    "UPI Fraud": {
        "priority": "HIGH",
        "golden_hour": True,
        "steps": [
            {"step": "Log complaint on NCRP (cybercrime.gov.in) immediately", "agency": "NCRP", "time": "0-15 min"},
            {"step": "Call 1930 — National Cyber Crime Helpline for instant bank freeze", "agency": "I4C", "time": "0-30 min"},
            {"step": "Contact beneficiary bank's fraud desk — request Sec 94 freeze", "agency": "Bank", "time": "0-1 hr"},
            {"step": "File FIR at local Cyber Crime PS with transaction screenshots", "agency": "Police", "time": "0-2 hr"},
            {"step": "Request CDR/IPDR of suspect phone via Sec 91 BNSS", "agency": "Telecom", "time": "24 hr"},
            {"step": "Obtain KYC of suspect account from bank", "agency": "Bank", "time": "48 hr"},
            {"step": "Check CCTNS for prior cases linked to suspect identifiers", "agency": "CCTNS", "time": "48 hr"},
            {"step": "Trace money trail to final cash-out point (ATM/wallet)", "agency": "Bank", "time": "72 hr"},
            {"step": "Obtain ATM CCTV footage near cash-out location", "agency": "Bank/Police", "time": "5 days"},
            {"step": "Cross-reference IMEI from CDR for device fingerprinting", "agency": "Police", "time": "7 days"},
        ],
    },
    "Digital Arrest": {
        "priority": "CRITICAL",
        "golden_hour": False,
        "steps": [
            {"step": "Reassure victim — no government agency conducts 'digital arrest'", "agency": "Police", "time": "Immediate"},
            {"step": "Log complaint on NCRP and call 1930", "agency": "NCRP/I4C", "time": "0-30 min"},
            {"step": "Collect call recordings, screenshots, chat logs from victim", "agency": "Police", "time": "1 hr"},
            {"step": "Trace suspect phone via CDR/IPDR (Sec 91 BNSS)", "agency": "Telecom", "time": "24 hr"},
            {"step": "If video call used — request app logs (WhatsApp/Skype/Zoom)", "agency": "Platform", "time": "MLAT"},
            {"step": "Check if money was transferred — initiate freeze immediately", "agency": "Bank", "time": "1 hr"},
            {"step": "Identify call center location via tower dumps", "agency": "Telecom", "time": "72 hr"},
            {"step": "Check for syndicate patterns — similar MO in CCTNS", "agency": "CCTNS", "time": "48 hr"},
            {"step": "Coordinate with other state units if inter-state operation", "agency": "I4C", "time": "7 days"},
            {"step": "Victim counseling and awareness campaign", "agency": "Police", "time": "Ongoing"},
        ],
    },
    "Investment Scam": {
        "priority": "HIGH",
        "golden_hour": True,
        "steps": [
            {"step": "Document all investment platform screenshots and communications", "agency": "Police", "time": "Immediate"},
            {"step": "Log NCRP complaint with full transaction history", "agency": "NCRP", "time": "0-1 hr"},
            {"step": "Freeze suspect bank accounts via Sec 94 BNSS", "agency": "Bank", "time": "0-2 hr"},
            {"step": "Identify and block fake trading app/website", "agency": "CERT-In", "time": "24 hr"},
            {"step": "Trace domain registration and hosting details", "agency": "Police", "time": "48 hr"},
            {"step": "Check for crypto wallet addresses — blockchain analysis", "agency": "Police/I4C", "time": "72 hr"},
            {"step": "Identify recruitment chain (Telegram groups, social media ads)", "agency": "Police", "time": "7 days"},
            {"step": "Coordinate with RBI if unlicensed financial platform", "agency": "RBI", "time": "7 days"},
        ],
    },
    "Sextortion": {
        "priority": "CRITICAL",
        "golden_hour": False,
        "steps": [
            {"step": "Reassure victim — do NOT pay the extortionist", "agency": "Police", "time": "Immediate"},
            {"step": "Preserve all evidence — screenshots, messages, payment receipts", "agency": "Police", "time": "Immediate"},
            {"step": "Report account on the social media platform for removal", "agency": "Platform", "time": "0-1 hr"},
            {"step": "File complaint on NCRP (cybercrime.gov.in)", "agency": "NCRP", "time": "0-1 hr"},
            {"step": "Request platform for IP logs and account details (Sec 91)", "agency": "Platform", "time": "MLAT"},
            {"step": "Trace payment channels if money was sent", "agency": "Bank", "time": "24 hr"},
            {"step": "CDR analysis of suspect phone for location/pattern", "agency": "Telecom", "time": "72 hr"},
            {"step": "Provide victim counseling and support services", "agency": "Police", "time": "Ongoing"},
        ],
    },
    "Job Scam": {
        "priority": "MEDIUM",
        "golden_hour": True,
        "steps": [
            {"step": "Collect all communication — job offer, task screenshots, payment receipts", "agency": "Police", "time": "Immediate"},
            {"step": "File NCRP complaint with Telegram/WhatsApp group details", "agency": "NCRP", "time": "0-1 hr"},
            {"step": "Freeze suspect accounts if recent payment made", "agency": "Bank", "time": "0-2 hr"},
            {"step": "Identify Telegram group admin — request platform data", "agency": "Platform", "time": "MLAT"},
            {"step": "Trace UPI IDs and bank accounts through KYC", "agency": "Bank", "time": "48 hr"},
            {"step": "Check for mule account patterns across multiple complaints", "agency": "Police", "time": "72 hr"},
            {"step": "Block identified fake job websites via CERT-In", "agency": "CERT-In", "time": "7 days"},
        ],
    },
    "KYC Fraud": {
        "priority": "HIGH",
        "golden_hour": True,
        "steps": [
            {"step": "Call 1930 and log NCRP complaint immediately", "agency": "I4C/NCRP", "time": "0-30 min"},
            {"step": "Contact victim's bank — freeze account if unauthorized access", "agency": "Bank", "time": "0-1 hr"},
            {"step": "Collect phishing link/SMS/email as evidence", "agency": "Police", "time": "1 hr"},
            {"step": "Trace suspect phone from phishing SMS (CDR)", "agency": "Telecom", "time": "24 hr"},
            {"step": "Identify phishing domain — WHOIS + hosting details", "agency": "CERT-In", "time": "48 hr"},
            {"step": "Request takedown of phishing domain", "agency": "CERT-In", "time": "72 hr"},
            {"step": "Trace money if unauthorized transactions occurred", "agency": "Bank", "time": "72 hr"},
        ],
    },
}


@app.route("/api/playbook", methods=["POST"])
def api_playbook():
    data = request.get_json(force=True)
    scam_type = (data.get("scam_type") or "").strip()
    if not scam_type:
        return jsonify({"error": "Select a scam type"}), 400
    playbook = PLAYBOOKS.get(scam_type)
    if not playbook:
        return jsonify({"error": f"No playbook for '{scam_type}'",
                        "available": list(PLAYBOOKS.keys())}), 404
    return jsonify({"scam_type": scam_type, **playbook})


@app.route("/api/playbooks")
def api_playbooks_list():
    return jsonify({k: {"priority": v["priority"], "golden_hour": v["golden_hour"],
                        "step_count": len(v["steps"])} for k, v in PLAYBOOKS.items()})


# ── Victim Impact Calculator ─────────────────────────────────────────────────

@app.route("/api/victim-impact", methods=["POST"])
def api_victim_impact():
    complaints = db.get_complaints(500)
    if not complaints:
        return jsonify({"error": "No complaints in database"}), 400

    total_amount = sum(float(c.get("amount", 0) or 0) for c in complaints)
    by_type = {}
    by_state = {}
    for c in complaints:
        t = c.get("scam_type") or "Unknown"
        s = c.get("state") or "Unknown"
        amt = float(c.get("amount", 0) or 0)
        by_type.setdefault(t, {"count": 0, "amount": 0})
        by_type[t]["count"] += 1
        by_type[t]["amount"] += amt
        by_state.setdefault(s, {"count": 0, "amount": 0})
        by_state[s]["count"] += 1
        by_state[s]["amount"] += amt

    avg_loss = total_amount / len(complaints) if complaints else 0
    max_loss = max((float(c.get("amount", 0) or 0) for c in complaints), default=0)

    return jsonify({
        "total_victims": len(complaints),
        "total_amount_lost": total_amount,
        "average_loss": round(avg_loss, 2),
        "max_single_loss": max_loss,
        "by_scam_type": [{"type": k, **v} for k, v in sorted(by_type.items(), key=lambda x: -x[1]["amount"])],
        "by_state": [{"state": k, **v} for k, v in sorted(by_state.items(), key=lambda x: -x[1]["amount"])],
    })


# ── Suspect Dossier PDF ─────────────────────────────────────────────────────

@app.route("/api/dossier", methods=["POST"])
def api_dossier():
    if not PDF_AVAILABLE:
        return jsonify({"error": "PDF generator not available"}), 500
    data = request.get_json(force=True)
    phone = (data.get("phone") or "").strip()
    name = (data.get("suspect_name") or "Unknown").strip()
    case_id = (data.get("case_id") or "SCINT-" + datetime.now().strftime("%Y%m%d%H%M")).strip()

    if not phone:
        return jsonify({"error": "Provide a suspect phone number"}), 400

    profile = build_phone_profile(phone)

    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors as rlc
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=16*mm,
                            title=f"SCINT Dossier — {name}")
    base = getSampleStyleSheet()
    CYAN = rlc.HexColor("#0e7490")
    RED = rlc.HexColor("#b91c1c")
    GREY = rlc.HexColor("#64748b")
    s = {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=22, textColor=CYAN, spaceAfter=2),
        "sub": ParagraphStyle("sub", parent=base["Normal"], fontSize=9, textColor=GREY),
        "h": ParagraphStyle("h", parent=base["Heading2"], fontSize=13, textColor=CYAN, spaceBefore=12, spaceAfter=4),
        "k": ParagraphStyle("k", parent=base["Normal"], fontSize=9.5, textColor=GREY),
        "v": ParagraphStyle("v", parent=base["Normal"], fontSize=9.5),
        "body": ParagraphStyle("body", parent=base["Normal"], fontSize=10, spaceAfter=6, leading=14),
        "red": ParagraphStyle("red", parent=base["Normal"], fontSize=10, textColor=RED, leftIndent=6),
        "disc": ParagraphStyle("disc", parent=base["Normal"], fontSize=8, textColor=GREY),
    }

    def kv_tbl(rows):
        data = [[Paragraph(f"<b>{k}</b>", s["k"]), Paragraph(str(v or "N/A"), s["v"])] for k, v in rows]
        t = Table(data, colWidths=[55*mm, 110*mm])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, rlc.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    score = profile.get("risk_score", 0)
    band = profile.get("risk_band", "LOW")
    band_c = {75: RED, 40: rlc.HexColor("#b45309")}.get(
        next((t for t in [75, 40] if score >= t), 0), rlc.HexColor("#15803d"))
    e = []

    # Page 1: Cover
    e.append(Spacer(1, 40*mm))
    e.append(Paragraph("CLASSIFIED — SUSPECT INTELLIGENCE DOSSIER", s["title"]))
    e.append(HRFlowable(width="100%", thickness=2, color=CYAN))
    e.append(Spacer(1, 10))
    e.append(kv_tbl([
        ("Dossier ID", case_id),
        ("Subject Name", name),
        ("Primary Phone", phone),
        ("Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S IST")),
        ("Risk Assessment", f"{score}/100 — {band}"),
        ("Classification", "RESTRICTED — Law Enforcement Use Only"),
        ("Generating Unit", "Cyber Crime PS, Gurugram — via SCINT v2.0"),
    ]))
    e.append(Spacer(1, 20))
    e.append(Paragraph("GPCSSI 2026 &middot; Gurugram Police Cyber Security Internship", s["sub"]))
    e.append(PageBreak())

    # Page 2: Risk Assessment + Factors
    e.append(Paragraph("SECTION 1 — RISK ASSESSMENT", s["h"]))
    risk_tbl = Table([[
        Paragraph("<b>COMPOSITE RISK SCORE</b>", s["k"]),
        Paragraph(f"<font color='{band_c.hexval()}'><b>{score}/100 &nbsp; {band}</b></font>",
                  ParagraphStyle("rs", parent=base["Normal"], fontSize=16)),
    ]], colWidths=[55*mm, 110*mm])
    e.append(risk_tbl)
    e.append(Spacer(1, 8))
    factors = profile.get("risk_factors", [])
    if factors:
        e.append(Paragraph("Risk Factors Identified:", s["body"]))
        for f in factors:
            e.append(Paragraph(f"&#8594; {f}", s["red"]))
    else:
        e.append(Paragraph("No risk factors detected in current scan.", s["body"]))

    # Aadhaar
    e.append(Paragraph("SECTION 2 — IDENTITY INTELLIGENCE (Aadhaar)", s["h"]))
    a = profile.get("aadhaar")
    if a:
        e.append(kv_tbl([
            ("Full Name", a.get("name")), ("Aadhaar ID", a.get("aadhaar_id")),
            ("Date of Birth", a.get("dob")), ("Address", a.get("address")),
            ("Flagged Identity", "YES — Known fraud" if a.get("flagged") == "True" else "No"),
        ]))
    else:
        e.append(Paragraph("No Aadhaar record linked to this phone number.", s["body"]))

    # Banking
    e.append(Paragraph("SECTION 3 — FINANCIAL INTELLIGENCE", s["h"]))
    b = profile.get("banking")
    if b:
        e.append(kv_tbl([
            ("UPI ID", b.get("upi_id")), ("Bank", b.get("bank")),
            ("Account Type", b.get("account_type")),
            ("Suspicious Txns", b.get("suspicious_transactions")),
            ("Suspicious Amount", b.get("total_amount_suspicious")),
            ("Linked Complaints", b.get("linked_complaints")),
        ]))
    else:
        e.append(Paragraph("No banking record linked.", s["body"]))
    e.append(PageBreak())

    # Page 3: Telecom + CCTNS
    e.append(Paragraph("SECTION 4 — TELECOM / CDR INTELLIGENCE", s["h"]))
    t = profile.get("telecom")
    if t:
        e.append(kv_tbl([
            ("Carrier", t.get("carrier")), ("SIM Type", t.get("sim_type")),
            ("Calls to Scam Numbers", t.get("calls_to_scam_numbers")),
            ("International Calls", t.get("international_calls")),
            ("VOIP Usage", t.get("voip_usage")),
            ("Linked IP", t.get("linked_ips")),
            ("Last Known Location", t.get("last_location")),
        ]))
    else:
        e.append(Paragraph("No telecom record found.", s["body"]))

    e.append(Paragraph("SECTION 5 — CRIMINAL RECORDS (CCTNS)", s["h"]))
    cases = profile.get("cctns_cases", [])
    if cases:
        for c in cases:
            e.append(kv_tbl([
                ("Case Number", c.get("case_number")), ("Crime Type", c.get("crime_type")),
                ("Year", c.get("year")), ("Police Station", c.get("police_station")),
                ("Status", c.get("status")), ("Victims", c.get("victim_count")),
            ]))
            e.append(Spacer(1, 6))
    else:
        e.append(Paragraph("No prior criminal record in CCTNS database.", s["body"]))
    e.append(PageBreak())

    # Page 4: Recommendations
    e.append(Paragraph("SECTION 6 — RECOMMENDED ACTIONS", s["h"]))
    actions = []
    if score >= 75:
        actions = [
            "Immediate Sec 94 BNSS freeze on all linked bank accounts",
            "Obtain CDR/IPDR via Sec 91 BNSS for last 90 days",
            "Request KYC details from bank and telecom provider",
            "Check for syndicate links via CCTNS pan-India search",
            "Coordinate with I4C for inter-state operations if required",
            "Obtain CCTV footage from ATM cash-out locations",
            "File charge-sheet within 60 days under relevant BNS sections",
        ]
    elif score >= 40:
        actions = [
            "Place suspect identifiers on watchlist for monitoring",
            "Request CDR for last 30 days for pattern analysis",
            "Cross-reference with existing complaint clusters",
            "Issue notice to bank for transaction history",
            "Monitor for repeat complaints against same identifiers",
        ]
    else:
        actions = [
            "Continue monitoring — low immediate risk",
            "Add to watchlist for passive surveillance",
            "Re-scan after 7 days for updated intelligence",
        ]
    for i, act in enumerate(actions, 1):
        e.append(Paragraph(f"<b>{i}.</b> {act}", s["body"]))

    e.append(Spacer(1, 20))
    e.append(HRFlowable(width="100%", thickness=0.6, color=rlc.HexColor("#e2e8f0")))
    e.append(Spacer(1, 6))
    e.append(Paragraph(
        "This dossier is auto-generated by SCINT Intelligence Platform v2.0. "
        "All personal data is SYNTHETIC / DUMMY and is used for demonstration only. "
        "This does not describe any real person, account, or criminal case.", s["disc"]))
    e.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Dossier ID: {case_id} | Classification: RESTRICTED", s["disc"]))

    doc.build(e)
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf",
                     download_name=f"SCINT_Dossier_{case_id}.pdf",
                     as_attachment=True)


# ── QR Code Forensics ──────────────────────────────────────────────────────

@app.route("/api/qr-analyze", methods=["POST"])
def api_qr_analyze():
    import re
    data = request.get_json(force=True)
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "No QR content to analyze"}), 400

    result = {"raw": content, "type": "UNKNOWN", "risk_score": 0, "findings": [], "iocs": {}}

    # Detect UPI payment links
    upi_match = re.match(r'upi://pay\?', content, re.I)
    if upi_match or "@" in content and not "://" in content:
        result["type"] = "UPI_PAYMENT"
        params = {}
        if "upi://pay?" in content.lower():
            for part in content.split("?", 1)[1].split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k.lower()] = v
        result["upi_params"] = params
        vpa = params.get("pa", content if "@" in content else "")
        result["iocs"]["upis"] = [vpa] if vpa else []
        payee = params.get("pn", "").replace("%20", " ")
        amount = params.get("am", "")
        result["findings"].append(f"UPI VPA detected: {vpa}")
        if payee:
            result["findings"].append(f"Payee name: {payee}")
        if amount:
            result["findings"].append(f"Pre-set amount: ₹{amount}")
            if float(amount or 0) > 10000:
                result["findings"].append("HIGH AMOUNT — verify before payment")
                result["risk_score"] += 30
        result["risk_score"] += 40

    # Detect URLs
    urls = re.findall(r'https?://[^\s<>"\']+', content, re.I)
    if urls:
        result["type"] = "URL" if result["type"] == "UNKNOWN" else result["type"]
        result["iocs"]["urls"] = urls
        for url in urls:
            result["findings"].append(f"URL found: {url}")
            short_domains = ["bit.ly", "tinyurl", "goo.gl", "t.co", "rb.gy", "cutt.ly", "is.gd"]
            if any(sd in url.lower() for sd in short_domains):
                result["findings"].append("SHORTENED URL DETECTED — may hide malicious destination")
                result["risk_score"] += 35
            suspicious_tlds = [".xyz", ".top", ".club", ".buzz", ".tk", ".ml", ".ga", ".cf"]
            if any(url.lower().endswith(tld) or tld + "/" in url.lower() for tld in suspicious_tlds):
                result["findings"].append("SUSPICIOUS TLD — commonly used in phishing")
                result["risk_score"] += 30
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                result["findings"].append("IP-BASED URL — no domain, likely malicious")
                result["risk_score"] += 40
        result["risk_score"] += 20

    # Detect phone numbers
    phones = re.findall(r'\b[6-9]\d{9}\b', content)
    if phones:
        result["iocs"]["phones"] = list(set(phones))
        for p in phones:
            result["findings"].append(f"Phone number: {p}")
        result["risk_score"] += 15

    # Detect emails
    emails = re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', content)
    if emails:
        result["iocs"]["emails"] = list(set(emails))
        result["risk_score"] += 10

    # Detect crypto addresses
    btc = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', content)
    if btc:
        result["findings"].append("BITCOIN ADDRESS DETECTED — possible crypto scam")
        result["iocs"]["crypto"] = btc
        result["risk_score"] += 45

    # Plain text analysis
    if result["type"] == "UNKNOWN":
        result["type"] = "TEXT"
        scam_kw = ["lottery", "winner", "prize", "congratulations", "won",
                    "transfer", "deposit", "otp", "kyc", "verify", "urgent", "blocked"]
        text_lower = content.lower()
        hits = [kw for kw in scam_kw if kw in text_lower]
        if hits:
            result["findings"].append(f"Scam keywords: {', '.join(hits)}")
            result["risk_score"] += len(hits) * 10

    result["risk_score"] = min(result["risk_score"], 100)
    if result["risk_score"] >= 70:
        result["verdict"] = "HIGH RISK — Likely Malicious QR Code"
        result["severity"] = "HIGH"
    elif result["risk_score"] >= 35:
        result["verdict"] = "MEDIUM RISK — Exercise Caution"
        result["severity"] = "MEDIUM"
    else:
        result["verdict"] = "LOW RISK"
        result["severity"] = "LOW"

    return jsonify(result)


# ── Live Threat Feed ────────────────────────────────────────────────────────

@app.route("/api/threat-feed")
def api_threat_feed():
    import requests as req
    feed = {"urlhaus": [], "threatfox": [], "errors": []}
    limit = request.args.get("limit", 25, type=int)

    # URLhaus recent threats
    try:
        resp = req.post("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{}/".format(min(limit, 50)),
                        timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            urls = data.get("urls") or []
            for u in urls[:limit]:
                feed["urlhaus"].append({
                    "url": u.get("url", ""),
                    "status": u.get("url_status", ""),
                    "threat": u.get("threat", ""),
                    "tags": u.get("tags") or [],
                    "host": u.get("host", ""),
                    "added": u.get("date_added", ""),
                    "country": u.get("country", ""),
                })
    except Exception as ex:
        feed["errors"].append(f"URLhaus: {str(ex)[:100]}")

    # ThreatFox recent IOCs
    try:
        resp = req.post("https://threatfox-api.abuse.ch/api/v1/",
                        json={"query": "get_iocs", "days": 1},
                        timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            iocs = (data.get("data") or [])[:limit]
            for ioc in iocs:
                feed["threatfox"].append({
                    "ioc": ioc.get("ioc", ""),
                    "ioc_type": ioc.get("ioc_type", ""),
                    "threat_type": ioc.get("threat_type", ""),
                    "malware": ioc.get("malware_printable", ""),
                    "confidence": ioc.get("confidence_level", 0),
                    "first_seen": ioc.get("first_seen_utc", ""),
                    "tags": ioc.get("tags") or [],
                })
    except Exception as ex:
        feed["errors"].append(f"ThreatFox: {str(ex)[:100]}")

    feed["total"] = len(feed["urlhaus"]) + len(feed["threatfox"])
    feed["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify(feed)


# ── Fraud Proof Package ────────────────────────────────────────────────────

@app.route("/api/fraud-proof", methods=["POST"])
def api_fraud_proof():
    data = request.get_json(force=True)
    victim = data.get("victim_name", "").strip()
    if not victim:
        return jsonify({"error": "Victim name required"}), 400

    now = datetime.now()
    ref_no = f"SCINT/FPP/{now.strftime('%Y%m%d')}/{now.strftime('%H%M%S')}"

    package = {
        "reference_number": ref_no,
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S IST"),
        "document_type": "Fraud Proof Package — Bank Submission",
        "victim_details": {
            "name": victim,
            "phone": data.get("victim_phone", "N/A"),
            "email": data.get("victim_email", "N/A"),
            "account_number": data.get("victim_account", "N/A"),
            "bank": data.get("victim_bank", "N/A"),
        },
        "incident_details": {
            "date_of_fraud": data.get("fraud_date", "N/A"),
            "time_of_fraud": data.get("fraud_time", "N/A"),
            "amount_lost": float(data.get("amount", 0) or 0),
            "transaction_ids": [t.strip() for t in (data.get("transaction_ids") or "").split(",") if t.strip()],
            "mode_of_fraud": data.get("fraud_mode", "UPI"),
            "scam_type": data.get("scam_type", "Unknown"),
            "description": data.get("description", ""),
        },
        "suspect_details": {
            "phone": data.get("suspect_phone", "N/A"),
            "upi_id": data.get("suspect_upi", "N/A"),
            "bank_account": data.get("suspect_account", "N/A"),
            "name_if_known": data.get("suspect_name", "N/A"),
        },
        "evidence_summary": [],
        "actions_taken": [],
        "legal_references": [
            "Section 66C IT Act 2000 — Identity Theft",
            "Section 66D IT Act 2000 — Cheating by Personation using Computer Resource",
            "Section 318(4) BNS 2023 — Cheating and Dishonestly Inducing Delivery of Property",
            "Section 319(2) BNS 2023 — Cheating by Personation",
            "RBI Circular on Limiting Liability of Customers in Unauthorized Electronic Banking Transactions",
        ],
        "bank_request": [
            "Immediately freeze the suspect account(s) mentioned above",
            "Provide KYC details of suspect account holder",
            "Provide complete transaction statement of suspect account for last 90 days",
            "Initiate chargeback / reversal process under RBI guidelines",
            "Share IP logs and device fingerprints used for the fraudulent transaction(s)",
            "Preserve all digital evidence for minimum 180 days",
        ],
    }

    # Add evidence items
    if data.get("ncrp_number"):
        package["evidence_summary"].append(f"NCRP Complaint No: {data['ncrp_number']}")
        package["actions_taken"].append("Complaint filed on National Cyber Crime Reporting Portal (cybercrime.gov.in)")
    if data.get("fir_number"):
        package["evidence_summary"].append(f"FIR No: {data['fir_number']}")
        package["actions_taken"].append("FIR registered at local Cyber Crime PS")
    if data.get("called_1930"):
        package["actions_taken"].append("Called 1930 — National Cyber Crime Helpline")
    if data.get("transaction_ids"):
        package["evidence_summary"].append(f"Transaction IDs: {data['transaction_ids']}")
    package["evidence_summary"].append("Screenshots of fraudulent communication (to be attached)")
    package["evidence_summary"].append("Bank statement showing unauthorized debit (to be attached)")

    # Auto-scan suspect if phone provided
    suspect_scan = None
    sp = (data.get("suspect_phone") or "").strip()
    if sp:
        try:
            s, f = scint.score_phone_quiet(sp)
            suspect_scan = {"score": s, "factors": f, "band": band_for(s)}
            package["scint_intelligence"] = {
                "suspect_risk_score": s,
                "risk_band": band_for(s),
                "risk_factors": f,
            }
        except Exception:
            pass

    return jsonify(package)


# ── Cyber Pulse — State-wise Cybercrime Trends ─────────────────────────────

CYBER_PULSE_DATA = {
    "Maharashtra": {"total": 37530, "top_crime": "Investment Scam", "yoy_change": 23.4, "hotspot": "Mumbai"},
    "Uttar Pradesh": {"total": 28954, "top_crime": "KYC Fraud", "yoy_change": 31.2, "hotspot": "Noida"},
    "Karnataka": {"total": 21437, "top_crime": "Job Scam", "yoy_change": 18.7, "hotspot": "Bengaluru"},
    "Telangana": {"total": 19876, "top_crime": "Digital Arrest", "yoy_change": 45.6, "hotspot": "Hyderabad"},
    "Tamil Nadu": {"total": 15234, "top_crime": "Phishing", "yoy_change": 14.2, "hotspot": "Chennai"},
    "Gujarat": {"total": 14567, "top_crime": "UPI Fraud", "yoy_change": 27.8, "hotspot": "Ahmedabad"},
    "Rajasthan": {"total": 13890, "top_crime": "Sextortion", "yoy_change": 52.1, "hotspot": "Jaipur"},
    "Haryana": {"total": 12456, "top_crime": "Digital Arrest", "yoy_change": 38.9, "hotspot": "Gurugram"},
    "West Bengal": {"total": 11234, "top_crime": "Lottery Scam", "yoy_change": 19.5, "hotspot": "Kolkata"},
    "Delhi": {"total": 23456, "top_crime": "Investment Scam", "yoy_change": 28.3, "hotspot": "South Delhi"},
    "Kerala": {"total": 9876, "top_crime": "Loan Scam", "yoy_change": 16.8, "hotspot": "Kochi"},
    "Madhya Pradesh": {"total": 8765, "top_crime": "KYC Fraud", "yoy_change": 22.1, "hotspot": "Bhopal"},
    "Bihar": {"total": 7654, "top_crime": "OTP Fraud", "yoy_change": 34.5, "hotspot": "Patna"},
    "Punjab": {"total": 7234, "top_crime": "Job Scam", "yoy_change": 25.6, "hotspot": "Ludhiana"},
    "Odisha": {"total": 5432, "top_crime": "Phishing", "yoy_change": 20.3, "hotspot": "Bhubaneswar"},
    "Jharkhand": {"total": 4567, "top_crime": "Sextortion", "yoy_change": 41.2, "hotspot": "Ranchi"},
    "Assam": {"total": 3456, "top_crime": "Digital Arrest", "yoy_change": 55.8, "hotspot": "Guwahati"},
    "Chhattisgarh": {"total": 2890, "top_crime": "UPI Fraud", "yoy_change": 18.4, "hotspot": "Raipur"},
    "Uttarakhand": {"total": 2345, "top_crime": "Investment Scam", "yoy_change": 29.7, "hotspot": "Dehradun"},
    "Goa": {"total": 1567, "top_crime": "Delivery Scam", "yoy_change": 12.1, "hotspot": "Panaji"},
}

@app.route("/api/cyber-pulse")
def api_cyber_pulse():
    complaints = db.get_complaints(500)
    scint_by_state = {}
    for c in complaints:
        st = c.get("state") or "Unknown"
        scint_by_state.setdefault(st, {"count": 0, "amount": 0})
        scint_by_state[st]["count"] += 1
        scint_by_state[st]["amount"] += float(c.get("amount", 0) or 0)

    states = []
    for name, info in sorted(CYBER_PULSE_DATA.items(), key=lambda x: -x[1]["total"]):
        scint_data = scint_by_state.get(name, {})
        states.append({
            "state": name,
            "total_cases": info["total"],
            "top_crime": info["top_crime"],
            "yoy_change": info["yoy_change"],
            "hotspot_city": info["hotspot"],
            "scint_complaints": scint_data.get("count", 0),
            "scint_amount": scint_data.get("amount", 0),
        })

    national_total = sum(s["total_cases"] for s in states)
    top_crime_counts = {}
    for s in states:
        top_crime_counts[s["top_crime"]] = top_crime_counts.get(s["top_crime"], 0) + s["total_cases"]

    return jsonify({
        "national_total": national_total,
        "states": states,
        "top_crimes_national": sorted(
            [{"type": k, "cases": v} for k, v in top_crime_counts.items()],
            key=lambda x: -x["cases"]
        ),
        "highest_growth": max(states, key=lambda s: s["yoy_change"])["state"],
        "most_affected": states[0]["state"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


# ── Cyber News & Breach Feed ───────────────────────────────────────────────

CYBER_NEWS_FEED = [
    {"title": "CERT-In Issues Advisory on Critical Vulnerability in Indian Banking Apps",
     "source": "CERT-In", "category": "Advisory", "severity": "CRITICAL",
     "date": "2026-09-03", "summary": "CERT-In has identified a critical authentication bypass vulnerability affecting multiple Indian banking applications. Banks have been directed to patch within 48 hours."},
    {"title": "Digital Arrest Scam Losses Cross ₹2,140 Crore in 2026",
     "source": "I4C", "category": "Report", "severity": "HIGH",
     "date": "2026-09-02", "summary": "Indian Cyber Crime Coordination Centre reports digital arrest scams have defrauded victims of over ₹2,140 crore in 2026 alone, with Telangana and Haryana being worst affected."},
    {"title": "Major Data Breach at Indian Telecom Provider Exposes 50M Records",
     "source": "BleepingComputer", "category": "Breach", "severity": "CRITICAL",
     "date": "2026-09-01", "summary": "A significant data breach at a major Indian telecom provider has exposed personal data of approximately 50 million subscribers including Aadhaar numbers and call records."},
    {"title": "RBI Mandates Real-Time Fraud Monitoring for All UPI Transactions",
     "source": "RBI", "category": "Regulation", "severity": "MEDIUM",
     "date": "2026-08-30", "summary": "Reserve Bank of India has issued new guidelines requiring all banks to implement real-time AI-based fraud detection for UPI transactions exceeding ₹10,000."},
    {"title": "Gurugram Cyber Cell Busts ₹85 Crore Investment Scam Ring",
     "source": "Gurugram Police", "category": "Enforcement", "severity": "HIGH",
     "date": "2026-08-29", "summary": "Gurugram Cyber Crime PS has arrested 12 suspects operating a fake stock trading platform that defrauded over 3,000 victims across 15 states."},
    {"title": "New Phishing Kit Targets Indian Government Officials via Fake NIC Portal",
     "source": "CERT-In", "category": "Threat Alert", "severity": "HIGH",
     "date": "2026-08-28", "summary": "A sophisticated phishing campaign using a cloned NIC email portal is targeting central and state government officials to steal credentials and sensitive documents."},
    {"title": "Indian Healthcare Database with 12M Patient Records Found on Dark Web",
     "source": "CloudSEK", "category": "Breach", "severity": "CRITICAL",
     "date": "2026-08-27", "summary": "Threat intelligence firm CloudSEK has discovered a database containing 12 million Indian patient records including diagnoses and Aadhaar numbers being sold on dark web forums."},
    {"title": "Cryptocurrency Scam via Fake WhatsApp Trading Groups Claims 5,000+ Victims",
     "source": "Economic Times", "category": "Scam", "severity": "HIGH",
     "date": "2026-08-26", "summary": "A nationwide cryptocurrency investment scam operating through coordinated WhatsApp groups has been uncovered, with losses estimated at ₹340 crore."},
    {"title": "NPCI Introduces AI-Based Mule Account Detection for UPI Ecosystem",
     "source": "NPCI", "category": "Technology", "severity": "MEDIUM",
     "date": "2026-08-25", "summary": "NPCI has deployed an AI/ML-based system to detect and flag mule accounts in real-time across the UPI payment ecosystem."},
    {"title": "Massive DDoS Attack Targets Indian Government Websites During Independence Day",
     "source": "CERT-In", "category": "Attack", "severity": "HIGH",
     "date": "2026-08-15", "summary": "Multiple Indian government websites faced coordinated DDoS attacks on Independence Day, attributed to hacktivist groups. CERT-In activated emergency response."},
    {"title": "SIM Swap Fraud Ring Operating from Jharkhand Dismantled",
     "source": "CBI", "category": "Enforcement", "severity": "MEDIUM",
     "date": "2026-08-14", "summary": "CBI has dismantled a SIM swap fraud ring operating from Deoghar, Jharkhand that had defrauded bank customers of over ₹25 crore using cloned SIM cards."},
    {"title": "Indian BFSI Sector Faces 300% Spike in Ransomware Attacks",
     "source": "DSCI", "category": "Report", "severity": "CRITICAL",
     "date": "2026-08-12", "summary": "Data Security Council of India reports a 300% increase in ransomware attacks targeting Indian banking, financial services, and insurance sector compared to 2025."},
]

@app.route("/api/cyber-news")
def api_cyber_news():
    category = request.args.get("category", "").strip()
    severity = request.args.get("severity", "").strip()
    limit = request.args.get("limit", 20, type=int)

    news = CYBER_NEWS_FEED[:]
    if category:
        news = [n for n in news if n["category"].lower() == category.lower()]
    if severity:
        news = [n for n in news if n["severity"] == severity.upper()]

    categories = list(set(n["category"] for n in CYBER_NEWS_FEED))
    sources = list(set(n["source"] for n in CYBER_NEWS_FEED))

    return jsonify({
        "articles": news[:limit],
        "total": len(news),
        "categories": sorted(categories),
        "sources": sorted(sources),
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


if __name__ == "__main__":
    db.ensure_db()
    db.ensure_extra_tables()
    print("\n  SCINT Intelligence Platform v2.0")
    print("  Open http://127.0.0.1:5000 in your browser")
    print("  Live intel: %s | PDF: %s\n" % (
        "ENABLED" if LIVE_AVAILABLE else "disabled",
        "ENABLED" if PDF_AVAILABLE else "disabled"))
    app.run(host="127.0.0.1", port=5000, debug=True)
