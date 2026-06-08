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
    "Lucknow": [26.85, 80.95],
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


if __name__ == "__main__":
    db.ensure_db()
    db.ensure_extra_tables()
    print("\n  SCINT Intelligence Platform v2.0")
    print("  Open http://127.0.0.1:5000 in your browser")
    print("  Live intel: %s | PDF: %s\n" % (
        "ENABLED" if LIVE_AVAILABLE else "disabled",
        "ENABLED" if PDF_AVAILABLE else "disabled"))
    app.run(host="127.0.0.1", port=5000, debug=True)
