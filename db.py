#!/usr/bin/env python3
"""
db.py — SQLite layer for SCINT
GPCSSI 2026 | Gurugram Police

Builds a queryable SQLite database from the dummy CSVs and provides
aggregate statistics for the dashboard's Analytics page.

The CSVs remain the canonical demo data; this DB is generated from them.
Set the env var SCINT_DB to override where the .db file lives.
"""

import os
import csv
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.getenv("SCINT_DB", os.path.join(DATA_DIR, "scint.db"))

TABLES = {
    "aadhaar": "aadhaar_db.csv",
    "banking": "banking_db.csv",
    "telecom": "telecom_db.csv",
    "cctns": "cctns_db.csv",
    "ip_threat": "ip_threat_db.csv",
}


def build_db():
    """(Re)create the SQLite DB from the CSV files. Returns row counts."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    counts = {}
    for table, fname in TABLES.items():
        path = os.path.join(DATA_DIR, fname)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            cols = reader.fieldnames or []
            coldef = ", ".join('"%s" TEXT' % c for c in cols)
            cur.execute("DROP TABLE IF EXISTS %s" % table)
            cur.execute("CREATE TABLE %s (%s)" % (table, coldef))
            placeholders = ",".join("?" * len(cols))
            rows = [tuple(row[c] for c in cols) for row in reader]
            cur.executemany("INSERT INTO %s VALUES (%s)" % (table, placeholders), rows)
            counts[table] = len(rows)
    conn.commit()
    conn.close()
    return counts


def ensure_db():
    """Build the DB if it doesn't exist yet."""
    if not os.path.exists(DB_PATH):
        build_db()


def query(sql, params=()):
    ensure_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_stats():
    """Aggregate stats for the Analytics dashboard (SQL + risk scoring)."""
    import scint  # reuse the canonical scoring

    # Risk distribution — score every phone
    phones = [r["phone"] for r in query("SELECT phone FROM aadhaar")]
    high = med = low = 0
    for p in phones:
        s, _ = scint.score_phone_quiet(p)
        if s >= 75:
            high += 1
        elif s >= 40:
            med += 1
        else:
            low += 1

    def pairs(rows, k, v):
        return [{"label": r[k], "value": r[v]} for r in rows]

    return {
        "totals": {
            "records": len(phones),
            "cases": query("SELECT COUNT(*) c FROM cctns")[0]["c"],
            "flagged_aadhaar": query("SELECT COUNT(*) c FROM aadhaar WHERE flagged='True'")[0]["c"],
            "high": high, "medium": med, "low": low,
        },
        "risk_distribution": [
            {"label": "High", "value": high},
            {"label": "Medium", "value": med},
            {"label": "Low", "value": low},
        ],
        "crime_types": pairs(query(
            "SELECT crime_type label, COUNT(*) value FROM cctns GROUP BY crime_type ORDER BY value DESC"),
            "label", "value"),
        "cases_by_year": pairs(query(
            "SELECT year label, COUNT(*) value FROM cctns GROUP BY year ORDER BY year"),
            "label", "value"),
        "case_status": pairs(query(
            "SELECT status label, COUNT(*) value FROM cctns GROUP BY status ORDER BY value DESC"),
            "label", "value"),
        "locations": pairs(query(
            "SELECT last_location label, COUNT(*) value FROM telecom GROUP BY last_location ORDER BY value DESC"),
            "label", "value"),
    }


# ── Watchlist & Activity Tracking (Palantir-style) ─────────────────────────

_extra_ready = False


def ensure_extra_tables():
    global _extra_ready
    if _extra_ready:
        return
    ensure_db()
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL UNIQUE,
            priority TEXT DEFAULT 'medium',
            notes TEXT DEFAULT '',
            added_at TEXT NOT NULL,
            last_score INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_type TEXT NOT NULL,
            query_value TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            risk_band TEXT DEFAULT 'LOW',
            ts TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS golden_hour (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            victim_name TEXT NOT NULL,
            victim_phone TEXT NOT NULL,
            suspect_phone TEXT DEFAULT '',
            suspect_upi TEXT DEFAULT '',
            suspect_bank TEXT DEFAULT '',
            suspect_account TEXT DEFAULT '',
            scam_type TEXT DEFAULT 'UPI Fraud',
            amount_lost REAL DEFAULT 0,
            description TEXT DEFAULT '',
            started_at TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            steps TEXT DEFAULT '{}',
            scan_results TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            victim_name TEXT DEFAULT '',
            victim_phone TEXT DEFAULT '',
            suspect_indicators TEXT DEFAULT '',
            scam_type TEXT DEFAULT '',
            amount REAL DEFAULT 0,
            description TEXT DEFAULT '',
            state TEXT DEFAULT '',
            filed_at TEXT NOT NULL,
            cluster_id INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()
    _extra_ready = True


def add_to_watchlist(type_, value, priority="medium", notes=""):
    ensure_extra_tables()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO watchlist (type,value,priority,notes,added_at,last_score) "
            "VALUES (?,?,?,?,datetime('now'),0)",
            (type_, value.strip(), priority, notes))
        conn.commit()
        wid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return wid
    except sqlite3.IntegrityError:
        conn.close()
        return None


def remove_from_watchlist(wid):
    ensure_extra_tables()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM watchlist WHERE id=?", (wid,))
    conn.commit()
    conn.close()


def update_watchlist_score(value, score):
    ensure_extra_tables()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE watchlist SET last_score=? WHERE value=?", (score, value))
    conn.commit()
    conn.close()


def get_watchlist():
    ensure_extra_tables()
    return query(
        "SELECT * FROM watchlist ORDER BY "
        "CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 ELSE 3 END, added_at DESC")


def log_activity(query_type, query_value, risk_score, risk_band):
    ensure_extra_tables()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO activity_log (query_type,query_value,risk_score,risk_band,ts) "
        "VALUES (?,?,?,?,datetime('now'))",
        (query_type, query_value.strip(), risk_score, risk_band))
    conn.commit()
    conn.close()


def get_recent_activity(limit=50):
    ensure_extra_tables()
    return query("SELECT * FROM activity_log ORDER BY ts DESC LIMIT ?", (limit,))


def get_threat_level():
    ensure_extra_tables()
    recent = query("SELECT risk_score FROM activity_log ORDER BY ts DESC LIMIT 20")
    wl = query("SELECT COUNT(*) c FROM watchlist")
    wl_count = wl[0]["c"] if wl else 0
    if not recent:
        return {"level": "NORMAL", "score": 0, "scans_24h": 0,
                "high_hits": 0, "watchlist": wl_count}
    scores = [r["risk_score"] for r in recent if r["risk_score"] is not None]
    avg = sum(scores) / len(scores) if scores else 0
    high_count = sum(1 for s in scores if s and s >= 75)
    if high_count >= 5 or avg >= 70:
        level = "CRITICAL"
    elif high_count >= 3 or avg >= 50:
        level = "SEVERE"
    elif high_count >= 1 or avg >= 30:
        level = "ELEVATED"
    else:
        level = "NORMAL"
    return {"level": level, "score": round(avg), "scans_24h": len(recent),
            "high_hits": high_count, "watchlist": wl_count}


# ── Golden Hour ──────────────────────────────────────────────────────────────

def start_golden_hour(victim_name, victim_phone, suspect_phone="",
                      suspect_upi="", suspect_bank="", suspect_account="",
                      scam_type="UPI Fraud", amount_lost=0, description=""):
    ensure_extra_tables()
    import json
    steps = json.dumps({
        "scan_suspect": {"done": False, "ts": None, "label": "Scan suspect identifiers"},
        "freeze_request": {"done": False, "ts": None, "label": "Generate bank freeze notice (Sec 94 BNSS)"},
        "cdr_request": {"done": False, "ts": None, "label": "Request CDR/IPDR from telecom"},
        "check_watchlist": {"done": False, "ts": None, "label": "Check against watchlist & CCTNS"},
        "log_ncrp": {"done": False, "ts": None, "label": "Log complaint in NCRP format"},
        "generate_report": {"done": False, "ts": None, "label": "Generate case summary PDF"},
    })
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO golden_hour "
        "(victim_name,victim_phone,suspect_phone,suspect_upi,suspect_bank,"
        "suspect_account,scam_type,amount_lost,description,started_at,status,steps,scan_results) "
        "VALUES (?,?,?,?,?,?,?,?,?,datetime('now'),'active',?,'{}')",
        (victim_name, victim_phone, suspect_phone, suspect_upi, suspect_bank,
         suspect_account, scam_type, amount_lost, description, steps))
    conn.commit()
    gid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return gid


def get_golden_hour(gid):
    ensure_extra_tables()
    rows = query("SELECT * FROM golden_hour WHERE id=?", (gid,))
    return rows[0] if rows else None


def get_active_golden_hours():
    ensure_extra_tables()
    return query("SELECT * FROM golden_hour ORDER BY started_at DESC LIMIT 20")


def update_golden_step(gid, step_key, done=True):
    ensure_extra_tables()
    import json
    row = get_golden_hour(gid)
    if not row:
        return
    steps = json.loads(row["steps"] or "{}")
    if step_key in steps:
        steps[step_key]["done"] = done
        steps[step_key]["ts"] = None  # will be set by trigger
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE golden_hour SET steps=? WHERE id=?",
                     (json.dumps(steps), gid))
        conn.commit()
        conn.close()


def update_golden_scan(gid, scan_results):
    ensure_extra_tables()
    import json
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE golden_hour SET scan_results=? WHERE id=?",
                 (json.dumps(scan_results), gid))
    conn.commit()
    conn.close()


def close_golden_hour(gid):
    ensure_extra_tables()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE golden_hour SET status='completed' WHERE id=?", (gid,))
    conn.commit()
    conn.close()


# ── Complaints & Clustering ──────────────────────────────────────────────────

def add_complaint(victim_name, victim_phone, suspect_indicators, scam_type,
                  amount, description, state):
    ensure_extra_tables()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO complaints "
        "(victim_name,victim_phone,suspect_indicators,scam_type,amount,"
        "description,state,filed_at,cluster_id) "
        "VALUES (?,?,?,?,?,?,?,datetime('now'),0)",
        (victim_name, victim_phone, suspect_indicators, scam_type,
         amount, description, state))
    conn.commit()
    cid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return cid


def get_complaints(limit=100):
    ensure_extra_tables()
    return query("SELECT * FROM complaints ORDER BY filed_at DESC LIMIT ?", (limit,))


def update_cluster_ids(clusters):
    ensure_extra_tables()
    conn = sqlite3.connect(DB_PATH)
    for cluster_id, complaint_ids in enumerate(clusters, 1):
        for cid in complaint_ids:
            conn.execute("UPDATE complaints SET cluster_id=? WHERE id=?",
                         (cluster_id, cid))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    print(f"Building SQLite DB at: {DB_PATH}")
    counts = build_db()
    for t, n in counts.items():
        print(f"  {t:<12} {n} rows")
    print("Done.")
