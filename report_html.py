#!/usr/bin/env python3
"""
report_html.py — Professional HTML report generator for SCINT v2
GPCSSI 2026 | Gurugram Police Cyber Security Internship

Renders a lookup result dict into a self-contained, screenshot-ready
HTML case file. No external dependencies — pure string templating so it
works offline and embeds nothing risky.
"""

import os
import html
from datetime import datetime


def _esc(v):
    """Escape any value for safe HTML embedding."""
    return html.escape(str(v if v is not None else "—"))


def _risk_band(score):
    score = int(score)
    if score >= 75:
        return "high", "HIGH RISK"
    elif score >= 40:
        return "medium", "MEDIUM RISK"
    return "low", "LOW RISK"


def _row(label, value, danger=False):
    cls = ' class="danger"' if danger else ""
    return f'<tr><td class="lbl">{_esc(label)}</td><td{cls}>{_esc(value)}</td></tr>'


def _section(title, tag, rows_html):
    return f"""
    <section class="card">
      <div class="card-head">
        <h2>{_esc(title)}</h2>
        <span class="tag tag-{tag[0]}">{_esc(tag[1])}</span>
      </div>
      <table>{rows_html}</table>
    </section>"""


def build_report(report):
    """
    report: the dict SCINT assembles (query, type, risk_score,
            risk_factors, and the various data blocks).
    Returns: full HTML string.
    """
    query = report.get("query", "—")
    qtype = report.get("type", "—")
    score = int(report.get("risk_score", 0))
    band_cls, band_txt = _risk_band(score)
    factors = report.get("risk_factors", []) or []
    ts = report.get("timestamp", datetime.now().isoformat())

    # ── Build data sections depending on type ────────────────────────────────
    sections = []

    if qtype == "phone":
        a = report.get("aadhaar") or {}
        if a:
            flagged = str(a.get("flagged")) == "True"
            rows = (
                _row("Name", a.get("name")) +
                _row("Aadhaar ID", a.get("aadhaar_id")) +
                _row("Date of Birth", a.get("dob")) +
                _row("Address", a.get("address")) +
                _row("Flagged", "YES — Known fraud identity" if flagged else "No flags", danger=flagged)
            )
            sections.append(_section("Aadhaar Intelligence  [dummy]",
                                     ("high" if flagged else "low",
                                      "FLAGGED" if flagged else "CLEAR"), rows))

        b = report.get("banking") or {}
        if b:
            tx = int(b.get("suspicious_transactions", 0) or 0)
            cp = int(b.get("linked_complaints", 0) or 0)
            rows = (
                _row("UPI ID", b.get("upi_id")) +
                _row("Bank", b.get("bank")) +
                _row("Account Type", b.get("account_type")) +
                _row("Suspicious Transactions", b.get("suspicious_transactions"), danger=tx > 5) +
                _row("Suspicious Amount", b.get("total_amount_suspicious"), danger=tx > 5) +
                _row("Linked Complaints", b.get("linked_complaints"), danger=cp > 2)
            )
            sections.append(_section("Banking & UPI Intelligence  [dummy]",
                                     ("high" if tx > 5 else "low",
                                      "SUSPICIOUS" if tx > 5 else "NORMAL"), rows))

        t = report.get("telecom") or {}
        if t:
            sc = int(t.get("calls_to_scam_numbers", 0) or 0)
            voip = str(t.get("voip_usage")) == "Yes"
            rows = (
                _row("Carrier", t.get("carrier")) +
                _row("SIM Type", t.get("sim_type")) +
                _row("Calls to Scam Numbers", t.get("calls_to_scam_numbers"), danger=sc > 10) +
                _row("International Calls", t.get("international_calls")) +
                _row("VOIP Usage", "YES — Suspicious" if voip else "No", danger=voip) +
                _row("Linked IP", t.get("linked_ips")) +
                _row("Last Location", t.get("last_location"))
            )
            sections.append(_section("Telecom / CDR / IPDR  [dummy]",
                                     ("high" if sc > 10 else "low",
                                      "FLAGGED" if sc > 10 else "CLEAR"), rows))

        cases = report.get("cctns_cases") or []
        if cases:
            rows = ""
            for c in cases:
                rows += (
                    _row("Case Number", c.get("case_number"), danger=True) +
                    _row("  Year", c.get("year")) +
                    _row("  Crime Type", c.get("crime_type"), danger=True) +
                    _row("  Police Station", c.get("police_station")) +
                    _row("  Status", c.get("status")) +
                    _row("  Victims", c.get("victim_count"))
                )
            sections.append(_section(f"CCTNS — {len(cases)} Criminal Case(s)  [dummy]",
                                     ("high", "RECORD FOUND"), rows))

    elif qtype == "ip":
        local = report.get("local") or {}
        if local:
            rows = (
                _row("IP Address", local.get("ip")) +
                _row("Country", local.get("country")) +
                _row("City", local.get("city")) +
                _row("ISP", local.get("isp")) +
                _row("Type", local.get("type")) +
                _row("Abuse Reports", local.get("abuse_reports")) +
                _row("Attack Types", local.get("attack_types"), danger=True)
            )
            sections.append(_section("IP Threat Intelligence  [dummy]",
                                     ("high", "DB MATCH"), rows))

        live = report.get("live") or {}
        if live:
            geo = live.get("geo", {})
            abuse = live.get("abuseipdb", {})
            vt = live.get("virustotal", {})
            rows = ""
            if geo.get("ok"):
                rows += (
                    _row("Country (live)", geo.get("country")) +
                    _row("City (live)", geo.get("city")) +
                    _row("ISP (live)", geo.get("isp")) +
                    _row("Hosting/Datacenter", "YES" if geo.get("is_hosting") else "No", danger=geo.get("is_hosting")) +
                    _row("Proxy/VPN", "YES" if geo.get("is_proxy") else "No", danger=geo.get("is_proxy"))
                )
            if abuse.get("ok"):
                rows += (
                    _row("AbuseIPDB Score", f"{abuse.get('abuse_score')}%", danger=int(abuse.get('abuse_score', 0)) >= 25) +
                    _row("Total Reports", abuse.get("total_reports"), danger=int(abuse.get('total_reports', 0)) > 20) +
                    _row("Tor Exit Node", "YES" if abuse.get("is_tor") else "No", danger=abuse.get("is_tor"))
                )
            if vt.get("ok"):
                rows += (
                    _row("VirusTotal Malicious", vt.get("malicious"), danger=int(vt.get('malicious', 0)) > 0) +
                    _row("VirusTotal Suspicious", vt.get("suspicious"), danger=int(vt.get('suspicious', 0)) > 0)
                )
            if rows:
                sections.append(_section("Live Threat Intelligence  [REAL DATA]",
                                         ("low", "LIVE"), rows))

    # ── Risk factors ─────────────────────────────────────────────────────────
    factors_html = ""
    if factors:
        items = "".join(f"<li>{_esc(f)}</li>" for f in factors)
        factors_html = f'<div class="factors"><h3>Risk Factors Detected</h3><ul>{items}</ul></div>'

    sections_html = "\n".join(sections)

    # ── Full HTML document ─────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SCINT Report — {_esc(query)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Sora:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0a0e14;
    --panel: #121823;
    --panel-2: #1a2332;
    --line: #243044;
    --text: #e6edf3;
    --dim: #8b98a9;
    --accent: #00d9a3;
    --high: #ff4d5e;
    --medium: #ffb020;
    --low: #00d9a3;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: radial-gradient(1200px 600px at 80% -10%, #14283a 0%, var(--bg) 60%);
    color: var(--text);
    font-family: 'Sora', sans-serif;
    padding: 40px 20px;
    min-height: 100vh;
  }}
  .wrap {{ max-width: 880px; margin: 0 auto; }}
  header {{
    display: flex; justify-content: space-between; align-items: flex-end;
    border-bottom: 1px solid var(--line); padding-bottom: 20px; margin-bottom: 28px;
  }}
  .brand {{ font-family: 'JetBrains Mono', monospace; }}
  .brand .logo {{ font-size: 28px; font-weight: 800; letter-spacing: 4px; color: var(--accent); }}
  .brand .sub {{ font-size: 11px; color: var(--dim); letter-spacing: 2px; margin-top: 4px; }}
  .meta {{ text-align: right; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--dim); line-height: 1.6; }}

  .hero {{
    background: var(--panel); border: 1px solid var(--line); border-radius: 16px;
    padding: 28px; margin-bottom: 24px; display: flex; align-items: center;
    justify-content: space-between; gap: 24px; position: relative; overflow: hidden;
  }}
  .hero::before {{
    content: ""; position: absolute; inset: 0;
    background: linear-gradient(135deg, transparent 60%, var(--accent) 200%);
    opacity: 0.06;
  }}
  .hero .q-label {{ font-size: 12px; color: var(--dim); letter-spacing: 2px; text-transform: uppercase; }}
  .hero .q-value {{ font-family: 'JetBrains Mono', monospace; font-size: 30px; font-weight: 700; margin-top: 6px; word-break: break-all; }}
  .gauge {{ text-align: center; flex-shrink: 0; }}
  .gauge .score {{ font-family: 'JetBrains Mono', monospace; font-size: 52px; font-weight: 700; line-height: 1; }}
  .gauge .outof {{ font-size: 13px; color: var(--dim); }}
  .badge {{
    display: inline-block; margin-top: 10px; padding: 6px 16px; border-radius: 999px;
    font-size: 12px; font-weight: 700; letter-spacing: 1px;
  }}
  .high  {{ color: var(--high); }}    .badge.high   {{ background: rgba(255,77,94,.14);  color: var(--high); border: 1px solid var(--high); }}
  .medium{{ color: var(--medium); }}  .badge.medium {{ background: rgba(255,176,32,.14); color: var(--medium); border: 1px solid var(--medium); }}
  .low   {{ color: var(--low); }}     .badge.low    {{ background: rgba(0,217,163,.12);  color: var(--low); border: 1px solid var(--low); }}

  .factors {{
    background: rgba(255,77,94,.07); border: 1px solid rgba(255,77,94,.3);
    border-radius: 12px; padding: 18px 22px; margin-bottom: 24px;
  }}
  .factors h3 {{ font-size: 13px; letter-spacing: 1px; text-transform: uppercase; color: var(--high); margin-bottom: 10px; }}
  .factors ul {{ list-style: none; }}
  .factors li {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; padding: 4px 0 4px 18px; position: relative; }}
  .factors li::before {{ content: "▸"; position: absolute; left: 0; color: var(--high); }}

  .card {{
    background: var(--panel); border: 1px solid var(--line); border-radius: 14px;
    margin-bottom: 18px; overflow: hidden;
  }}
  .card-head {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 16px 22px; background: var(--panel-2); border-bottom: 1px solid var(--line);
  }}
  .card-head h2 {{ font-size: 14px; font-weight: 600; letter-spacing: .5px; }}
  .tag {{ font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700; padding: 4px 10px; border-radius: 6px; letter-spacing: 1px; }}
  .tag-high   {{ background: rgba(255,77,94,.15);  color: var(--high); }}
  .tag-medium {{ background: rgba(255,176,32,.15); color: var(--medium); }}
  .tag-low    {{ background: rgba(0,217,163,.13);  color: var(--low); }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 11px 22px; font-size: 13px; border-bottom: 1px solid rgba(36,48,68,.5); }}
  td.lbl {{ color: var(--dim); width: 42%; font-size: 12px; }}
  td.danger {{ color: var(--high); font-weight: 600; }}
  tr:last-child td {{ border-bottom: none; }}

  footer {{ margin-top: 30px; padding-top: 18px; border-top: 1px solid var(--line); text-align: center; }}
  footer p {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--dim); line-height: 1.7; }}
  .disclaimer {{ color: var(--medium); }}
</style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="brand">
        <div class="logo">SCINT</div>
        <div class="sub">SCAM CYBER INTELLIGENCE TOOL</div>
      </div>
      <div class="meta">
        GPCSSI 2026 · GURUGRAM POLICE<br>
        REPORT · {_esc(qtype.upper())}<br>
        {_esc(ts[:19].replace("T", " "))}
      </div>
    </header>

    <div class="hero">
      <div>
        <div class="q-label">Subject of Investigation</div>
        <div class="q-value">{_esc(query)}</div>
      </div>
      <div class="gauge">
        <div class="score {band_cls}">{score}<span class="outof">/100</span></div>
        <span class="badge {band_cls}">{band_txt}</span>
      </div>
    </div>

    {factors_html}

    {sections_html}

    <footer>
      <p class="disclaimer">⚠ Aadhaar / CCTNS / banking / telecom data is DUMMY — for demonstration only.</p>
      <p>Live IP intelligence sourced from public APIs (ip-api, AbuseIPDB, VirusTotal).</p>
      <p>Generated by SCINT v3 · {_esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</p>
    </footer>
  </div>
</body>
</html>"""


def save_report(report, out_dir):
    """Write the HTML report and return its path."""
    query = str(report.get("query", "unknown")).replace("/", "_").replace(":", "_")
    fname = f"scint_{query}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    path = os.path.join(out_dir, fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_report(report))
    return path
