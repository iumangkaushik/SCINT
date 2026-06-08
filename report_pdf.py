#!/usr/bin/env python3
"""
report_pdf.py - PDF case-report generator for SCINT
GPCSSI 2026 | Gurugram Police

Builds a professional one-page PDF case report for a scanned phone number,
using reportlab (pure Python, no system dependencies).
"""

import io
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

CYAN = colors.HexColor("#0e7490")
HIGH = colors.HexColor("#b91c1c")
MED = colors.HexColor("#b45309")
LOW = colors.HexColor("#15803d")
GREY = colors.HexColor("#64748b")


def _band_color(band):
    return {"HIGH": HIGH, "MEDIUM": MED, "LOW": LOW}.get(band, GREY)


def _kv_table(rows, styles):
    """Build a two-column key/value table from a list of (k, v) tuples."""
    data = [[Paragraph(f"<b>{k}</b>", styles["k"]), Paragraph(str(v), styles["v"])]
            for k, v in rows]
    t = Table(data, colWidths=[55 * mm, 110 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def build_phone_pdf(profile):
    """profile = the dict from build_phone_profile(). Returns a BytesIO of the PDF."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"SCINT Report {profile.get('query','')}")

    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("title", parent=base["Title"], fontSize=20,
                                 textColor=CYAN, spaceAfter=2),
        "sub": ParagraphStyle("sub", parent=base["Normal"], fontSize=9,
                               textColor=GREY),
        "h": ParagraphStyle("h", parent=base["Heading2"], fontSize=12,
                            textColor=CYAN, spaceBefore=10, spaceAfter=4),
        "k": ParagraphStyle("k", parent=base["Normal"], fontSize=9.5,
                            textColor=GREY),
        "v": ParagraphStyle("v", parent=base["Normal"], fontSize=9.5),
        "factor": ParagraphStyle("factor", parent=base["Normal"], fontSize=10,
                                 textColor=HIGH, leftIndent=6),
        "disc": ParagraphStyle("disc", parent=base["Normal"], fontSize=8,
                               textColor=GREY),
    }

    band = profile.get("risk_band", "LOW")
    score = profile.get("risk_score", 0)
    e = []

    # Header
    e.append(Paragraph("SCINT - Cyber Intelligence Report", styles["title"]))
    e.append(Paragraph("GPCSSI 2026 &middot; Gurugram Police &middot; "
                       "DUMMY DATA - for demonstration only", styles["sub"]))
    e.append(Spacer(1, 6))
    e.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    e.append(Spacer(1, 8))

    # Subject + risk
    e.append(_kv_table([
        ("Subject (phone)", profile.get("query", "")),
        ("Report generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ], styles))
    e.append(Spacer(1, 6))

    risk_tbl = Table([[
        Paragraph(f"<b>RISK SCORE</b>", styles["k"]),
        Paragraph(f"<font color='{_band_color(band).hexval()}'><b>{score}/100 &nbsp; {band}</b></font>",
                  ParagraphStyle("rs", parent=base["Normal"], fontSize=14)),
    ]], colWidths=[55 * mm, 110 * mm])
    risk_tbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    e.append(risk_tbl)

    factors = profile.get("risk_factors", [])
    if factors:
        e.append(Paragraph("Risk factors detected", styles["h"]))
        for f in factors:
            e.append(Paragraph(f"&#8594; {f}", styles["factor"]))
    else:
        e.append(Paragraph("No risk factors detected.", styles["v"]))

    # Aadhaar
    a = profile.get("aadhaar")
    e.append(Paragraph("Aadhaar Intelligence", styles["h"]))
    if a:
        e.append(_kv_table([
            ("Name", a.get("name")), ("Aadhaar ID", a.get("aadhaar_id")),
            ("Date of Birth", a.get("dob")), ("Address", a.get("address")),
            ("Flagged", "YES - known fraud identity" if a.get("flagged") == "True" else "No"),
        ], styles))
    else:
        e.append(Paragraph("No Aadhaar record.", styles["v"]))

    # Banking
    b = profile.get("banking")
    e.append(Paragraph("Banking & UPI Intelligence", styles["h"]))
    if b:
        e.append(_kv_table([
            ("UPI ID", b.get("upi_id")), ("Bank", b.get("bank")),
            ("Account Type", b.get("account_type")),
            ("Suspicious Transactions", b.get("suspicious_transactions")),
            ("Suspicious Amount", b.get("total_amount_suspicious")),
            ("Linked Complaints", b.get("linked_complaints")),
        ], styles))
    else:
        e.append(Paragraph("No banking record.", styles["v"]))

    # Telecom
    t = profile.get("telecom")
    e.append(Paragraph("Telecom / CDR Intelligence", styles["h"]))
    if t:
        e.append(_kv_table([
            ("Carrier", t.get("carrier")), ("SIM Type", t.get("sim_type")),
            ("Calls to Scam Numbers", t.get("calls_to_scam_numbers")),
            ("International Calls", t.get("international_calls")),
            ("VOIP Usage", t.get("voip_usage")),
            ("Linked IP", t.get("linked_ips")),
            ("Last Known Location", t.get("last_location")),
        ], styles))
    else:
        e.append(Paragraph("No telecom record.", styles["v"]))

    # CCTNS
    cases = profile.get("cctns_cases", [])
    e.append(Paragraph("CCTNS - Crime Records", styles["h"]))
    if cases:
        for c in cases:
            e.append(_kv_table([
                ("Case Number", c.get("case_number")),
                ("Crime Type", c.get("crime_type")),
                ("Year", c.get("year")),
                ("Police Station", c.get("police_station")),
                ("Status", c.get("status")),
                ("Victims", c.get("victim_count")),
            ], styles))
            e.append(Spacer(1, 4))
    else:
        e.append(Paragraph("No prior criminal record.", styles["v"]))

    e.append(Spacer(1, 14))
    e.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#e2e8f0")))
    e.append(Spacer(1, 4))
    e.append(Paragraph(
        "This report is generated from randomly-generated dummy data for "
        "educational/portfolio demonstration only. It does not describe any real "
        "person, account, or criminal case.", styles["disc"]))

    doc.build(e)
    buf.seek(0)
    return buf
