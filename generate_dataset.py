#!/usr/bin/env python3
"""
generate_dataset.py — builds 100 internally-consistent dummy records
across aadhaar_db, banking_db, telecom_db, cctns_db.

Run once:  python generate_dataset.py
It overwrites the four CSVs in data/ with a realistic risk spread:
  ~65 low-risk, ~25 medium-risk, ~10 high-risk.

All data is SYNTHETIC. Names/IDs/amounts are randomly generated and do
not correspond to real individuals.
"""

import csv
import os
import random

random.seed(2026)  # reproducible

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

FIRST = ["Rajesh","Priya","Amit","Sunita","Rahul","Meena","Vijay","Anjali","Sanjay","Kavita",
         "Deepak","Pooja","Manoj","Neha","Arun","Ritu","Suresh","Divya","Vikas","Shweta",
         "Rohit","Anita","Naveen","Swati","Karan","Nisha","Gaurav","Preeti","Ajay","Rekha",
         "Sandeep","Jyoti","Mohit","Sneha","Ramesh","Komal","Ashok","Geeta","Vivek","Pallavi"]
LAST  = ["Kumar","Sharma","Verma","Devi","Gupta","Patel","Singh","Mishra","Yadav","Reddy",
         "Nair","Mehta","Joshi","Chauhan","Bansal","Khanna","Malhotra","Saxena","Tiwari","Bhatt"]
CITIES = [("Gurugram","Haryana"),("Delhi","Delhi"),("Noida","UP"),("Faridabad","Haryana"),
          ("Mumbai","Maharashtra"),("Bengaluru","Karnataka"),("Pune","Maharashtra"),
          ("Kolkata","WB"),("Jaipur","Rajasthan"),("Lucknow","UP")]
BANKS = ["HDFC Bank","SBI","ICICI Bank","Axis Bank","Yes Bank","Kotak Bank","PNB","IDFC Bank"]
UPI_SUFFIX = ["paytm","upi","ybl","okaxis","ibl","okhdfc","apl","okicici"]
CARRIERS = ["Jio","Airtel","Vodafone","BSNL"]
CRIME_TYPES = ["Investment Fraud","UPI Scam","Digital Arrest Scam","APK Malware Fraud",
               "SIM Swap Fraud","Phishing","OTP Fraud","Online Fraud","Loan App Extortion","Sextortion"]
PS = ["Cyber PS Gurugram","Cyber PS Delhi","Cyber PS Noida","Cyber PS Faridabad","Cyber PS Jaipur"]
STATUS = ["Under Investigation","Chargesheeted","Convicted"]
SCAM_IPS = ["45.133.1.98","185.220.101.45","194.165.16.72","91.108.4.200"]
CLEAN_IPS = ["103.21.45.67","122.161.45.67","49.32.11.201","103.56.78.90"]


def rupees(n):
    """Format an integer into Indian comma style, e.g. 3245000 -> ₹32,45,000."""
    s = str(n)
    if len(s) <= 3:
        return "₹" + s
    head, tail = s[:-3], s[-3:]
    parts = []
    while len(head) > 2:
        parts.insert(0, head[-2:]); head = head[:-2]
    if head:
        parts.insert(0, head)
    return "₹" + ",".join(parts) + "," + tail


def aadhaar_id():
    return "-".join(f"{random.randint(0,9999):04d}" for _ in range(3))


# Risk tiers: 0=low, 1=medium, 2=high
N = 100
tiers = [0]*65 + [1]*25 + [2]*10
random.shuffle(tiers)

phones, aadhaar, banking, telecom, cctns = [], [], [], [], []
used = set()

for i in range(N):
    # unique-ish phone
    while True:
        phone = "9" + "".join(str(random.randint(0,9)) for _ in range(9))
        if phone not in used:
            used.add(phone); break
    phones.append(phone)
    tier = tiers[i]
    name = f"{random.choice(FIRST)} {random.choice(LAST)}"
    city, state = random.choice(CITIES)
    dob = f"{random.randint(1970,2000)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"

    # ── Aadhaar ──
    flagged = "True" if tier == 2 and random.random() < 0.9 else ("True" if tier == 1 and random.random() < 0.3 else "False")
    aadhaar.append({
        "aadhaar_id": aadhaar_id(), "name": name, "phone": phone,
        "address": f"{random.randint(1,99)} {city}", "dob": dob, "flagged": flagged
    })

    # ── Banking ──
    if tier == 2:
        tx = random.randint(8, 20); cp = random.randint(3, 9); amt = random.randint(5,40)*100000 + random.randint(0,99)*1000
    elif tier == 1:
        tx = random.randint(4, 7); cp = random.randint(1, 3); amt = random.randint(1,8)*10000 + random.randint(0,99)*100
    else:
        tx = random.randint(0, 3); cp = random.randint(0, 1); amt = random.randint(0,5)*1000
    banking.append({
        "phone": phone, "upi_id": f"{name.split()[0].lower()}{random.randint(1,99)}@{random.choice(UPI_SUFFIX)}",
        "bank": random.choice(BANKS), "account_type": random.choice(["Savings","Current"]),
        "suspicious_transactions": tx, "total_amount_suspicious": rupees(amt), "linked_complaints": cp
    })

    # ── Telecom ──
    if tier == 2:
        sc = random.randint(15, 70); voip = "Yes"; flg = "True"; ip = random.choice(SCAM_IPS); sim = random.choice(["eSIM","Physical SIM"])
    elif tier == 1:
        sc = random.randint(5, 14); voip = random.choice(["Yes","No"]); flg = "False"; ip = random.choice(CLEAN_IPS); sim = "Physical SIM"
    else:
        sc = random.randint(0, 4); voip = "No"; flg = "False"; ip = random.choice(CLEAN_IPS); sim = "Physical SIM"
    telecom.append({
        "phone": phone, "carrier": random.choice(CARRIERS), "sim_type": sim,
        "calls_to_scam_numbers": sc, "international_calls": random.randint(0,40),
        "voip_usage": voip, "linked_ips": ip, "last_location": f"{city}, {state}", "flagged": flg
    })

    # ── CCTNS (only high, and some medium) ──
    if tier == 2:
        for _ in range(random.randint(1, 3)):
            yr = random.randint(2022, 2025)
            cctns.append({
                "phone": phone, "case_number": f"CYBER/{random.choice(['GGN','DL','NDA','HR'])}/{yr}/{random.randint(100,1999):04d}",
                "year": yr, "crime_type": random.choice(CRIME_TYPES), "police_station": random.choice(PS),
                "status": random.choice(STATUS), "victim_count": random.randint(1, 35)
            })
    elif tier == 1 and random.random() < 0.25:
        yr = random.randint(2022, 2025)
        cctns.append({
            "phone": phone, "case_number": f"CYBER/{random.choice(['GGN','DL'])}/{yr}/{random.randint(100,1999):04d}",
            "year": yr, "crime_type": random.choice(CRIME_TYPES), "police_station": random.choice(PS),
            "status": "Under Investigation", "victim_count": random.randint(1, 5)
        })


def write(path, fieldnames, rows):
    with open(os.path.join(DATA_DIR, path), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


write("aadhaar_db.csv", ["aadhaar_id","name","phone","address","dob","flagged"], aadhaar)
write("banking_db.csv", ["phone","upi_id","bank","account_type","suspicious_transactions","total_amount_suspicious","linked_complaints"], banking)
write("telecom_db.csv", ["phone","carrier","sim_type","calls_to_scam_numbers","international_calls","voip_usage","linked_ips","last_location","flagged"], telecom)
write("cctns_db.csv",   ["phone","case_number","year","crime_type","police_station","status","victim_count"], cctns)

# Also write a ready-to-use bulk input of all 100 phones
with open(os.path.join(BASE_DIR, "sample_phones.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["phone"])
    for p in phones:
        w.writerow([p])

print(f"Generated {N} records:")
print(f"  aadhaar_db.csv : {len(aadhaar)} rows")
print(f"  banking_db.csv : {len(banking)} rows")
print(f"  telecom_db.csv : {len(telecom)} rows")
print(f"  cctns_db.csv   : {len(cctns)} rows  ({len(set(c['phone'] for c in cctns))} individuals)")
print(f"  sample_phones.csv : {N} phones for bulk testing")
print(f"  Risk spread -> low: {tiers.count(0)}, medium: {tiers.count(1)}, high: {tiers.count(2)}")
