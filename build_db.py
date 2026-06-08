#!/usr/bin/env python3
"""
build_db.py — one-shot script to (re)build the SCINT SQLite database from CSVs.

Usage:
    python build_db.py
"""

import db

if __name__ == "__main__":
    print(f"Building SQLite DB at: {db.DB_PATH}")
    counts = db.build_db()
    for table, n in counts.items():
        print(f"  {table:<12} {n} rows")
    print("Done. The Analytics page now reads from this database.")
