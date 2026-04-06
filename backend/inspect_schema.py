"""Inspect live PostgreSQL schema vs ORM models to detect drift."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import inspect as sa_inspect
from database.db import engine
from database import models

inspector = sa_inspect(engine)

tables = inspector.get_table_names()
print("=== EXISTING TABLES ===")
for t in sorted(tables):
    print(f"  {t}")

print()

TARGET_TABLES = {
    "scan_jobs": [
        "job_id", "user_id", "target", "status", "scan_type",
        "scan_profile", "use_ajax", "created_at", "raw_results", "error_detail",
    ],
    "assets": [
        "asset_id", "job_id", "user_id", "ip_address", "hostname", "os_detected",
        "criticality", "environment", "tags", "internet_exposed",
        "business_owner", "first_seen", "last_seen",
    ],
    "vulnerabilities": [
        "vuln_id", "job_id", "user_id", "title", "description", "severity",
        "risk_score", "evidence", "url", "solution", "cve_id", "cwe_id",
        "cvss_score", "cvss_vector", "confidence_score", "exploit_available",
        "patch_version", "epss_score", "is_false_positive", "severity_override",
        "override_note", "override_by", "override_expires_at",
        "sla_due_date", "resolved_at", "sla_breached",
    ],
    "notification_configs": [
        "id", "user_id", "channel", "target", "trigger", "is_active", "created_at",
    ],
    "scheduled_scans": [
        "id", "user_id", "target", "scan_type", "scan_profile",
        "cron_expr", "is_active", "last_run", "next_run", "created_at",
    ],
}

print("=== SCHEMA DRIFT REPORT ===")
all_missing = {}
for table, required_cols in TARGET_TABLES.items():
    if table not in tables:
        print(f"\n  TABLE MISSING: {table}")
        all_missing[table] = required_cols
        continue
    existing_cols = {c["name"] for c in inspector.get_columns(table)}
    missing = [c for c in required_cols if c not in existing_cols]
    if missing:
        print(f"\n  {table}: MISSING COLUMNS: {missing}")
        all_missing[table] = missing
    else:
        print(f"\n  {table}: OK (all required columns present)")

print()
print("=== CURRENT scan_jobs COLUMNS ===")
if "scan_jobs" in tables:
    for col in inspector.get_columns("scan_jobs"):
        print(f"  {col['name']:30s} {col['type']}")

print()
print("=== CURRENT assets COLUMNS ===")
if "assets" in tables:
    for col in inspector.get_columns("assets"):
        print(f"  {col['name']:30s} {col['type']}")
