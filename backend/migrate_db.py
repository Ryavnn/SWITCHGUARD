"""
Phase 2 Schema Migration — Safe Column Additions
=================================================
Adds all Phase 2 columns that are present in ORM models
but absent in the live PostgreSQL database.

Affected tables:
  - scan_jobs:        scan_profile, use_ajax, error_detail
  - assets:           criticality, environment, tags, internet_exposed,
                      business_owner, first_seen, last_seen
  - vulnerabilities:  epss_score, is_false_positive, severity_override,
                      override_note, override_by, override_expires_at,
                      sla_due_date, resolved_at, sla_breached

Rules:
  - Uses IF NOT EXISTS to make every ALTER idempotent
  - Supplies safe backward-compatible DEFAULT values for every column
  - Preserves all existing rows
  - Can be re-run safely if interrupted
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import text, inspect as sa_inspect
from database.db import engine


MIGRATIONS = [
    # ── scan_jobs ──────────────────────────────────────────────────────────────
    ("scan_jobs", "scan_profile",  "VARCHAR(50)  NOT NULL DEFAULT 'standard'"),
    ("scan_jobs", "use_ajax",      "BOOLEAN      NOT NULL DEFAULT FALSE"),
    ("scan_jobs", "error_detail",  "TEXT"),           # nullable, no default needed

    # ── assets ─────────────────────────────────────────────────────────────────
    ("assets", "criticality",       "VARCHAR(20)  NOT NULL DEFAULT 'medium'"),
    ("assets", "environment",       "VARCHAR(30)  NOT NULL DEFAULT 'unknown'"),
    ("assets", "tags",              "TEXT"),           # JSON array stored as text
    ("assets", "internet_exposed",  "BOOLEAN      NOT NULL DEFAULT FALSE"),
    ("assets", "business_owner",    "VARCHAR(255)"),
    ("assets", "first_seen",        "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"),
    ("assets", "last_seen",         "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"),

    # ── vulnerabilities ────────────────────────────────────────────────────────
    ("vulnerabilities", "epss_score",          "FLOAT"),
    ("vulnerabilities", "is_false_positive",   "BOOLEAN NOT NULL DEFAULT FALSE"),
    ("vulnerabilities", "severity_override",   "VARCHAR(50)"),
    ("vulnerabilities", "override_note",       "TEXT"),
    ("vulnerabilities", "override_by",         "VARCHAR(36)"),   # user UUID
    ("vulnerabilities", "override_expires_at", "TIMESTAMP WITHOUT TIME ZONE"),
    ("vulnerabilities", "sla_due_date",        "TIMESTAMP WITHOUT TIME ZONE"),
    ("vulnerabilities", "resolved_at",         "TIMESTAMP WITHOUT TIME ZONE"),
    ("vulnerabilities", "sla_breached",        "BOOLEAN NOT NULL DEFAULT FALSE"),

    # ── cve_cache ──────────────────────────────────────────────────────────────
    # These columns exist in the ORM model but were never migrated, causing
    # UndefinedColumn errors that poison the entire scan session transaction.
    ("cve_cache", "epss_score",       "FLOAT"),
    ("cve_cache", "cvss_vector",      "VARCHAR(100)"),
    ("cve_cache", "cwe_id",           "VARCHAR(50)"),
    ("cve_cache", "exploit_available","BOOLEAN NOT NULL DEFAULT FALSE"),
    ("cve_cache", "cve_id",           "VARCHAR(50)"),
    ("cve_cache", "description",      "TEXT"),
    ("cve_cache", "cvss_score",       "FLOAT"),

    # ── users ──────────────────────────────────────────────────────────────────
    ("users", "mfa_enabled",  "BOOLEAN NOT NULL DEFAULT FALSE"),
    ("users", "mfa_secret",   "VARCHAR(100)"),    # TOTP secret
    ("users", "last_login",   "TIMESTAMP WITHOUT TIME ZONE"),
    ("users", "tenant_id",    "VARCHAR(36)"),

    # ── Phase 3: AI & Multi-tenancy ───────────────────────────────────────────
    ("scan_jobs", "tenant_id", "VARCHAR(36)"),
    ("assets",    "tenant_id", "VARCHAR(36)"),
    ("reports",   "tenant_id", "VARCHAR(36)"),
    ("audit_logs", "tenant_id", "VARCHAR(36)"),

    ("vulnerabilities", "tenant_id",          "VARCHAR(36)"),
    ("vulnerabilities", "ai_summary",        "TEXT"),
    ("vulnerabilities", "ai_impact",         "TEXT"),
    ("vulnerabilities", "ai_remediation",    "TEXT"),
    ("vulnerabilities", "ai_confidence",     "FLOAT DEFAULT 0.0"),
    ("vulnerabilities", "ai_generated_at",   "TIMESTAMP WITHOUT TIME ZONE"),
    ("vulnerabilities", "kev_status",        "BOOLEAN DEFAULT FALSE"),
    ("vulnerabilities", "metasploit_module", "VARCHAR(255)"),
    ("vulnerabilities", "exploit_db_id",     "VARCHAR(50)"),
    ("vulnerabilities", "ransomware_related","BOOLEAN DEFAULT FALSE"),
    ("vulnerabilities", "threat_actor_tags", "TEXT"),
    ("vulnerabilities", "priority_score",    "FLOAT DEFAULT 0.0"),
    ("vulnerabilities", "remediation_rank",  "INTEGER"),
    ("vulnerabilities", "patch_urgency",     "VARCHAR(20) DEFAULT 'Standard'"),
    ("vulnerabilities", "assigned_owner",    "VARCHAR(255)"),
]

NEW_TABLES = [
    """
    CREATE TABLE IF NOT EXISTS tenants (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        slug VARCHAR(255) UNIQUE NOT NULL,
        plan VARCHAR(20) DEFAULT 'free',
        branding_json TEXT,
        created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tenant_api_tokens (
        id VARCHAR(36) PRIMARY KEY,
        tenant_id VARCHAR(36) REFERENCES tenants(id),
        token_hash VARCHAR(255),
        label VARCHAR(255),
        created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
        last_used TIMESTAMP WITHOUT TIME ZONE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS suppression_rules (
        id VARCHAR(36) PRIMARY KEY,
        tenant_id VARCHAR(36) REFERENCES tenants(id),
        pattern TEXT NOT NULL,
        match_field VARCHAR(50) DEFAULT 'title',
        scope VARCHAR(50) DEFAULT 'global',
        expires_at TIMESTAMP WITHOUT TIME ZONE,
        created_by VARCHAR(255),
        created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS attack_chains (
        id VARCHAR(36) PRIMARY KEY,
        job_id VARCHAR(36) REFERENCES scan_jobs(job_id),
        tenant_id VARCHAR(36) REFERENCES tenants(id),
        chain_risk_score FLOAT DEFAULT 0.0,
        path_nodes TEXT,
        exploit_path_summary TEXT,
        blast_radius VARCHAR(20),
        lateral_movement_score FLOAT DEFAULT 0.0,
        created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS remediation_comments (
        id VARCHAR(36) PRIMARY KEY,
        vuln_id VARCHAR(36) REFERENCES vulnerabilities(vuln_id),
        user_id VARCHAR(36) REFERENCES users(id),
        tenant_id VARCHAR(36) REFERENCES tenants(id),
        comment TEXT NOT NULL,
        created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
    )
    """
]


def migrate():
    print("=" * 60)
    print("  SwitchGuard Phase 3 — Schema Migration")
    print("=" * 60)

    inspector = sa_inspect(engine)

    with engine.begin() as conn:   # auto-commit on success, auto-rollback on error
        for table, column, col_def in MIGRATIONS:
            # Check if column already exists (idempotent guard)
            existing = {c["name"] for c in inspector.get_columns(table)} \
                       if table in inspector.get_table_names() else set()

            if column in existing:
                print(f"  SKIP   {table}.{column} (already exists)")
                continue

            sql = f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {col_def}"
            try:
                conn.execute(text(sql))
                print(f"  ADD    {table}.{column}  [{col_def.split()[0]}]")
            except Exception as e:
                print(f"  ERROR  {table}.{column}: {e}")
                raise   # re-raise to trigger rollback of the whole transaction

    print()
    print("  Ensuring new tables exist...")
    with engine.begin() as conn:
        for sql in NEW_TABLES:
            conn.execute(text(sql))
    
    print("  Ensuring Default Tenant exists...")
    default_tenant_id = "default-tenant-0000"
    with engine.begin() as conn:
        conn.execute(text(f"""
            INSERT INTO tenants (id, name, slug, plan)
            VALUES ('{default_tenant_id}', 'Default Tenant', 'default', 'enterprise')
            ON CONFLICT (slug) DO NOTHING
        """))
        
        # Migrate orphaned rows
        tables_to_migrate = ["users", "scan_jobs", "assets", "reports", "audit_logs", "vulnerabilities"]
        for table in tables_to_migrate:
            res = conn.execute(text(f"UPDATE {table} SET tenant_id = '{default_tenant_id}' WHERE tenant_id IS NULL"))
            if res.rowcount > 0:
                print(f"  MIGRATE {table}: Assigned {res.rowcount} rows to Default Tenant")

    print()
    print("  Migration complete. Run inspect_schema.py to verify.")
    print("=" * 60)


if __name__ == "__main__":
    migrate()
