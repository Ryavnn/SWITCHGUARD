from database.db import engine
from sqlalchemy import text

sql_commands = [
    # vulnerabilities table
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cve_id VARCHAR;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cwe_id VARCHAR;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss_score FLOAT;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss_vector VARCHAR;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS confidence_score FLOAT DEFAULT 0.5;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS exploit_available BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS patch_version VARCHAR;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_summary TEXT;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_impact TEXT;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_remediation TEXT;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_confidence FLOAT DEFAULT 0.0;",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_generated_at TIMESTAMP;",

    # assets table
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS criticality VARCHAR DEFAULT 'Medium';",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS environment VARCHAR DEFAULT 'Production';",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '{}';",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS internet_exposed BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS business_owner VARCHAR;",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP;",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP;",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS tenant_id VARCHAR REFERENCES tenants(id);"
]

with engine.connect() as conn:
    for cmd in sql_commands:
        try:
            print(f"Executing: {cmd}")
            conn.execute(text(cmd))
            conn.commit()
        except Exception as e:
            print(f"ERROR: {e}")
            conn.rollback()

print("Schema migration script finished.")
