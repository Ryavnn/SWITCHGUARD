from sqlalchemy import text as sql_text
from database.db import SessionLocal, engine
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_users_table():
    """Injects missing columns into the users table to match the current models.py."""
    
    # 1. Columns to add (name, type, default_val)
    missing_columns = [
        ("is_active", "BOOLEAN", "TRUE"),
        ("mfa_enabled", "BOOLEAN", "FALSE"),
        ("last_login", "TIMESTAMP", "NULL"),
    ]
    
    with engine.connect() as conn:
        logger.info("Starting schema reconciliation for 'users' table...")
        
        for col_name, col_type, default in missing_columns:
            try:
                # Check if column exists first to avoid error on retry
                check_sql = sql_text(f"SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='{col_name}'")
                exists = conn.execute(check_sql).fetchone()
                
                if not exists:
                    logger.info(f"  Adding column '{col_name}' ({col_type})...")
                    alter_sql = sql_text(f"ALTER TABLE users ADD COLUMN {col_name} {col_type} DEFAULT {default}")
                    conn.execute(alter_sql)
                    conn.commit()
                else:
                    logger.info(f"  Column '{col_name}' already exists.")
                    
            except Exception as e:
                logger.error(f"  Failed to add column '{col_name}': {e}")
                conn.rollback()

        logger.info("Schema reconciliation complete.")

if __name__ == "__main__":
    fix_users_table()
