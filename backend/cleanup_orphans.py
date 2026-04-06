import sys
import os
from sqlalchemy.orm import Session

# Add current directory to path
sys.path.append(os.getcwd())

from database.db import SessionLocal
from database import models

def cleanup_orphans():
    db: Session = SessionLocal()
    print("--- Starting Orphan Cleanup ---")
    
    try:
        links = db.query(models.CorrelationLink).all()
        orphans_removed = 0
        
        for link in links:
            # Check if related vuln and service still exist
            vuln = db.query(models.VulnerabilityInstance).filter_by(vuln_id=link.vuln_id).first()
            svc  = db.query(models.Service).filter_by(service_id=link.service_id).first()
            
            if not vuln or not svc:
                print(f"  Removing orphaned link: {link.id} (Job: {link.job_id})")
                db.delete(link)
                orphans_removed += 1
        
        db.commit()
        print(f"--- Cleanup Complete. {orphans_removed} orphans removed. ---")
        
    except Exception as e:
        print(f"Error during cleanup: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    cleanup_orphans()
