import sys
import os
import json
import uuid

# Add backend to path
sys.path.append(os.getcwd())

from database.db import SessionLocal, engine
from database import models
from services import parsers, report_service

def verify():
    db = SessionLocal()
    job_id = str(uuid.uuid4())
    user_id = None
    
    print(f"Creating mock job: {job_id}")
    
    # 1. Create a dummy job with raw results in the bare list format
    mock_alerts = [
        {"alert": "XSS", "risk": "High", "url": "https://example.com/foo", "confidence": "3", "description": "XSS test", "evidence": "<script>"},
        {"alert": "Insecure Header", "risk": "Low", "url": "https://example.com/", "confidence": "2", "description": "Missing header"}
    ]
    
    job = models.ScanJob(
        job_id=job_id,
        user_id=user_id,
        target="https://example.com",
        scan_type="web",
        status="completed",
        raw_results=json.dumps(mock_alerts)
    )
    db.add(job)
    db.commit()

    print("--- Testing Parser ---")
    # 2. Test Parser
    parsers.parse_zap_results(job_id, mock_alerts, db, user_id=user_id)
    
    asset_count = db.query(models.Asset).filter_by(job_id=job_id).count()
    vuln_count = db.query(models.VulnerabilityInstance).filter_by(job_id=job_id).count()
    
    print(f"Assets found: {asset_count} (Expected: 1)")
    print(f"Vulns found: {vuln_count} (Expected: 2)")
    
    if asset_count == 1 and vuln_count == 2:
        print("[SUCCESS] Parser Test Passed")
    else:
        print("[FAILURE] Parser Test Failed")

    print("--- Testing Report Data Fetch ---")
    # 3. Test Report Service Fetch
    data = report_service.fetch_report_data(job_id, db)
    
    print(f"Report Data total_vulns: {data['metrics']['total_vulns']}")
    print(f"Report Data total_assets: {data['metrics']['total_assets']}")
    
    if data['metrics']['total_vulns'] == 2 and data['metrics']['total_assets'] == 1:
        print("[SUCCESS] Report Service Fetch Passed")
    else:
        print("[FAILURE] Report Service Fetch Failed")

    # Cleanup
    db.query(models.VulnerabilityInstance).filter_by(job_id=job_id).delete()
    db.query(models.Asset).filter_by(job_id=job_id).delete()
    db.query(models.ScanJob).filter_by(job_id=job_id).delete()
    db.commit()
    db.close()

if __name__ == "__main__":
    verify()
