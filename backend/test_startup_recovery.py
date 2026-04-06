"""
Startup Recovery Test
=====================
1. Creates a fake 'running' job
2. Simulates a restart by calling _recover_stale_jobs()
3. Verifies the job becomes 'failed' with error_detail populated
4. Verifies no crash occurs
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db import SessionLocal
from database import models
from database.db import engine
# Bootstrap tables (safe if already exist)
models.Base.metadata.create_all(bind=engine)

import uuid
from datetime import datetime


def test_recovery():
    job_id = str(uuid.uuid4())

    # Step 1: Insert a fake 'running' job
    with SessionLocal() as db:
        fake_job = models.ScanJob(
            job_id=job_id,
            user_id=None,
            target="test-recovery-target",
            scan_type="network",
            scan_profile="standard",
            status="running",
        )
        db.add(fake_job)
        db.commit()
        print(f"[TEST] Created fake running job: {job_id}")

    # Step 2: Import and call the recovery function
    from main import _recover_stale_jobs, _detect_schema_drift
    drift = _detect_schema_drift()
    if drift:
        print(f"[FAIL] Schema drift still present: {drift}")
        sys.exit(1)
    print("[TEST] No schema drift detected — safe to run recovery")

    _recover_stale_jobs()

    # Step 3: Verify results
    with SessionLocal() as db:
        job = db.query(models.ScanJob).filter_by(job_id=job_id).first()
        assert job is not None, "Job not found after recovery"
        assert job.status == "failed", f"Expected 'failed', got '{job.status}'"
        assert job.error_detail is not None, "error_detail should be populated"
        print(f"[PASS] Job status = '{job.status}'")
        print(f"[PASS] error_detail = '{job.error_detail}'")

        # Cleanup
        db.delete(job)
        db.commit()
        print("[TEST] Test job cleaned up.")

    print()
    print("="*50)
    print("  ALL STARTUP RECOVERY TESTS PASSED")
    print("="*50)


if __name__ == "__main__":
    test_recovery()
