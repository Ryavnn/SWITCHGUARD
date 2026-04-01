from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text as sql_text
from database import models
from database.db import SessionLocal, engine
from services import parsers, report_service
from scanners import nmap_scanner, zap_scanner
from scanners.zap_scanner import is_zap_running
from pydantic import BaseModel, EmailStr
import uuid
import json
import logging
from routes import auth_routes, ws_routes, admin_routes
import auth
import nmap as nmap_lib


# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="SwitchGuard API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables on startup
models.Base.metadata.create_all(bind=engine)

# Seed default roles if they don't exist
with SessionLocal() as db:
    for r_name in ["Admin", "Analyst", "User"]:
        if not db.query(models.Role).filter_by(name=r_name).first():
            db.add(models.Role(name=r_name))
    db.commit()

# ── Request models ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str

# ── DB dependency ──────────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ── Mount Modular Routers ──────────────────────────────────────────────────────
app.include_router(auth_routes.router)
app.include_router(admin_routes.router)
app.include_router(ws_routes.router)


# ── Root ───────────────────────────────────────────────────────────────────────

@app.get("/")
def read_root():
    return {"message": "SwitchGuard Backend is Online"}


# ── Network scan ───────────────────────────────────────────────────────────────

@app.post("/api/scan/network")
def run_network_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    job_id = str(uuid.uuid4())
    job = models.ScanJob(
        job_id=job_id,
        user_id=current_user.id,
        target=request.target,
        scan_type="network",
        status="running",
    )
    db.add(job)
    db.commit()
    logger.info("Network scan job %s created for target %r (user: %s)", job_id, request.target, current_user.id)

    def task_wrapper():
        with SessionLocal() as session:
            try:
                logger.info("[%s] Starting Nmap scan on %r", job_id, request.target)
                scanner = nmap_scanner.NmapScanner()
                raw_data = scanner.run_scan(request.target)

                scan_job = session.query(models.ScanJob).filter_by(job_id=job_id).first()
                if not scan_job:
                    logger.error("[%s] ScanJob record vanished from DB", job_id)
                    return

                if scan_job.status == "cancelled":
                    logger.info("[%s] Job was cancelled — discarding results.", job_id)
                    return

                try:
                    scan_job.raw_results = json.dumps(raw_data)
                except TypeError as te:
                    logger.error("[%s] JSON serialisation failed: %s", job_id, te)
                    scan_job.raw_results = json.dumps({"error": "Serialisation failed", "detail": str(te)})

                if raw_data and raw_data.get("scan"):
                    parsers.parse_nmap_results(job_id, raw_data, session, user_id=current_user.id)
                    host_count = len(raw_data["scan"])
                    logger.info("[%s] Nmap results parsed — %d host(s) in DB.", job_id, host_count)
                else:
                    logger.warning("[%s] Nmap returned empty scan result for %r.", job_id, request.target)

                scan_job.status = "completed"
                session.commit()
                logger.info("[%s] Network scan completed.", job_id)
                
                # Auto-generate reports
                try:
                    report_service.auto_generate_reports(job_id, scan_job.user_id, session)
                    logger.info("[%s] Reports generated successfully.", job_id)
                except Exception as rpt_err:
                    logger.error("[%s] Report generation failed: %s", job_id, rpt_err)

                import asyncio
                asyncio.run(ws_routes.manager.broadcast({"type": "SCAN_COMPLETED", "job_id": job_id, "scan_type": "network"}))

            except Exception as e:
                logger.error("[%s] Network scan FAILED: %s", job_id, e, exc_info=True)
                session.rollback()
                scan_job = session.query(models.ScanJob).filter_by(job_id=job_id).first()
                if scan_job and scan_job.status != "cancelled":
                    scan_job.status = "failed"
                    scan_job.raw_results = json.dumps({"fatal_error": str(e)})
                    session.commit()

    background_tasks.add_task(task_wrapper)
    return {"message": "Scan started", "job_id": job_id}


# ── Web scan ───────────────────────────────────────────────────────────────────

@app.post("/api/scan/web")
def run_web_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    # ── Pre-flight: confirm ZAP is actually running before queuing the job ──
    if not is_zap_running():
        raise HTTPException(
            status_code=503,
            detail=(
                "OWASP ZAP is not running. "
                "Start ZAP in daemon mode on port 8080 before triggering a web scan. "
                "Command: zap.bat -daemon -port 8080 -config api.key=12345 "
                "-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"
            ),
        )

    job_id = str(uuid.uuid4())
    job = models.ScanJob(
        job_id=job_id,
        user_id=current_user.id,
        target=request.target,
        scan_type="web",
        status="running",
    )
    db.add(job)
    db.commit()
    logger.info("Web scan job %s created for target %r (user: %s)", job_id, request.target, current_user.id)

    def task_wrapper():
        with SessionLocal() as session:
            try:
                logger.info("[%s] Starting ZAP scan on %r", job_id, request.target)
                scanner = zap_scanner.ZapScanner(request.target)

                # Build a cancellation predicate that checks the DB
                def is_cancelled():
                    fresh = session.query(models.ScanJob).filter_by(job_id=job_id).first()
                    return fresh is not None and fresh.status == "cancelled"

                # Spider + Active Scan via the ZapScanner helper methods
                results = scanner.run_full_scan(cancellation_check=is_cancelled)

                scan_job = session.query(models.ScanJob).filter_by(job_id=job_id).first()
                if not scan_job:
                    logger.error("[%s] ScanJob record vanished from DB", job_id)
                    return

                if scan_job.status == "cancelled":
                    logger.info("[%s] Job was cancelled — discarding ZAP results.", job_id)
                    return

                try:
                    scan_job.raw_results = json.dumps(results)
                except TypeError as te:
                    logger.error("[%s] JSON serialisation failed: %s", job_id, te)
                    scan_job.raw_results = json.dumps({"error": "Serialisation failed", "detail": str(te)})

                if results:
                    parsers.parse_zap_results(job_id, results, session, user_id=current_user.id)
                    logger.info("[%s] ZAP results parsed — %d alert(s) in DB.", job_id, len(results))
                else:
                    logger.info("[%s] ZAP returned zero alerts for %r.", job_id, request.target)

                scan_job.status = "completed"
                session.commit()
                logger.info("[%s] Web scan completed.", job_id)
                
                # Auto-generate reports
                try:
                    report_service.auto_generate_reports(job_id, scan_job.user_id, session)
                    logger.info("[%s] Reports generated successfully.", job_id)
                except Exception as rpt_err:
                    logger.error("[%s] Report generation failed: %s", job_id, rpt_err)

                import asyncio
                asyncio.run(ws_routes.manager.broadcast({"type": "SCAN_COMPLETED", "job_id": job_id, "scan_type": "web"}))

            except Exception as e:
                logger.error("[%s] Web scan FAILED: %s", job_id, e, exc_info=True)
                session.rollback()
                scan_job = session.query(models.ScanJob).filter_by(job_id=job_id).first()
                if scan_job and scan_job.status != "cancelled":
                    scan_job.status = "failed"
                    scan_job.raw_results = json.dumps({"fatal_error": str(e)})
                    session.commit()

    background_tasks.add_task(task_wrapper)
    return {"message": "Web scan started", "job_id": job_id}


# ── Jobs ───────────────────────────────────────────────────────────────────────

@app.get("/api/jobs")
def get_jobs(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    query = db.query(
        models.ScanJob.job_id,
        models.ScanJob.target,
        models.ScanJob.status,
        models.ScanJob.scan_type,
        models.ScanJob.created_at,
    )
    
    # Isolate strictly to the owner unless they are Admin or Analyst (platform wide read)
    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role not in ["Admin", "Analyst"]:
        query = query.filter(models.ScanJob.user_id == current_user.id)
        
    jobs = query.order_by(models.ScanJob.created_at.desc()).all()

    return [
        {
            "job_id": j.job_id,
            "target": j.target,
            "status": j.status,
            "scan_type": j.scan_type,
            "created_at": j.created_at.isoformat() if j.created_at else None,
        }
        for j in jobs
    ]


@app.get("/api/jobs/{job_id}")
def get_job_details(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    job = db.query(models.ScanJob).filter(models.ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role not in ["Admin", "Analyst"] and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to view this scan")


    assets = db.query(models.Asset).filter(models.Asset.job_id == job_id).all()
    vulns  = db.query(models.VulnerabilityInstance).filter(
        models.VulnerabilityInstance.job_id == job_id
    ).all()

    return {"job": job, "assets": assets, "vulnerabilities": vulns}


@app.patch("/api/jobs/{job_id}/cancel")
def cancel_job(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    """
    Marks a running/pending scan job as cancelled.
    FastAPI BackgroundTasks cannot be interrupted mid-execution; the flag is
    checked inside the scan loop and results are discarded on completion.
    """
    job = db.query(models.ScanJob).filter(models.ScanJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role not in ["Admin"] and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to cancel this scan")

    if job.status not in ("running", "pending"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel a job with status '{job.status}'. Only running or pending jobs can be cancelled.",
        )

    job.status = "cancelled"
    db.commit()
    logger.info("Job %s marked as cancelled by user %s.", job_id, current_user.id)
    return {"message": "Job cancelled successfully", "job_id": job_id}


# ── Dashboard Logic ────────────────────────────────────────────────────────────

from sqlalchemy import func

@app.get("/api/dashboard/me")
def get_dashboard_metrics(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user)
):
    user_role = current_user.roles[0].name if current_user.roles else "User"
    is_global = user_role in ["Admin", "Analyst"]

    # Scans Query
    scans_q = db.query(models.ScanJob)
    if not is_global:
        scans_q = scans_q.filter(models.ScanJob.user_id == current_user.id)
    total_scans = scans_q.count()

    # Assets Query
    assets_q = db.query(models.Asset)
    if not is_global:
        assets_q = assets_q.filter(models.Asset.user_id == current_user.id)
    total_assets = assets_q.count()

    # Vulnerabilities Query
    vulns_q = db.query(models.VulnerabilityInstance)
    if not is_global:
        vulns_q = vulns_q.filter(models.VulnerabilityInstance.user_id == current_user.id)
    
    total_vulns = vulns_q.count()
    critical_vulns = vulns_q.filter(models.VulnerabilityInstance.severity.in_(["High", "Critical"])).count()

    # Calculate basic risk score directly
    risk_score = 0
    if total_assets > 0:
        risk_score = min(100, int((critical_vulns * 10 + total_vulns * 2) / total_assets))

    # Recent activity
    recent_q = db.query(models.ScanJob)
    if not is_global:
        recent_q = recent_q.filter(models.ScanJob.user_id == current_user.id)
    recent_scans = recent_q.order_by(models.ScanJob.created_at.desc()).limit(5).all()

    return {
        "metrics": {
            "total_scans": total_scans,
            "total_assets": total_assets,
            "total_vulnerabilities": total_vulns,
            "critical_findings": critical_vulns,
            "risk_score": risk_score
        },
        "recent_activity": [
            {
                "id": s.job_id,
                "target": s.target,
                "status": s.status,
                "type": s.scan_type,
                "date": s.created_at.isoformat() if s.created_at else None
            } for s in recent_scans
        ]
    }



# ── Reports ────────────────────────────────────────────────────────────────────

from fastapi.responses import FileResponse
import os

@app.get("/api/reports/{scan_id}/{file_type}")
def download_report(
    scan_id: str,
    file_type: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if file_type not in ["csv", "pdf"]:
        raise HTTPException(status_code=400, detail="Invalid report type. Supported: csv, pdf")

    # Fetch report metadata
    report_record = db.query(models.Report).filter(
        models.Report.scan_id == scan_id, 
        models.Report.file_type == file_type
    ).first()

    if not report_record:
        raise HTTPException(status_code=404, detail="Report not found or not generated yet")

    # Verify authorization (Ownership or Admin)
    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role not in ["Admin"] and report_record.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized access to report")

    file_path = report_record.file_path
    
    # Check physical file
    if not os.path.exists(file_path):
        logger.error("Report physical file missing for %s", file_path)
        raise HTTPException(status_code=404, detail="File missing on server")

    return FileResponse(
        path=file_path,
        media_type="application/pdf" if file_type == "pdf" else "text/csv",
        filename=f"SwitchGuard_Report_{scan_id}.{file_type}"
    )

            
# ── Health check ───────────────────────────────────────────────────────────────

NMAP_SEARCH_PATH = (
    "nmap",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
)

@app.get("/api/health")
def health_check(db: Session = Depends(get_db)):
    """Real-time health of core platform components — no auth required."""
    # Database
    db_ok = False
    db_error = None
    try:
        db.execute(sql_text("SELECT 1"))
        db_ok = True
    except Exception as e:
        db_error = str(e)
        logger.warning("Health check: DB unreachable — %s", e)

    # Nmap
    nmap_ok = False
    nmap_version = None
    try:
        nm = nmap_lib.PortScanner(nmap_search_path=NMAP_SEARCH_PATH)
        nmap_version = str(nm.nmap_version())
        nmap_ok = True
    except Exception:
        pass

    # ZAP
    zap_ok = is_zap_running()

    return {
        "backend":      True,
        "database":     db_ok,
        "database_error": db_error,
        "nmap":         nmap_ok,
        "nmap_version": nmap_version,
        "zap":          zap_ok,
    }