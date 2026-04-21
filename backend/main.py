"""
SwitchGuard Backend — main.py  (Phase 1 + Phase 2 complete)
=============================================================

Phase 1 Fixes applied:
  1. asyncio.run() replaced with asyncio.run_coroutine_threadsafe()
  2. shutil imported — health endpoint works
  3. Session rollback boundary fixed
  4. Report generation isolated — scan results never lost
  5. Input validation on ScanRequest.target
  6. Rate limiting via slowapi
  7. Startup self-test with schema drift detection
  8. Stale 'running' job recovery — now SCHEMA-DRIFT-SAFE
  9. Defensive exception logging with tracebacks

Phase 2 Features added:
  - scan_profile selection (fast/standard/deep/udp/vuln)
  - Nuclei + Nikto scan endpoints
  - JSON / executive PDF / diff report endpoints
  - Severity override + false-positive endpoints
  - Asset inventory + enrichment endpoint
  - Notification + Schedule routers mounted
  - Schema drift guardrails (startup warning + safe recovery)
"""

import asyncio
import json
import logging
import os
import re
import shutil
import traceback
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

import nmap as nmap_lib
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import func, text as sql_text
from sqlalchemy.orm import Session, joinedload

import auth
import schemas
from database.db import engine, SessionLocal, get_db
from database import models
from scanners import nmap_scanner, zap_scanner
from services import parsers, report_service, zap_service, ollama_service, tenant_service
from services.notification_service import NotificationService
from routes import admin_routes, auth_routes, notification_routes, schedule_routes, ws_routes, tenant_routes, chain_routes, analytics_routes, portal_routes

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ── Rate Limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Nmap search paths ──────────────────────────────────────────────────────────
NMAP_SEARCH_PATH = (
    "nmap",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
)


# ── Lifespan (startup + shutdown) ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(application: FastAPI):
    # ── Startup ────────────────────────────────────────────────────────────────
    logger.info("=== SwitchGuard starting up ===")

    # Create / migrate tables
    models.Base.metadata.create_all(bind=engine)

    # Seed default roles
    with SessionLocal() as db:
        for r_name in ["Admin", "Analyst", "User"]:
            if not db.query(models.Role).filter_by(name=r_name).first():
                db.add(models.Role(name=r_name))
        db.commit()

    # FIX: Recover stale "running" jobs — drift-safe, never crashes startup
    _recover_stale_jobs()

    # Start ZAP daemon — runs in background, does not block startup.
    # ensure_zap_running_async() handles zombie detection, CWD fix, 180s timeout.
    asyncio.create_task(zap_service.ZapService.ensure_zap_running_async())

    # Phase 3: Ollama Health & Tenant Migration
    with SessionLocal() as db:
        tenant_service.TenantService(db).get_or_create_default_tenant()
        ollama_health = ollama_service.OllamaService().health_check()
        logger.info(f"Ollama Health: {ollama_health}")

    # Start APScheduler
    try:
        from services.scheduler_service import start_scheduler
        start_scheduler()
    except Exception as e:
        logger.warning("APScheduler could not start: %s", e)

    # Run startup self-test
    asyncio.create_task(_startup_self_test())

    yield

    # ── Shutdown ───────────────────────────────────────────────────────────────
    logger.info("=== SwitchGuard shutting down ===")
    try:
        from services.scheduler_service import scheduler
        if scheduler.running:
            scheduler.shutdown(wait=False)
    except Exception:
        pass


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="SwitchGuard API", version="2.1.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
app.include_router(auth_routes.router)
app.include_router(admin_routes.router)
app.include_router(ws_routes.router)
app.include_router(notification_routes.router)
app.include_router(schedule_routes.router)
app.include_router(tenant_routes.router)
app.include_router(chain_routes.router)
app.include_router(analytics_routes.router)
app.include_router(portal_routes.router)


# ── DB dependency ──────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Request models ─────────────────────────────────────────────────────────────
_TARGET_RE = re.compile(r'^[\w\.\-\/\:\[\]]+$')


class ScanRequest(BaseModel):
    target:      str
    profile:     str = "standard"   # fast|standard|deep|udp|vuln|custom
    custom_args: str = None
    use_ajax:    bool = False        # use AJAX spider (SPA targets)

    @validator("target")
    def validate_target(cls, v):
        v = v.strip()
        if not v or not _TARGET_RE.match(v):
            raise ValueError(
                "Invalid target. Provide an IP address, hostname, CIDR block, or URL."
            )
        return v

    @validator("profile")
    def validate_profile(cls, v):
        allowed = {"fast", "standard", "deep", "udp", "vuln", "custom"}
        if v not in allowed:
            raise ValueError(f"Invalid profile. Choose from: {allowed}")
        return v


class WebScanRequest(ScanRequest):
    login_url:        str = None
    username:         str = None
    password:         str = None
    session_cookie:   str = None


class VulnOverrideRequest(BaseModel):
    severity_override:  str = None    # override severity
    is_false_positive:  bool = None
    override_note:      str = None


class AssetUpdateRequest(BaseModel):
    criticality:      str = None   # critical|high|medium|low
    environment:      str = None   # prod|staging|internal|unknown
    tags:             str = None   # JSON array string
    internet_exposed: bool = None
    business_owner:   str = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_event_loop() -> asyncio.AbstractEventLoop:
    """Safely get the running event loop (works in both sync and async contexts)."""
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.new_event_loop()


def _broadcast(message: dict):
    """
    FIX: Thread-safe WebSocket broadcast from inside a BackgroundTasks thread.
    asyncio.run() was here before — it crashes inside an existing event loop.
    """
    try:
        loop = _get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(
                ws_routes.manager.broadcast(message), loop
            )
        else:
            loop.run_until_complete(ws_routes.manager.broadcast(message))
    except Exception as e:
        logger.warning("WS broadcast failed: %s", e)


# Required columns that must exist before ORM queries run.
# Used inside _recover_stale_jobs and _startup_self_test.
_REQUIRED_COLUMNS = {
    "scan_jobs":       ["scan_profile", "use_ajax", "error_detail", "tenant_id"],
    "assets":          ["criticality", "environment", "tags", "internet_exposed",
                        "business_owner", "first_seen", "last_seen", "tenant_id"],
    "vulnerabilities": ["epss_score", "is_false_positive", "severity_override",
                        "override_note", "override_by", "sla_due_date", "sla_breached",
                        "cve_id", "cvss_score", "exploit_available", "tenant_id"],
}


def _detect_schema_drift() -> dict:
    """
    Compare live PostgreSQL column names against ORM expectations.
    Returns {table: [missing_col, ...]} for any drift found.
    """
    from sqlalchemy import inspect as sa_inspect
    missing: dict = {}
    try:
        inspector = sa_inspect(engine)
        existing_tables = set(inspector.get_table_names())
        for table, required_cols in _REQUIRED_COLUMNS.items():
            if table not in existing_tables:
                missing[table] = required_cols
                continue
            existing_cols = {c["name"] for c in inspector.get_columns(table)}
            drift = [c for c in required_cols if c not in existing_cols]
            if drift:
                missing[table] = drift
    except Exception as e:
        logger.error("Schema drift detection failed: %s", e)
    return missing


def _recover_stale_jobs():
    """
    On startup, mark any jobs stuck in 'running' as 'failed'.
    SCHEMA-DRIFT-SAFE: checks for required columns BEFORE querying the ORM.
    If columns are missing (migration not yet applied), logs a clear message
    and skips recovery so the API can still start.
    """
    drift = _detect_schema_drift()
    if drift:
        logger.warning(
            "SCHEMA DRIFT DETECTED — skipping stale job recovery to avoid startup crash.\n"
            "  Missing columns: %s\n"
            "  Run: python migrate_db.py",
            drift,
        )
        return

    try:
        with SessionLocal() as db:
            stale = db.query(models.ScanJob).filter_by(status="running").all()
            if stale:
                logger.warning(
                    "Recovering %d stale 'running' job(s) from previous session.",
                    len(stale),
                )
                for job in stale:
                    job.status       = "failed"
                    job.error_detail = "Recovered on restart — previous process crashed."
                db.commit()
                logger.info("Stale job recovery complete.")
    except Exception as e:
        logger.error(
            "Stale job recovery FAILED (non-fatal — API will still start): %s\n%s",
            e, traceback.format_exc(),
        )


async def _startup_self_test():
    """
    Validates all platform dependencies at startup.
    Now includes schema drift detection for early migration warnings.
    """
    await asyncio.sleep(2)   # allow services to initialise
    issues  = []
    warnings = []

    # 1. DB connectivity
    try:
        with SessionLocal() as db:
            db.execute(sql_text("SELECT 1"))
    except Exception as e:
        issues.append(f"❌ Database unreachable: {e}")

    # 2. Schema drift — check all required ORM columns exist in live DB
    drift = _detect_schema_drift()
    if drift:
        for table, cols in drift.items():
            issues.append(
                f"❌ Schema drift in '{table}': missing columns {cols}. "
                f"Run: python migrate_db.py"
            )
    else:
        logger.info("Startup self-test: all required DB columns present.")

    # 3. Nmap
    nmap_ok = any(shutil.which(p) or os.path.exists(p) for p in NMAP_SEARCH_PATH)
    if not nmap_ok:
        issues.append("❌ Nmap not found. Network scans will fail.")

    # 4. ZAP
    if not zap_service.ZapService.is_zap_healthy():
        warnings.append("⚠️  ZAP daemon not running. Web scans will fail until ZAP starts.")

    # 5. Nuclei
    if not shutil.which("nuclei"):
        warnings.append("⚠️  Nuclei not in PATH. Nuclei scans will be skipped.")

    # 6. Nikto
    if not (shutil.which("nikto") or shutil.which("nikto.pl")):
        warnings.append("⚠️  Nikto not in PATH. Nikto scans will be skipped.")

    # 7. APScheduler
    try:
        from services.scheduler_service import scheduler
        if not scheduler.running:
            warnings.append("⚠️  APScheduler is not running. Scheduled scans inactive.")
    except Exception:
        warnings.append("⚠️  APScheduler unavailable.")

    # Report
    if issues:
        logger.error("=== Startup Self-Test: CRITICAL ISSUES ===")
        for issue in issues:
            logger.error("  %s", issue)
    if warnings:
        logger.warning("=== Startup Self-Test: WARNINGS ===")
        for w in warnings:
            logger.warning("  %s", w)
    if not issues and not warnings:
        logger.info("=== Startup Self-Test: ALL SYSTEMS OK ===")


async def _run_scan_task(scan_type: str, target: str, profile: str, user_id: str):
    """
    Reusable internal coroutine for scheduled scans.
    Creates a ScanJob and runs the appropriate scanner.
    """
    with SessionLocal() as session:
        job_id = str(uuid.uuid4())
        job = models.ScanJob(
            job_id=job_id, user_id=user_id,
            target=target, scan_type=scan_type,
            scan_profile=profile, status="running",
        )
        session.add(job)
        session.commit()
        logger.info("Scheduled scan %s started: %s → %s", job_id, scan_type, target)
        # Delegate to the background task helpers below
        if scan_type == "network":
            _network_task(job_id, target, profile, None, user_id)
        elif scan_type == "web":
            _web_task(job_id, target, profile, False, None, None, None, None, user_id)


# ── AI Analysis Task ────────────────────────────────────────────────────────────

def _ai_analyze_task(job_id: str, user_id: str):
    """Background task to summarize high-severity findings using Ollama."""
    from database.db import SessionLocal
    with SessionLocal() as db:
        try:
            vulns = db.query(models.VulnerabilityInstance).filter(
                models.VulnerabilityInstance.job_id == job_id,
                models.VulnerabilityInstance.severity.in_(["Critical", "High"]),
                models.VulnerabilityInstance.ai_summary == None
            ).all()

            if not vulns:
                return

            logger.info("[%s] AI Analysis: Processing %d findings...", job_id, len(vulns))
            ai = ollama_service.OllamaService()
            
            for v in vulns:
                v_dict = {
                    "title": v.title,
                    "description": v.description,
                    "severity": v.severity,
                    "cve_id": v.cve_id,
                    "evidence": v.evidence,
                    "url": v.url
                }
                
                result = ai.summarize_finding(v_dict)
                v.ai_summary = result.get("summary")
                v.ai_impact = result.get("impact")
                v.ai_remediation = result.get("remediation")
                v.ai_confidence = result.get("confidence", 0.0)
                v.ai_generated_at = datetime.utcnow()
                db.commit()
            
            logger.info("[%s] AI Analysis complete.", job_id)
            _broadcast({"type": "AI_ANALYSIS_COMPLETE", "job_id": job_id})
        except Exception as e:
            logger.error("[%s] AI Analysis failed: %s", job_id, e)

@app.get("/api/diagnostics/ollama")
def get_ollama_status(current_user: models.User = Depends(auth.get_current_active_user)):
    """Check local Ollama health status."""
    return ollama_service.OllamaService().health_check()


# ── Network Scan Task ──────────────────────────────────────────────────────────

def _network_task(job_id, target, profile, custom_args, user_id):
    """Worker function that runs inside FastAPI BackgroundTasks."""
    with SessionLocal() as session:
        try:
            _broadcast({"type": "SCAN_RUNNING", "job_id": job_id, "scan_type": "network"})
            logger.info("[%s] Starting Nmap scan on %r (profile=%s)", job_id, target, profile)

            scanner = nmap_scanner.NmapScanner()
            raw_data = scanner.run_profile_scan(target, profile=profile, custom_args=custom_args)

            scan_job = session.query(models.ScanJob).filter_by(job_id=job_id).first()
            if not scan_job or scan_job.status == "cancelled":
                return

            # ── Persist raw results BEFORE parsing (never lost on failure) ──
            try:
                scan_job.raw_results = json.dumps(raw_data)
                session.commit()
            except Exception as re_err:
                logger.warning("[%s] Could not persist raw_results: %s", job_id, re_err)
                session.rollback()

            _broadcast({"type": "SCAN_PARSING", "job_id": job_id})
            if raw_data and raw_data.get("scan"):
                parsers.parse_nmap_results(job_id, raw_data, session, user_id=user_id)

            # Enrichment is non-fatal — never poison the scan job status
            try:
                parsers.enrich_scan_results(job_id, session)
            except Exception as ee:
                logger.warning("[%s] Enrichment skipped (non-fatal): %s", job_id, ee)
                session.rollback()

            # Re-query after parser ops may have modified session state
            scan_job = session.query(models.ScanJob).filter_by(job_id=job_id).first()
            if scan_job and scan_job.status != "cancelled":
                scan_job.status = "completed"
                session.commit()
            logger.info("[%s] Network scan completed.", job_id)

            # Reports (isolated — failures here don't affect scan status)
            try:
                report_service.auto_generate_reports(job_id, user_id, session)
            except Exception as rpe:
                logger.warning("[%s] Report generation skipped (non-fatal): %s", job_id, rpe)

            # Trigger AI Analysis
            _ai_analyze_task(job_id, user_id)

            # Notifications
            try:
                vulns    = session.query(models.VulnerabilityInstance).filter_by(job_id=job_id)
                critical = vulns.filter_by(severity="Critical").count()
                high     = vulns.filter_by(severity="High").count()
                total    = vulns.count()
                NotificationService().notify_scan_complete(
                    job_id, target, "network", critical, high, total, session
                )
            except Exception as ne:
                logger.warning("[%s] Notification failed: %s", job_id, ne)

            _broadcast({
                "type": "SCAN_COMPLETED",
                "job_id": job_id,
                "scan_type": "network",
            })

        except Exception as e:
            logger.error("[%s] Network scan FAILED: %s\n%s", job_id, e, traceback.format_exc())
            err_str = str(e)
            if "nmap" in err_str.lower() or "PortScannerError" in err_str:
                detail = f"Nmap error: {err_str[:500]}"
            elif "timeout" in err_str.lower():
                detail = f"Scan timed out: {err_str[:500]}"
            elif "permission" in err_str.lower() or "denied" in err_str.lower():
                detail = f"Permission denied — try running as administrator: {err_str[:500]}"
            elif "UndefinedColumn" in err_str or "InFailedSqlTransaction" in err_str:
                detail = f"DB schema error (run migrate_db.py): {err_str[:500]}"
            else:
                detail = err_str[:1000]
            try:
                session.rollback()
                failed_job = session.query(models.ScanJob).filter_by(job_id=job_id).first()
                if failed_job:
                    failed_job.status       = "failed"
                    failed_job.error_detail = detail
                    session.commit()
            except Exception as inner:
                logger.error("[%s] Could not mark job as failed: %s", job_id, inner)
            _broadcast({"type": "SCAN_FAILED", "job_id": job_id, "error": detail})


# ── Web Scan Task ──────────────────────────────────────────────────────────────

def _web_task(job_id, target, profile, use_ajax,
              login_url, username, password, session_cookie, user_id):
    with SessionLocal() as session:
        try:
            _broadcast({"type": "SCAN_RUNNING", "job_id": job_id, "scan_type": "web"})
            logger.info("[%s] Starting ZAP scan on %r (profile=%s, ajax=%s)", job_id, target, profile, use_ajax)

            scanner = zap_scanner.ZapScanner(target)

            if login_url and username:
                scanner.configure_form_auth(login_url, username, password)
            elif session_cookie:
                scanner.configure_bearer_auth(session_cookie)

            def is_cancelled():
                fresh = session.query(models.ScanJob).filter_by(job_id=job_id).first()
                return fresh is not None and fresh.status == "cancelled"

            results = scanner.run_full_scan(
                cancellation_check=is_cancelled,
                use_ajax=use_ajax,
            )

            scan_job = session.query(models.ScanJob).filter_by(job_id=job_id).first()
            if not scan_job or scan_job.status == "cancelled":
                return

            scan_job.raw_results = json.dumps(results or [])

            _broadcast({"type": "SCAN_PARSING", "job_id": job_id})
            if results:
                parsers.parse_zap_results(job_id, results, session, user_id=user_id)

            parsers.enrich_scan_results(job_id, session)

            scan_job.status = "completed"
            session.commit()
            logger.info("[%s] Web scan completed.", job_id)

            # Trigger AI Analysis
            _ai_analyze_task(job_id, user_id)

            report_service.auto_generate_reports(job_id, user_id, session)

            try:
                vulns    = session.query(models.VulnerabilityInstance).filter_by(job_id=job_id)
                critical = vulns.filter_by(severity="Critical").count()
                high     = vulns.filter_by(severity="High").count()
                total    = vulns.count()
                NotificationService().notify_scan_complete(
                    job_id, target, "web", critical, high, total, session
                )
            except Exception as ne:
                logger.warning("[%s] Notification failed: %s", job_id, ne)

            _broadcast({
                "type": "SCAN_COMPLETED",
                "job_id": job_id,
                "scan_type": "web",
            })

        except Exception as e:
            logger.error("[%s] Web scan FAILED: %s\n%s", job_id, e, traceback.format_exc())
            try:
                session.rollback()
                failed_job = session.query(models.ScanJob).filter_by(job_id=job_id).first()
                if failed_job:
                    failed_job.status       = "failed"
                    failed_job.error_detail = str(e)[:2000]
                    session.commit()
            except Exception as inner:
                logger.error("[%s] Could not mark job as failed: %s", job_id, inner)
            _broadcast({"type": "SCAN_FAILED", "job_id": job_id, "error": str(e)})


# ── Root ────────────────────────────────────────────────────────────────────────
@app.get("/")
def read_root():
    return {"message": "SwitchGuard API v2.1", "status": "online"}


# ── Network Scan ────────────────────────────────────────────────────────────────
@app.post("/api/scan/network")
@limiter.limit("10/minute")
def run_network_scan(
    request_data: ScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    job_id = str(uuid.uuid4())
    job = models.ScanJob(
        job_id=job_id,
        user_id=current_user.id,
        target=request_data.target,
        scan_type="network",
        scan_profile=request_data.profile,
        status="running",
    )
    db.add(job)
    db.commit()
    logger.info("Network scan job %s created for %r (profile=%s)", job_id, request_data.target, request_data.profile)

    background_tasks.add_task(
        _network_task,
        job_id, request_data.target, request_data.profile,
        request_data.custom_args, current_user.id,
    )
    return {"message": "Scan started", "job_id": job_id}


# ── Web Scan ────────────────────────────────────────────────────────────────────
@app.post("/api/scan/web")
@limiter.limit("5/minute")
def run_web_scan(
    request_data: WebScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if not zap_service.ZapService.is_zap_healthy():
        raise HTTPException(
            status_code=503,
            detail="OWASP ZAP is not running or unreachable. Start ZAP before launching a web scan.",
        )

    job_id = str(uuid.uuid4())
    job = models.ScanJob(
        job_id=job_id,
        user_id=current_user.id,
        target=request_data.target,
        scan_type="web",
        scan_profile=request_data.profile,
        use_ajax=request_data.use_ajax,
        status="running",
    )
    db.add(job)
    db.commit()
    logger.info("Web scan job %s created for %r (ajax=%s)", job_id, request_data.target, request_data.use_ajax)

    background_tasks.add_task(
        _web_task,
        job_id, request_data.target, request_data.profile,
        request_data.use_ajax,
        request_data.login_url, request_data.username,
        request_data.password, request_data.session_cookie,
        current_user.id,
    )
    return {"message": "Web scan started", "job_id": job_id}


# ── Nuclei Scan ─────────────────────────────────────────────────────────────────
@app.post("/api/scan/nuclei")
@limiter.limit("5/minute")
def run_nuclei_scan(
    request_data: ScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    from scanners.nuclei_scanner import NucleiScanner, is_nuclei_installed
    if not is_nuclei_installed():
        raise HTTPException(status_code=503, detail="Nuclei is not installed on this server.")

    job_id = str(uuid.uuid4())
    job = models.ScanJob(
        job_id=job_id, user_id=current_user.id,
        target=request_data.target, scan_type="nuclei",
        scan_profile=request_data.profile, status="running",
    )
    db.add(job)
    db.commit()

    def nuclei_task():
        with SessionLocal() as session:
            try:
                _broadcast({"type": "SCAN_RUNNING", "job_id": job_id, "scan_type": "nuclei"})
                findings = NucleiScanner().run_scan(request_data.target)
                scan_job = session.query(models.ScanJob).filter_by(job_id=job_id).first()
                if not scan_job or scan_job.status == "cancelled":
                    return
                scan_job.raw_results = json.dumps(findings)
                parsers.parse_nuclei_results(job_id, findings, session, user_id=current_user.id)
                parsers.enrich_scan_results(job_id, session)
                scan_job.status = "completed"
                session.commit()
                report_service.auto_generate_reports(job_id, current_user.id, session)
                _broadcast({"type": "SCAN_COMPLETED", "job_id": job_id, "scan_type": "nuclei"})
            except Exception as e:
                logger.error("[%s] Nuclei scan FAILED: %s", job_id, e)
                try:
                    session.rollback()
                    j = session.query(models.ScanJob).filter_by(job_id=job_id).first()
                    if j:
                        j.status = "failed"; j.error_detail = str(e)[:2000]; session.commit()
                except Exception:
                    pass
                _broadcast({"type": "SCAN_FAILED", "job_id": job_id})

    background_tasks.add_task(nuclei_task)
    return {"message": "Nuclei scan started", "job_id": job_id}


# ── Jobs ─────────────────────────────────────────────────────────────────────
@app.get("/api/jobs")
def get_jobs(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    user_role = current_user.roles[0].name if current_user.roles else "User"
    q = db.query(
        models.ScanJob.job_id, models.ScanJob.target,
        models.ScanJob.status, models.ScanJob.scan_type,
        models.ScanJob.scan_profile, models.ScanJob.created_at,
    )
    if user_role not in ["Admin", "Analyst"]:
        q = q.filter(models.ScanJob.user_id == current_user.id)

    return [
        {
            "job_id":       j.job_id,
            "target":       j.target,
            "status":       j.status,
            "scan_type":    j.scan_type,
            "scan_profile": j.scan_profile,
            "created_at":   j.created_at.isoformat() if j.created_at else None,
        }
        for j in q.order_by(models.ScanJob.created_at.desc()).all()
    ]


@app.get("/api/jobs/{job_id}", response_model=schemas.JobDetailResponse)
def get_job_details(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    job = db.query(models.ScanJob).options(
        joinedload(models.ScanJob.assets).joinedload(models.Asset.services),
        joinedload(models.ScanJob.vulnerabilities),
    ).filter(models.ScanJob.job_id == job_id).first()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role not in ["Admin", "Analyst"] and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to view this scan")

    return {
        "job":             job,
        "assets":          job.assets or [],
        "vulnerabilities": job.vulnerabilities or [],
    }


@app.get("/api/jobs/{job_id}/correlation", response_model=schemas.CorrelationResponse)
def get_job_correlation(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    links = db.query(models.CorrelationLink).options(
        joinedload(models.CorrelationLink.vulnerability),
        joinedload(models.CorrelationLink.service).joinedload(models.Service.asset),
    ).filter_by(job_id=job_id).all()

    nodes, edges, seen = [], [], set()
    for idx, link in enumerate(links):
        vuln = link.vulnerability
        svc  = link.service
        if not vuln or not svc or not svc.asset:
            continue
        asset = svc.asset

        if asset.asset_id not in seen:
            nodes.append({
                "id":   asset.asset_id, "type": "asset",
                "data": {"label": f"Host: {asset.ip_address}"},
                "position": {"x": 100, "y": len(seen) * 80},
            })
            seen.add(asset.asset_id)

        svc_id = f"svc_{svc.service_id}"
        if svc_id not in seen:
            nodes.append({
                "id":   svc_id, "type": "service",
                "data": {"label": f"{svc.service_name or 'port'}:{svc.port}"},
                "position": {"x": 350, "y": len(seen) * 80},
            })
            seen.add(svc_id)
            edges.append({"id": f"e_a_s_{idx}", "source": asset.asset_id, "target": svc_id, "animated": True})

        vuln_id = f"vuln_{vuln.vuln_id}"
        if vuln_id not in seen:
            nodes.append({
                "id":   vuln_id, "type": "vulnerability",
                "data": {"label": vuln.title, "severity": vuln.severity},
                "position": {"x": 600, "y": len(seen) * 80},
            })
            seen.add(vuln_id)
            edges.append({
                "id": f"e_s_v_{idx}", "source": svc_id, "target": vuln_id,
                "label": f"Conf: {int((link.confidence or 0.5) * 100)}%", "animated": True,
            })

    return {"nodes": nodes, "edges": edges}


@app.patch("/api/jobs/{job_id}/cancel")
def cancel_job(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    job = db.query(models.ScanJob).filter_by(job_id=job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role not in ["Admin"] and job.user_id != current_user.id:
        raise HTTPException(403, "Not authorized to cancel this scan")
    if job.status not in ("running", "pending"):
        raise HTTPException(400, f"Cannot cancel job with status '{job.status}'")
    job.status = "cancelled"
    db.commit()
    return {"message": "Job cancelled", "job_id": job_id}


# ── Dashboard ──────────────────────────────────────────────────────────────────
@app.get("/api/dashboard/me")
def get_dashboard_metrics(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    user_role = current_user.roles[0].name if current_user.roles else "User"
    is_global = user_role in ["Admin", "Analyst"]

    scans_q = db.query(models.ScanJob)
    if not is_global:
        scans_q = scans_q.filter_by(user_id=current_user.id)
    total_scans = scans_q.count()

    assets_q = db.query(models.Asset)
    if not is_global:
        assets_q = assets_q.filter_by(user_id=current_user.id)
    total_assets = assets_q.count()

    vulns_q = db.query(models.VulnerabilityInstance).filter_by(is_false_positive=False)
    if not is_global:
        vulns_q = vulns_q.filter_by(user_id=current_user.id)

    total_vulns    = vulns_q.count()
    # FIX: case now consistent — "Critical"/"High" not "CRITICAL"/"HIGH"
    critical_vulns = vulns_q.filter(models.VulnerabilityInstance.severity.in_(["Critical", "High"])).count()

    risk_score = 0
    if total_assets > 0:
        risk_score = min(100, int((critical_vulns * 10 + total_vulns * 2) / total_assets))

    recent_q = db.query(models.ScanJob)
    if not is_global:
        recent_q = recent_q.filter_by(user_id=current_user.id)
    recent_scans = recent_q.order_by(models.ScanJob.created_at.desc()).limit(5).all()

    return {
        "metrics": {
            "total_scans":         total_scans,
            "total_assets":        total_assets,
            "total_vulnerabilities": total_vulns,
            "critical_findings":   critical_vulns,
            "risk_score":          risk_score,
        },
        "recent_activity": [
            {
                "id":     s.job_id,
                "target": s.target,
                "status": s.status,
                "type":   s.scan_type,
                "date":   s.created_at.isoformat() if s.created_at else None,
            }
            for s in recent_scans
        ],
    }


# ── Reports ────────────────────────────────────────────────────────────────────
@app.get("/api/reports/{scan_id}/{file_type}")
def download_report(
    scan_id: str,
    file_type: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    allowed = {"csv", "pdf", "json", "pdf_executive"}
    if file_type not in allowed:
        raise HTTPException(400, f"Invalid report type. Allowed: {allowed}")

    report_record = db.query(models.Report).filter_by(
        scan_id=scan_id, file_type=file_type
    ).first()

    if not report_record:
        raise HTTPException(404, "Report not found or not yet generated.")

    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role not in ["Admin"] and report_record.user_id != current_user.id:
        raise HTTPException(403, "Unauthorized")

    if not os.path.exists(report_record.file_path):
        logger.error("Report file missing on disk: %s", report_record.file_path)
        raise HTTPException(404, "Report file missing on server.")

    media_map = {
        "pdf":            "application/pdf",
        "pdf_executive":  "application/pdf",
        "csv":            "text/csv",
        "json":           "application/json",
    }
    ext_map = {"pdf_executive": "pdf"}

    return FileResponse(
        path=report_record.file_path,
        media_type=media_map.get(file_type, "application/octet-stream"),
        filename=f"SwitchGuard_{file_type}_{scan_id[:8]}.{ext_map.get(file_type, file_type)}",
    )


@app.get("/api/reports/diff/{scan_a}/{scan_b}")
def get_diff_report(
    scan_a: str,
    scan_b: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    diff = report_service.generate_diff_report(scan_a, scan_b, db)
    # Serialize vuln objects to dicts for JSON response
    def _v(vuln):
        return {
            "vuln_id":  vuln.vuln_id,
            "title":    vuln.title,
            "severity": (vuln.severity_override or vuln.severity or "Low"),
            "url":      vuln.url,
            "cve_id":   vuln.cve_id,
        }
    return {
        "scan_a":            diff["scan_a"],
        "scan_b":            diff["scan_b"],
        "new_count":         diff["new_count"],
        "resolved_count":    diff["resolved_count"],
        "worsened_count":    diff["worsened_count"],
        "new_findings":      [_v(v) for v in diff["new_findings"]],
        "resolved_findings": [_v(v) for v in diff["resolved_findings"]],
        "worsened_findings": [
            {"before": _v(w["before"]), "after": _v(w["after"])}
            for w in diff["worsened_findings"]
        ],
    }


# ── Vulnerability Management ───────────────────────────────────────────────────
@app.patch("/api/vulnerabilities/{vuln_id}")
def update_vulnerability(
    vuln_id: str,
    req: VulnOverrideRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    """Allow Analyst/Admin to override severity or suppress a finding."""
    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role not in ["Admin", "Analyst"]:
        raise HTTPException(403, "Analyst or Admin role required")

    vuln = db.query(models.VulnerabilityInstance).filter_by(vuln_id=vuln_id).first()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")

    if req.severity_override is not None:
        vuln.severity_override = req.severity_override.title()
        vuln.override_by       = current_user.id
    if req.is_false_positive is not None:
        vuln.is_false_positive = req.is_false_positive
        vuln.override_by       = current_user.id
    if req.override_note is not None:
        vuln.override_note = req.override_note

    db.commit()

    # Audit log
    log = models.AuditLog(
        user_id=current_user.id,
        action="vuln_override",
        target_id=vuln_id,
        details=json.dumps({
            "severity_override": req.severity_override,
            "is_false_positive": req.is_false_positive,
        }),
    )
    db.add(log)
    db.commit()

    return {"message": "Vulnerability updated", "vuln_id": vuln_id}


# ── Asset Management ────────────────────────────────────────────────────────────
@app.get("/api/assets")
def get_assets(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    user_role = current_user.roles[0].name if current_user.roles else "User"
    q = db.query(models.Asset)
    if user_role not in ["Admin", "Analyst"]:
        q = q.filter_by(user_id=current_user.id)
    assets = q.order_by(models.Asset.last_seen.desc()).limit(200).all()
    return [
        {
            "asset_id":       a.asset_id,
            "ip_address":     a.ip_address,
            "hostname":       a.hostname,
            "os_detected":    a.os_detected,
            "criticality":    a.criticality,
            "environment":    a.environment,
            "tags":           a.tags,
            "internet_exposed": a.internet_exposed,
            "business_owner": a.business_owner,
            "job_id":         a.job_id,
            "port_count":     len(a.services),
            "last_seen":      a.last_seen.isoformat() if a.last_seen else None,
        }
        for a in assets
    ]


@app.patch("/api/assets/{asset_id}")
def update_asset(
    asset_id: str,
    req: AssetUpdateRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    asset = db.query(models.Asset).filter_by(asset_id=asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role not in ["Admin", "Analyst"] and asset.user_id != current_user.id:
        raise HTTPException(403, "Not authorized")

    if req.criticality      is not None: asset.criticality      = req.criticality
    if req.environment       is not None: asset.environment       = req.environment
    if req.tags              is not None: asset.tags              = req.tags
    if req.internet_exposed  is not None: asset.internet_exposed  = req.internet_exposed
    if req.business_owner    is not None: asset.business_owner    = req.business_owner
    db.commit()
    return {"message": "Asset updated", "asset_id": asset_id}


# ── Health Check ───────────────────────────────────────────────────────────────
@app.get("/api/health")
def health_check(db: Session = Depends(get_db)):
    """Real-time health of all platform components, including detailed ZAP state."""
    db_ok, db_error = False, None
    try:
        db.execute(sql_text("SELECT 1"))
        db_ok = True
    except Exception as e:
        db_error = str(e)

    nmap_ok   = any(shutil.which(p) or os.path.exists(p) for p in NMAP_SEARCH_PATH)
    zap_ok, _ = zap_service._zap_api_ping(timeout=4)
    zap_state = zap_service.get_zap_state()

    try:
        disk_root = "C:\\" if os.name == "nt" else "/"
        disk = shutil.disk_usage(disk_root)
        disk_info = {
            "total_gb": round(disk.total / 1e9, 1),
            "used_gb":  round(disk.used  / 1e9, 1),
            "free_gb":  round(disk.free  / 1e9, 1),
        }
    except Exception:
        disk_info = None

    return {
        "status":   "online",
        "version":  "2.1.0",
        "database": {"status": "up" if db_ok else "down", "error": db_error},
        "zap": {
            "status":           "up" if zap_ok else "down",
            "version":          zap_state.get("version"),
            "pid":              zap_state.get("pid"),
            "startup_attempts": zap_state.get("startup_attempts", 0),
            "last_error":       zap_state.get("last_error"),
            "last_checked":     zap_state.get("last_checked"),
            "binary":           zap_service.ZapService.find_zap_binary(),
        },
        "nmap":    {"status": "up" if nmap_ok else "down"},
        "nuclei":  {"status": "up" if shutil.which("nuclei") else "down"},
        "nikto":   {"status": "up" if (shutil.which("nikto") or shutil.which("nikto.pl")) else "down"},
        "disk":    disk_info,
        "os":      os.name,
    }


# ── ZAP Diagnostics ─────────────────────────────────────────────────────────────
@app.get("/api/diagnostics/zap")
def zap_diagnostics(current_user: models.User = Depends(auth.get_current_user)):
    """Detailed ZAP runtime state — Analyst/Admin only."""
    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role not in ["Admin", "Analyst"]:
        raise HTTPException(403, "Analyst or Admin role required")

    state   = zap_service.get_zap_state()
    binary  = zap_service.ZapService.find_zap_binary()
    live_ok, version = zap_service._zap_api_ping(timeout=4)

    return {
        "binary_path":    binary,
        "binary_found":   binary is not None,
        "port":           zap_service.ZAP_PORT,
        "timeout_config": zap_service.ZAP_STARTUP_TIMEOUT,
        "live_healthy":   live_ok,
        "live_version":   version,
        **state,
    }


@app.post("/api/diagnostics/zap/restart")
async def restart_zap(current_user: models.User = Depends(auth.get_current_user)):
    """Trigger on-demand ZAP daemon restart — Admin only."""
    user_role = current_user.roles[0].name if current_user.roles else "User"
    if user_role != "Admin":
        raise HTTPException(403, "Admin role required")
    asyncio.create_task(zap_service.ZapService.ensure_zap_running_async())
    return {"message": "ZAP restart initiated. Poll /api/diagnostics/zap for status."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)