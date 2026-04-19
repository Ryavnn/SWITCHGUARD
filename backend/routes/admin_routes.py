from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Optional
from datetime import datetime

from database import models
from database.db import SessionLocal
from auth import get_current_user, RoleChecker, get_password_hash
from pydantic import BaseModel, EmailStr

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(RoleChecker(["Admin"]))])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def log_audit(db: Session, admin_id: str, action: str, target: str = None, ip: str = None):
    log = models.AuditLog(user_id=admin_id, action=action, target_id=target, ip_address=ip)
    db.add(log)
    db.commit()


# ── KPI Dashboard ─────────────────────────────────────────────────────────────
@router.get("/dashboard/summary")
def get_admin_summary(db: Session = Depends(get_db)):
    total_users = db.query(models.User).count()
    total_assets = db.query(models.Asset).count()
    total_reports = db.query(models.Report).count()
    
    scans = {
        "total": db.query(models.ScanJob).count(),
        "running": db.query(models.ScanJob).filter_by(status="running").count(),
        "completed": db.query(models.ScanJob).filter_by(status="completed").count(),
        "failed": db.query(models.ScanJob).filter_by(status="failed").count()
    }
    
    criticals = db.query(models.VulnerabilityInstance).filter_by(severity="Critical").count()
    highs = db.query(models.VulnerabilityInstance).filter_by(severity="High").count()
    total_vulns = db.query(models.VulnerabilityInstance).count()
    
    avg_risk = 0
    if total_assets > 0:
        avg_risk = min(100, int(( (criticals + highs) * 10 + total_vulns * 2) / total_assets))

    return {
        "users": {"total": total_users, "active_today": total_users}, # simplified active today
        "assets": {"total": total_assets},
        "scans": scans,
        "vulnerabilities": {"critical": criticals, "high": highs},
        "risk_score": {"average": avg_risk},
        "reports": {"generated": total_reports},
        "system": {"uptime": "99.9%"}
    }


# ── User Management ───────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str

@router.get("/users")
def get_users(skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    users = db.query(models.User).order_by(models.User.created_at.desc()).offset(skip).limit(limit).all()
    results = []
    for u in users:
        role = u.roles[0].name if u.roles else "User"
        results.append({
            "id": u.id, "name": u.name, "email": u.email, 
            "role": role, "is_active": u.is_active, 
            "last_login": u.last_login, "created_at": u.created_at
        })
    return {"data": results, "total": db.query(models.User).count()}

@router.post("/users")
def create_user(req: UserCreate, db: Session = Depends(get_db), current_admin: models.User = Depends(get_current_user)):
    if db.query(models.User).filter_by(email=req.email).first():
        raise HTTPException(status_code=400, detail="Email exists")
        
    hashed = get_password_hash(req.password)
    new_user = models.User(name=req.name, email=req.email, hashed_password=hashed)
    target_role = db.query(models.Role).filter_by(name=req.role).first()
    if target_role:
        new_user.roles.append(target_role)
    db.add(new_user)
    db.commit()
    log_audit(db, current_admin.id, f"created_user", new_user.id)
    return {"message": "User created", "id": new_user.id}

@router.patch("/users/{user_id}/status")
def toggle_user_status(user_id: str, is_active: bool, db: Session = Depends(get_db), admin: models.User = Depends(get_current_user)):
    user = db.query(models.User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.is_active = is_active
    db.commit()
    action = "activated_user" if is_active else "suspended_user"
    log_audit(db, admin.id, action, user_id)
    return {"message": f"User {action}"}

@router.delete("/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db), admin: models.User = Depends(get_current_user)):
    user = db.query(models.User).filter_by(id=user_id).first()
    if not user:
         raise HTTPException(404, "User not found")
    db.delete(user)
    db.commit()
    log_audit(db, admin.id, "deleted_user", user_id)
    return {"message": "User deleted"}


# ── Global Asset Inventory ────────────────────────────────────────────────────
@router.get("/assets")
def get_global_assets(skip: int = 0, limit: int = 50, search: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.Asset)
    if search:
        query = query.filter(models.Asset.ip_address.contains(search) | models.Asset.hostname.contains(search))
    
    total = query.count()
    assets = query.order_by(desc(models.Asset.ip_address)).offset(skip).limit(limit).all()
    
    res = []
    for a in assets:
        owner = db.query(models.User).filter_by(id=a.user_id).first()
        res.append({
            "asset_id": a.asset_id,
            "ip_address": a.ip_address,
            "hostname": a.hostname,
            "os": a.os_detected,
            "job_id": a.job_id,
            "owner": owner.email if owner else "System",
            "ports": len(a.services)
        })
    return {"data": res, "total": total}


# ── Vulnerability Analytics ───────────────────────────────────────────────────
@router.get("/vulnerabilities/analytics")
def get_vuln_analytics(db: Session = Depends(get_db)):
    # Severity distribution
    sev_counts = db.query(models.VulnerabilityInstance.severity, func.count('*')).group_by(models.VulnerabilityInstance.severity).all()
    distribution = {sev: count for sev, count in sev_counts}
    
    # Top 5 recurring titles
    top_vulns = db.query(models.VulnerabilityInstance.title, func.count('*').label('c')).group_by(models.VulnerabilityInstance.title).order_by(desc('c')).limit(5).all()
    recurring = [{"title": t, "count": c} for t, c in top_vulns]
    
    return {
        "severity_distribution": distribution,
        "top_recurring": recurring
    }


# ── Audit Logs ────────────────────────────────────────────────────────────────
@router.get("/audit-logs")
def get_audit_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    # Simple join to get user email
    logs = db.query(models.AuditLog, models.User.email).outerjoin(models.User, models.AuditLog.user_id == models.User.id).order_by(desc(models.AuditLog.timestamp)).offset(skip).limit(limit).all()
    
    results = []
    for log, email in logs:
        results.append({
            "id": log.id,
            "user": email or "System",
            "action": log.action,
            "target_id": log.target_id,
            "timestamp": log.timestamp
        })
    return {"data": results, "total": db.query(models.AuditLog).count()}


# ── System Settings ───────────────────────────────────────────────────────────
class SettingUpdate(BaseModel):
    value: str

@router.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    settings = db.query(models.SystemSetting).all()
    # Provide defaults if empty
    if not settings:
        default_settings = [
            models.SystemSetting(key="max_concurrent_scans", value="5", description="Limits parallel threads"),
            models.SystemSetting(key="report_retention_days", value="30", description="Days to keep PDFs"),
            models.SystemSetting(key="zap_daemon_port", value="8081", description="ZAP API Hook")
        ]
        db.add_all(default_settings)
        db.commit()
        settings = default_settings
    
    res = {s.key: {"value": s.value, "desc": s.description} for s in settings}
    return res

@router.patch("/settings/{key}")
def update_setting(key: str, req: SettingUpdate, db: Session = Depends(get_db), admin: models.User = Depends(get_current_user)):
    setting = db.query(models.SystemSetting).filter_by(key=key).first()
    if not setting:
        raise HTTPException(404, "Setting not found")
        
    old_val = setting.value
    setting.value = req.value
    db.commit()
    log_audit(db, admin.id, f"changed_setting_{key}", f"{old_val} -> {req.value}")
    return {"message": "Setting updated", "key": key, "value": req.value}
