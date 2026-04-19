from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_
from database import db, models
import auth
import schemas
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

router = APIRouter(prefix="/api/portal", tags=["client-portal"])


class PortalAssetSchema(BaseModel):
    """Minimal asset schema for the client portal — includes criticality."""
    asset_id: str
    ip_address: str
    hostname: Optional[str] = None
    os_detected: Optional[str] = None
    criticality: Optional[str] = "medium"
    tenant_id: Optional[str] = None

    class Config:
        from_attributes = True


def _asset_query(db: Session, current_user: models.User):
    """
    Build an asset query scoped to the user's tenant (or the user themselves
    if tenant_id is NULL — handles legacy / admin accounts).
    """
    if current_user.tenant_id:
        return db.query(models.Asset).filter(models.Asset.tenant_id == current_user.tenant_id)
    else:
        # Fallback: return assets created by this user
        return db.query(models.Asset).filter(models.Asset.user_id == current_user.id)


def _vuln_query(db: Session, current_user: models.User):
    """
    Build a vulnerability query scoped similarly, filtering out resolved ones.
    """
    q = db.query(models.VulnerabilityInstance).filter(
        models.VulnerabilityInstance.resolved_at.is_(None)  # correct NULL check
    )
    if current_user.tenant_id:
        return q.filter(models.VulnerabilityInstance.tenant_id == current_user.tenant_id)
    else:
        return q.filter(models.VulnerabilityInstance.user_id == current_user.id)


@router.get("/metrics")
def get_tenant_metrics(
    db: Session = Depends(db.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Get high-level security metrics for the tenant dashboard."""
    total_assets = _asset_query(db, current_user).count()
    
    base_vulns = _vuln_query(db, current_user)
    total_vulns = base_vulns.count()
    
    severity_counts = {
        "Critical": base_vulns.filter(models.VulnerabilityInstance.severity == "Critical").count(),
        "High":     base_vulns.filter(models.VulnerabilityInstance.severity == "High").count(),
        "Medium":   base_vulns.filter(models.VulnerabilityInstance.severity == "Medium").count(),
        "Low":      base_vulns.filter(models.VulnerabilityInstance.severity == "Low").count(),
    }
    
    tenant_name = "Enterprise"
    if current_user.tenant:
        tenant_name = current_user.tenant.name
    
    return {
        "total_assets": total_assets,
        "total_vulnerabilities": total_vulns,
        "severity_distribution": severity_counts,
        "tenant_name": tenant_name
    }


@router.get("/assets", response_model=List[PortalAssetSchema])
def get_tenant_assets(
    db: Session = Depends(db.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """List all assets belonging to the tenant (or user if no tenant assigned)."""
    return _asset_query(db, current_user).all()
