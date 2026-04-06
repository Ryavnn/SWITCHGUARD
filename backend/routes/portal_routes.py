from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import db, models
import auth
import schemas
from typing import List, Dict, Any

router = APIRouter(prefix="/api/portal", tags=["client-portal"])

@router.get("/metrics")
def get_tenant_metrics(
    db: Session = Depends(db.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Get high-level security metrics for the tenant dashboard."""
    tenant_id = current_user.tenant_id
    
    total_assets = db.query(models.Asset).filter_by(tenant_id=tenant_id).count()
    total_vulns = db.query(models.VulnerabilityInstance).filter_by(tenant_id=tenant_id, resolved_at=None).count()
    
    severity_counts = {
        "Critical": db.query(models.VulnerabilityInstance).filter_by(tenant_id=tenant_id, resolved_at=None, severity="Critical").count(),
        "High": db.query(models.VulnerabilityInstance).filter_by(tenant_id=tenant_id, resolved_at=None, severity="High").count(),
        "Medium": db.query(models.VulnerabilityInstance).filter_by(tenant_id=tenant_id, resolved_at=None, severity="Medium").count(),
        "Low": db.query(models.VulnerabilityInstance).filter_by(tenant_id=tenant_id, resolved_at=None, severity="Low").count(),
    }
    
    return {
        "total_assets": total_assets,
        "total_vulnerabilities": total_vulns,
        "severity_distribution": severity_counts,
        "tenant_name": current_user.tenant.name if current_user.tenant else "Default"
    }

@router.get("/assets", response_model=List[schemas.AssetSchema])
def get_tenant_assets(
    db: Session = Depends(db.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """List all assets belonging to the tenant."""
    return db.query(models.Asset).filter_by(tenant_id=current_user.tenant_id).all()
