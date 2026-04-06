import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import db as db_module, models
from services.tenant_service import TenantService
import auth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tenants", tags=["tenants"])

def get_db():
    db = db_module.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/", response_model=List[dict])
def list_tenants(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """List all tenants — Admin only."""
    if not any(r.name in ["Admin", "SuperAdmin"] for r in current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can list tenants."
        )
    
    tenants = TenantService(db).get_all_tenants()
    return [
        {
            "id": t.id,
            "name": t.name,
            "slug": t.slug,
            "plan": t.plan,
            "created_at": t.created_at
        } for t in tenants
    ]

@router.get("/{tenant_id}/metrics")
def get_tenant_metrics(
    tenant_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Get usage metrics for a specific tenant. tenant_id must match current_user.tenant_id or user is Admin."""
    is_admin = any(r.name in ["Admin", "SuperAdmin"] for r in current_user.roles)
    
    if not is_admin and current_user.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this tenant's metrics."
        )
    
    tenant = TenantService(db).get_tenant_by_id(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")
        
    metrics = TenantService(db).get_tenant_metrics(tenant_id)
    return {
        "tenant_name": tenant.name,
        "metrics": metrics
    }

@router.post("/", status_code=status.HTTP_201_CREATED)
def create_tenant(
    name: str,
    slug: str,
    plan: str = "free",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Create a new tenant — Admin only."""
    if not any(r.name in ["Admin", "SuperAdmin"] for r in current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can create tenants."
        )
    
    service = TenantService(db)
    if service.get_tenant_by_slug(slug):
        raise HTTPException(status_code=400, detail=f"Tenant slug '{slug}' already exists.")
        
    tenant = service.create_tenant(name, slug, plan)
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "plan": tenant.plan
    }
