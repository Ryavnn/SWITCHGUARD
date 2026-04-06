import logging
import uuid
from typing import Optional, List, Any
from sqlalchemy.orm import Session
from database import models

logger = logging.getLogger(__name__)

class TenantService:
    def __init__(self, db: Session):
        self.db = db

    def get_or_create_default_tenant(self) -> models.Tenant:
        """Ensure a default tenant exists for legacy migration."""
        default_id = "default-tenant-0000"
        tenant = self.db.query(models.Tenant).filter_by(id=default_id).first()
        if not tenant:
            tenant = models.Tenant(
                id=default_id,
                name="Default Tenant",
                slug="default",
                plan="enterprise"
            )
            self.db.add(tenant)
            self.db.commit()
            self.db.refresh(tenant)
        return tenant

    def create_tenant(self, name: str, slug: str, plan: str = "free") -> models.Tenant:
        """Create a new tenant with unique slug."""
        tenant = models.Tenant(
            id=str(uuid.uuid4()),
            name=name,
            slug=slug.lower(),
            plan=plan
        )
        self.db.add(tenant)
        self.db.commit()
        self.db.refresh(tenant)
        logger.info(f"Created new tenant: {name} ({slug})")
        return tenant

    def get_tenant_by_id(self, tenant_id: str) -> Optional[models.Tenant]:
        return self.db.query(models.Tenant).filter_by(id=tenant_id).first()

    def get_tenant_by_slug(self, slug: str) -> Optional[models.Tenant]:
        return self.db.query(models.Tenant).filter_by(slug=slug.lower()).first()

    def get_all_tenants(self) -> List[models.Tenant]:
        return self.db.query(models.Tenant).all()

    def enforce_isolation(self, model_class: Any, tenant_id: str):
        """Helper to create a filtered query for a specific tenant."""
        return self.db.query(model_class).filter(model_class.tenant_id == tenant_id)

    def assign_user_to_tenant(self, user_id: str, tenant_id: str):
        """Update user record with tenant_id."""
        user = self.db.query(models.User).filter_by(id=user_id).first()
        if user:
            user.tenant_id = tenant_id
            self.db.commit()
            logger.info(f"Assigned user {user_id} to tenant {tenant_id}")
            return True
        return False

    def get_tenant_metrics(self, tenant_id: str) -> dict:
        """Gather usage metrics for a specific tenant."""
        from sqlalchemy import func
        
        return {
            "total_assets": self.db.query(models.Asset).filter_by(tenant_id=tenant_id).count(),
            "total_scans": self.db.query(models.ScanJob).filter_by(tenant_id=tenant_id).count(),
            "active_vulnerabilities": self.db.query(models.VulnerabilityInstance).filter_by(
                tenant_id=tenant_id, is_false_positive=False
            ).filter(models.VulnerabilityInstance.resolved_at == None).count(),
            "sla_breaches": self.db.query(models.VulnerabilityInstance).filter_by(
                tenant_id=tenant_id, sla_breached=True
            ).count()
        }
