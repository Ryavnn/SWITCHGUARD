import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database import models
from services.threat_intel_service import ThreatIntelService

logger = logging.getLogger(__name__)

class RemediationService:
    def __init__(self, db: Session):
        self.db = db

    def calculate_priority_score(self, vuln: models.VulnerabilityInstance) -> float:
        """
        Risk = (CVSS * 0.3) + (EPSS * 10 * 0.25) + (KEV * 20 * 0.2) + (Exposure * 15 * 0.15) + (Chain * 10 * 0.1)
        Normalized to 0 - 100 range.
        """
        score = 0.0
        
        # 1. CVSS (0-10) -> Weight 0.3
        cvss = vuln.cvss_score or 5.0 # default to 5 if none
        score += cvss * 0.3 * 10 # scale to 100 basis weight
        
        # 2. EPSS (0-1) -> Weight 0.25
        epss = vuln.epss_score or 0.0
        score += epss * 10 * 0.25 * 10 # epss 0.1 * 10 = 1, * 0.25 = 0.25 * 10 = 2.5
        
        # 3. KEV (Known Exploited) -> Weight 0.2
        if ThreatIntelService.is_known_exploited(vuln.cve_id):
            score += 20 * 0.2
            vuln.kev_status = True
            
        # 4. Internet Exposure (Assets table) -> Weight 0.15
        asset = vuln.asset
        if asset and asset.internet_exposed:
            score += 15 * 0.15
            
        # 5. Ransomware Relationship
        if ThreatIntelService.is_ransomware_related(vuln.cve_id):
            score += 10 # flat bonus
            vuln.ransomware_related = True

        return min(round(score, 2), 100.0)

    def suggest_due_date(self, severity: str, is_kev: bool) -> datetime:
        """SLA-aware due date calculation."""
        now = datetime.utcnow()
        if is_kev or severity == "Critical":
            return now + timedelta(days=7) # Immediate/Critical/KEV -> 7 days
        elif severity == "High":
            return now + timedelta(days=30)
        elif severity == "Medium":
            return now + timedelta(days=60)
        return now + timedelta(days=90) # Low -> 90 days

    def refresh_remediation_queue(self, tenant_id: str):
        """Re-rank ALL unresolved vulnerabilities for a tenant."""
        vulns = self.db.query(models.VulnerabilityInstance).filter(
            models.VulnerabilityInstance.tenant_id == tenant_id,
            models.VulnerabilityInstance.resolved_at == None
        ).all()
        
        for v in vulns:
            v.priority_score = self.calculate_priority_score(v)
            v.sla_due_date = self.suggest_due_date(v.severity, v.kev_status)
            
        self.db.commit()
        
        # Assign numeric ranks
        vulns.sort(key=lambda x: x.priority_score, reverse=True)
        for i, v in enumerate(vulns):
            v.remediation_rank = i + 1
            
        self.db.commit()
        logger.info(f"Rebuilt remediation queue for tenant {tenant_id}: {len(vulns)} items.")

    def get_remediation_queue(self, tenant_id: str) -> List[models.VulnerabilityInstance]:
        return self.db.query(models.VulnerabilityInstance).filter(
            models.VulnerabilityInstance.tenant_id == tenant_id,
            models.VulnerabilityInstance.resolved_at == None
        ).order_by(models.VulnerabilityInstance.remediation_rank.asc()).all()

    def add_comment(self, vuln_id: str, user_id: str, tenant_id: str, text: str):
        comment = models.RemediationComment(
            vuln_id=vuln_id,
            user_id=user_id,
            tenant_id=tenant_id,
            comment=text
        )
        self.db.add(comment)
        self.db.commit()
        return comment
