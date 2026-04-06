import logging
from sqlalchemy.orm import Session
from database import models

logger = logging.getLogger(__name__)

class RiskEngine:
    def __init__(self, db: Session):
        self.db = db

    def apply_contextual_risk(self, job_id: str):
        """
        Calculates and updates risk_score for all vulnerabilities in a job
        based on:
        1. Base CVSS / ZAP Severity
        2. Asset Context (Internal vs External)
        3. Attack Chain Boost (is it linked via correlation?)
        """
        logger.info(f"Applying contextual risk for job {job_id}")
        
        vulns = self.db.query(models.VulnerabilityInstance).filter_by(job_id=job_id).all()
        
        for vuln in vulns:
            # 1. Base Score
            # If ZAP provided a score via confidence, use it. Otherwise use severity mappings.
            base_score = vuln.risk_score or self._severity_to_score(vuln.severity)
            
            # 2. Contextual Modifiers
            context_multiplier = 1.0
            
            # Check if target is 'internal' or 'business-critical' via tags (simulated)
            target = vuln.scan.target
            if "localhost" in target or "127.0.0.1" in target or target.startswith("192.168"):
                # Internal targets get a slightly lower weight if they are not exposed
                context_multiplier = 0.8
            
            # 3. Correlation / Attack Chain Boost
            # If this vuln is linked to a network service, it's more likely exploitable
            boost = 0.0
            if vuln.correlation_links:
                boost = 2.0 # Significant boost for verified attack chains
            
            # 4. Calculation
            # Formula: (Base * Context) + Boost
            final_score = (base_score * context_multiplier) + boost
            
            # Caps at 10.0
            vuln.risk_score = round(min(10.0, final_score), 1)

        self.db.commit()
        return len(vulns)

    def _severity_to_score(self, severity: str):
        mapping = {
            "Critical": 9.5,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.5,
            "Informational": 1.0,
            "Unknown": 1.0
        }
        return mapping.get(severity, 1.0)
