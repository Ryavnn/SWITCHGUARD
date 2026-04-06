import logging
from sqlalchemy.orm import Session
from database import models
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class CorrelationService:
    def __init__(self, db: Session):
        self.db = db

    def correlate_job(self, job_id: str):
        """
        Attempts to link ZAP vulnerabilities to Nmap services discovered in the same job.
        This is the 'Hybrid' part of the scanner.
        """
        logger.info(f"Starting correlation for job {job_id}")
        
        # 1. Fetch data
        vulns = self.db.query(models.VulnerabilityInstance).filter_by(job_id=job_id).all()
        assets = self.db.query(models.Asset).filter_by(job_id=job_id).all()
        
        if not vulns or not assets:
            logger.warning(f"Insufficient data for correlation in job {job_id}")
            return 0

        links_created = 0

        # 2. Map Assets by IP and Hostname for quick lookup
        asset_map = {}
        for a in assets:
            asset_map[a.ip_address] = a
            if a.hostname:
                asset_map[a.hostname] = a

        # 3. Correlate each vulnerability
        for vuln in vulns:
            if not vuln.url:
                continue

            try:
                parsed_url = urlparse(vuln.url)
                netloc = parsed_url.netloc
                
                # Extract host and port
                if ':' in netloc:
                    host, port = netloc.split(':')
                    port = int(port)
                else:
                    host = netloc
                    port = 443 if parsed_url.scheme == 'https' else 80

                # 4. Find matching asset
                target_asset = asset_map.get(host)
                if not target_asset:
                    # Try resolving hostname if possible or fuzzy match
                    continue

                # 5. Find matching service on that asset
                for service in target_asset.services:
                    confidence = 0.5
                    evidence = []

                    # Match by Port
                    if service.port == port:
                        confidence += 0.2
                        evidence.append(f"Port {port} match.")

                    # Match by Version/Banner (if vuln title mentions the service)
                    service_name = (service.service_name or "").lower()
                    service_version = (service.version or "").lower()
                    vuln_title = vuln.title.lower()
                    vuln_desc = (vuln.description or "").lower()

                    if service_name and (service_name in vuln_title or service_name in vuln_desc):
                        confidence += 0.2
                        evidence.append(f"Service name '{service_name}' match.")
                    
                    if service_version and (service_version in vuln_desc):
                        confidence += 0.1
                        evidence.append(f"Service version '{service_version}' found in vulnerability description.")

                    # 6. Create Link if confidence is sufficient
                    if confidence >= 0.7:
                        link = models.CorrelationLink(
                            job_id=job_id,
                            service_id=service.service_id,
                            vuln_id=vuln.vuln_id,
                            confidence=min(confidence, 1.0),
                            description="; ".join(evidence)
                        )
                        self.db.add(link)
                        links_created += 1
                        
                        # Update vuln confidence
                        vuln.confidence_score = max(vuln.confidence_score, confidence)

            except Exception as e:
                logger.error(f"Error correlating vulnerability {vuln.vuln_id}: {e}")
                continue

        self.db.commit()
        logger.info(f"Correlation complete for {job_id}. Created {links_created} link(s).")
        return links_created
