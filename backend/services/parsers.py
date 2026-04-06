"""
Parsers — Fixed & Extended
============================
Fixes applied:
  - Defensive exception logging with full tracebacks
  - Nuclei and Nikto finding normalization
  - epss_score stored on VulnerabilityInstance
  - SLA due date auto-calculated on creation

"""

from sqlalchemy.orm import Session
from database import models
from .nvd_service import NVDService
from .correlation_service import CorrelationService
import logging
import json
import traceback
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# SLA windows by severity (days)
SLA_DAYS = {
    "Critical":      7,
    "High":         30,
    "Medium":       90,
    "Low":         180,
    "Informational": 365,
}


def _calc_sla(severity: str) -> datetime:
    days = SLA_DAYS.get(severity.title(), 180)
    return datetime.utcnow() + timedelta(days=days)


def parse_nmap_results(job_id: str, raw_data: dict, db: Session, user_id: str = None):
    try:
        if not raw_data or "scan" not in raw_data:
            return
        scan_data = raw_data["scan"]
        if not scan_data:
            return

        nvd = NVDService(db)

        for ip, host_info in scan_data.items():
            hostname  = ""
            hostnames = host_info.get("hostnames", [])
            if hostnames:
                hostname = hostnames[0].get("name", "")

            # ── Asset insertion (isolated) ─────────────────────────────────────
            try:
                asset = models.Asset(
                    job_id=job_id,
                    user_id=user_id,
                    ip_address=ip,
                    hostname=hostname,
                    os_detected=(
                        host_info.get("osmatch", [{}])[0].get("name", "Unknown")
                        if host_info.get("osmatch") else "Unknown"
                    ),
                )
                db.add(asset)
                db.commit()
                db.refresh(asset)
            except Exception as ae:
                logger.error("[%s] Failed to save asset %s: %s", job_id, ip, ae)
                db.rollback()
                continue   # skip this host's ports, we have no FK to attach to

            # ── Port / Service loop ────────────────────────────────────────────
            open_ports = []
            if "tcp" in host_info:
                for port_num, port_info in host_info["tcp"].items():
                    if port_info.get("state") != "open":
                        continue

                    service_name = port_info.get("name", "unknown")
                    version      = port_info.get("version", "")
                    product      = port_info.get("product", "")
                    open_ports.append(int(port_num))

                    # ── Service insertion (isolated) ───────────────────────────
                    try:
                        service = models.Service(
                            asset_id=asset.asset_id,
                            port=int(port_num),
                            protocol="tcp",
                            service_name=service_name,
                            state="open",
                            version=f"{product} {version}".strip(),
                        )
                        db.add(service)
                        db.commit()
                    except Exception as se:
                        logger.error("[%s] Failed to save service port %s: %s", job_id, port_num, se)
                        db.rollback()
                        continue   # skip CVE lookups for this port

                    # ── NVD CVE lookup (isolated) ──────────────────────────────
                    if product:
                        cves = []
                        try:
                            cves = nvd.lookup_cves(product, version)
                        except Exception as e:
                            logger.warning("[%s] NVD lookup failed for %s — skipping CVEs: %s", job_id, product, e)
                            db.rollback()  # <─ KEY FIX: clear poisoned transaction

                        for cve in cves:
                            try:
                                severity = (cve.get("severity") or "Low").title()
                                vuln = models.VulnerabilityInstance(
                                    job_id=job_id,
                                    user_id=user_id,
                                    title=f"CVE: {cve['id']} in {product}",
                                    description=cve.get("description", ""),
                                    severity=severity,
                                    risk_score=cve.get("score", 0.0),
                                    cve_id=cve["id"],
                                    cvss_score=cve.get("score"),
                                    cvss_vector=cve.get("vector"),
                                    cwe_id=cve.get("cwe"),
                                    epss_score=cve.get("epss_score"),
                                    confidence_score=0.6,
                                    sla_due_date=_calc_sla(severity),
                                )
                                db.add(vuln)
                                db.commit()

                                link = models.CorrelationLink(
                                    job_id=job_id,
                                    service_id=service.service_id,
                                    vuln_id=vuln.vuln_id,
                                    confidence=0.8,
                                    description=f"Service version {service.version} matches CVE.",
                                )
                                db.add(link)
                                db.commit()
                            except Exception as ve:
                                logger.warning("[%s] Failed to save CVE %s: %s", job_id, cve.get("id"), ve)
                                db.rollback()

            logger.info("[%s] Host %s — %d open TCP port(s): %s", job_id, ip, len(open_ports), open_ports)

    except Exception as e:
        logger.error(
            "[%s] parse_nmap_results FAILED: %s\n%s",
            job_id, e, traceback.format_exc()
        )
        try:
            db.rollback()
        except Exception:
            pass


def parse_zap_results(job_id: str, alerts: list, db: Session, user_id: str = None):
    try:
        seen_alerts = set()
        for alert in alerts:
            sig = f"{alert.get('alert')}|{alert.get('url')}|{alert.get('evidence')}"
            if sig in seen_alerts:
                continue
            seen_alerts.add(sig)

            severity = _normalize_severity(alert.get("risk", "Low"))
            vuln = models.VulnerabilityInstance(
                job_id=job_id,
                user_id=user_id,
                title=alert.get("alert", "Unknown Issue"),
                description=alert.get("description", ""),
                severity=severity,
                risk_score=float(alert.get("confidence", 0)) * 2,
                evidence=alert.get("evidence", ""),
                url=alert.get("url", ""),
                solution=alert.get("solution", ""),
                cwe_id=str(alert.get("cweid", "")) or None,
                confidence_score=float(alert.get("confidence", 0)) / 4.0,
                sla_due_date=_calc_sla(severity),
            )
            db.add(vuln)
        db.commit()

        correlator = CorrelationService(db)
        correlator.correlate_job(job_id)

    except Exception as e:
        logger.error(
            "[%s] parse_zap_results FAILED: %s\n%s",
            job_id, e, traceback.format_exc()
        )


def parse_nuclei_results(job_id: str, findings: list, db: Session, user_id: str = None):
    """Parse Nuclei scanner output into VulnerabilityInstance records."""
    try:
        seen = set()
        for f in findings:
            sig = f"{f.get('title')}|{f.get('url')}"
            if sig in seen:
                continue
            seen.add(sig)

            severity = _normalize_severity(f.get("severity", "Low"))
            vuln = models.VulnerabilityInstance(
                job_id=job_id,
                user_id=user_id,
                title=f.get("title", "Nuclei Finding"),
                description=f.get("description", ""),
                severity=severity,
                risk_score=0.0,
                url=f.get("url", ""),
                solution=f.get("solution", ""),
                evidence=f.get("evidence", ""),
                cve_id=f.get("cve_id"),
                cwe_id=str(f.get("cwe_id") or ""),
                cvss_score=f.get("cvss_score"),
                confidence_score=0.7,
                sla_due_date=_calc_sla(severity),
            )
            db.add(vuln)
        db.commit()

    except Exception as e:
        logger.error(
            "[%s] parse_nuclei_results FAILED: %s\n%s",
            job_id, e, traceback.format_exc()
        )


def parse_nikto_results(job_id: str, findings: list, db: Session, user_id: str = None):
    """Parse Nikto scanner output into VulnerabilityInstance records."""
    try:
        for f in findings:
            severity = _normalize_severity(f.get("severity", "Low"))
            vuln = models.VulnerabilityInstance(
                job_id=job_id,
                user_id=user_id,
                title=f.get("title", "Nikto Finding"),
                description=f.get("description", ""),
                severity=severity,
                risk_score=0.0,
                url=f.get("url", ""),
                solution=f.get("solution", ""),
                evidence=f.get("evidence", ""),
                sla_due_date=_calc_sla(severity),
            )
            db.add(vuln)
        db.commit()

    except Exception as e:
        logger.error(
            "[%s] parse_nikto_results FAILED: %s\n%s",
            job_id, e, traceback.format_exc()
        )


def enrich_scan_results(job_id: str, db: Session):
    """Final enrichment pass — applies contextual risk scoring."""
    from .risk_engine import RiskEngine
    try:
        engine = RiskEngine(db)
        return engine.apply_contextual_risk(job_id)
    except Exception as e:
        logger.error("[%s] enrich_scan_results failed: %s", job_id, e)
        return 0


def _normalize_severity(raw: str) -> str:
    """Normalise any severity string to title-case SwitchGuard standard."""
    mapping = {
        "critical":      "Critical",
        "high":          "High",
        "medium":        "Medium",
        "low":           "Low",
        "informational": "Informational",
        "info":          "Informational",
        "note":          "Informational",
        "warn":          "Medium",
        "warning":       "Medium",
    }
    return mapping.get((raw or "low").lower(), "Low")