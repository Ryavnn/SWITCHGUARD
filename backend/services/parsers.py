from sqlalchemy.orm import Session
from database import models
import logging

logger = logging.getLogger(__name__)

def parse_nmap_results(job_id: str, raw_data: dict, db: Session, user_id: str = None):
    try:
        if not raw_data or 'scan' not in raw_data:
            return

        scan_data = raw_data['scan']
        
        if scan_data is None:
            return

        for ip, host_info in scan_data.items():
            hostnames = host_info.get('hostnames', [])
            hostname = ''
            if hostnames and len(hostnames) > 0:
                hostname = hostnames[0].get('name', '')

            asset = models.Asset(
                job_id=job_id,
                user_id=user_id,
                ip_address=ip,
                hostname=hostname,
                os_detected="Unknown"
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)

            if 'tcp' in host_info and host_info['tcp']:
                tcp_ports = host_info['tcp']
                
                for port_num, port_info in tcp_ports.items():
                    state = port_info.get('state')
                    if state == 'open':
                        service = models.Service(
                            asset_id=asset.asset_id,
                            port=int(port_num),
                            protocol='tcp',
                            service_name=port_info.get('name', 'unknown'),
                            state='open',
                            version=port_info.get('version', '')
                        )
                        db.add(service)
                db.commit()

    except Exception as e:
        logger.error(f"Error parsing Nmap results for Job {job_id}: {str(e)}")
        pass

def parse_zap_results(job_id: str, alerts: list, db: Session, user_id: str = None):
    try:
        for alert in alerts:
            vuln = models.VulnerabilityInstance(
                job_id=job_id,
                user_id=user_id,
                title=alert.get('alert', 'Unknown Issue'),
                description=alert.get('description', ''),
                severity=alert.get('risk', 'Low'),
                risk_score=0.0,
                evidence=alert.get('evidence', ''),
                url=alert.get('url', ''),
                solution=alert.get('solution', '')
            )
            db.add(vuln)
        db.commit()
    except Exception as e:
        logger.error(f"Error parsing ZAP results for Job {job_id}: {str(e)}")
        pass

def enrich_scan_results(job_id: str, db: Session):
    return 0