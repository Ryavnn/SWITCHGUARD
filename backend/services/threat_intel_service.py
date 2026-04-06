import logging
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ThreatIntelService:
    _kev_cache: List[str] = []
    _last_fetch: Optional[datetime] = None
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    @classmethod
    def fetch_kev_list(cls) -> List[str]:
        """Fetch the CISA KEV JSON feed and return a list of CVE IDs."""
        current_time = datetime.utcnow()
        
        # Cache for 24 hours
        if cls._last_fetch and (current_time - cls._last_fetch) < timedelta(hours=24):
            return cls._kev_cache

        try:
            logger.info("Fetching CISA KEV list...")
            resp = requests.get(cls.KEV_URL, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                cls._kev_cache = [v.get("cveID") for v in vulnerabilities if v.get("cveID")]
                cls._last_fetch = current_time
                logger.info(f"Successfully cached {len(cls._kev_cache)} KEV CVEs.")
                return cls._kev_cache
            else:
                logger.error(f"Failed to fetch KEV list: Status {resp.status_code}")
                return cls._kev_cache
        except Exception as e:
            logger.error(f"Error fetching KEV list: {e}")
            return cls._kev_cache

    @classmethod
    def is_known_exploited(cls, cve_id: str) -> bool:
        if not cve_id:
            return False
        kev_list = cls.fetch_kev_list()
        return cve_id in kev_list

    @classmethod
    def get_metasploit_module(cls, cve_id: str) -> Optional[str]:
        """Placeholder for Metasploit module lookup logic."""
        # In a real implementation, this might query an offline JSON or local DB
        return None

    @classmethod
    def is_ransomware_related(cls, cve_id: str) -> bool:
        """Placeholder for ransomware-related CVE tagging."""
        # Known ransomware CVEs list (example)
        ransomware_cves = ["CVE-2017-0144", "CVE-2019-11510", "CVE-2021-34473"]
        return cve_id in ransomware_cves
