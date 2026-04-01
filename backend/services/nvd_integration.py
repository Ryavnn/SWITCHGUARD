import requests
import time
import logging

logger = logging.getLogger(__name__)

class NVDService:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {
            "User-Agent": "SwitchGuard-Scanner/1.0"
        }

    def lookup_cves(self, product: str, version: str):
        if not product or not version:
            return []

        search_query = f"{product} {version}"
        params = {
            "keywordSearch": search_query,
            "resultsPerPage": 3
        }

        try:
            # NVD has rate limits, so we sleep briefly to be safe
            time.sleep(1) 
            response = requests.get(self.base_url, params=params, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                    
                    score = 0.0
                    severity = "UNKNOWN"
                    
                    if metrics:
                        score = metrics[0].get("cvssData", {}).get("baseScore", 0.0)
                        severity = metrics[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")

                    vuln_data = {
                        "id": cve.get("id"),
                        "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
                        "score": score,
                        "severity": severity
                    }
                    vulnerabilities.append(vuln_data)
                
                return vulnerabilities
            
            return []

        except Exception as e:
            logger.error(f"NVD Lookup failed: {e}")
            return []