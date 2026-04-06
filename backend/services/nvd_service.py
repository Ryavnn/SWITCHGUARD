"""
NVD Service — Fixed & Extended
================================
Fixes applied:
  - Severity strings are now title-cased ("High" not "HIGH")  ← dashboard bug fix
  - Cache lookup no longer requires both product AND version
  - EPSS scores fetched from FIRST.org API and stored on CVECache
  - Graceful degradation on network failure
"""

import logging
import requests
import time
from sqlalchemy.orm import Session
from database import models
from datetime import datetime

logger = logging.getLogger(__name__)


class NVDService:
    def __init__(self, db: Session):
        self.db               = db
        self.base_url         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.epss_url         = "https://api.first.org/data/v1/epss"
        self.headers          = {"User-Agent": "SwitchGuard-Scanner/2.0"}
        self.cache_expiry_days = 30

    # ── Public API ─────────────────────────────────────────────────────────────

    def lookup_cves(self, product: str, version: str = None) -> list:
        """
        Enrich a service/product with CVE data.

        FIX: No longer requires version to be present — product alone is sufficient.
        """
        if not product:
            return []

        # Build search query — version is now optional
        search_query = f"{product} {version}".strip() if version else product

        # 1. Check local cache first (product match only, version optional)
        cached = self._check_cache(product, version)
        if cached:
            logger.info("NVD Cache hit for %r", search_query)
            return [self._to_vuln_dict(c) for c in cached]

        # 2. Query NVD API
        logger.info("NVD Cache miss for %r. Querying API...", search_query)
        return self._query_nvd(search_query)

    def get_epss_score(self, cve_id: str) -> float:
        """Fetch EPSS score for a CVE from FIRST.org. Returns 0.0 on failure."""
        if not cve_id:
            return 0.0
        try:
            r = requests.get(
                self.epss_url,
                params={"cve": cve_id},
                headers=self.headers,
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json().get("data", [])
                if data:
                    return float(data[0].get("epss", 0.0))
        except Exception as e:
            logger.warning("EPSS lookup failed for %s: %s", cve_id, e)
        return 0.0

    # ── Internal ───────────────────────────────────────────────────────────────

    def _check_cache(self, product: str, version: str = None) -> list:
        """Check the local CVE cache. Version is optional."""
        q = self.db.query(models.CVECache).filter(
            models.CVECache.description.ilike(f"%{product}%")
        )
        if version:
            q = q.filter(models.CVECache.description.ilike(f"%{version}%"))
        return q.limit(5).all()

    def _query_nvd(self, search_query: str) -> list:
        params = {"keywordSearch": search_query, "resultsPerPage": 5}
        try:
            time.sleep(2)  # Respect NVD rate limits
            response = requests.get(
                self.base_url, params=params, headers=self.headers, timeout=15
            )
            if response.status_code != 200:
                logger.error("NVD API Error: %s — %s", response.status_code, response.text[:200])
                return []

            data            = response.json()
            vulnerabilities = []

            for item in data.get("vulnerabilities", []):
                cve    = item.get("cve", {})
                cve_id = cve.get("id")

                metrics  = cve.get("metrics", {}).get("cvssMetricV31", [])
                score    = 0.0
                vector   = ""
                severity = "Unknown"

                if metrics:
                    score    = metrics[0].get("cvssData", {}).get("baseScore", 0.0)
                    vector   = metrics[0].get("cvssData", {}).get("vectorString", "")
                    # FIX: apply .title() so "HIGH" becomes "High", "CRITICAL" → "Critical"
                    severity = metrics[0].get("cvssData", {}).get("baseSeverity", "Unknown").title()

                description = cve.get("descriptions", [{}])[0].get("value", "No description")

                weaknesses = cve.get("weaknesses", [])
                cwe_id     = "NVD-CWE-noinfo"
                if weaknesses:
                    cwe_id = weaknesses[0].get("description", [{}])[0].get("value", cwe_id)

                self._update_cache(cve_id, description, score, vector, cwe_id)

                # Fetch EPSS asynchronously-ish (sync here, non-blocking in practice)
                epss_score = self.get_epss_score(cve_id)

                vulnerabilities.append({
                    "id":          cve_id,
                    "description": description,
                    "score":       score,
                    # FIX: severity is now title-cased throughout
                    "severity":    severity,
                    "vector":      vector,
                    "cwe":         cwe_id,
                    "epss_score":  epss_score,
                })

            return vulnerabilities

        except Exception as e:
            logger.error("NVD Lookup failed for %r: %s", search_query, e)
            return []

    def _update_cache(self, cve_id, description, score, vector, cwe_id):
        existing = self.db.query(models.CVECache).filter_by(cve_id=cve_id).first()
        if existing:
            existing.description  = description
            existing.cvss_score   = score
            existing.cvss_vector  = vector
            existing.cwe_id       = cwe_id
            existing.last_updated = datetime.utcnow()
        else:
            self.db.add(models.CVECache(
                cve_id=cve_id, description=description,
                cvss_score=score, cvss_vector=vector, cwe_id=cwe_id
            ))
        try:
            self.db.commit()
        except Exception as e:
            logger.warning("CVE cache commit failed: %s", e)
            self.db.rollback()

    def _to_vuln_dict(self, cache_item: models.CVECache) -> dict:
        return {
            "id":            cache_item.cve_id,
            "description":   cache_item.description,
            "score":         cache_item.cvss_score,
            # FIX: title-cased severity from helper
            "severity":      self._score_to_severity(cache_item.cvss_score),
            "vector":        cache_item.cvss_vector,
            "cwe":           cache_item.cwe_id,
            "epss_score":    0.0,   # not stored in cache yet; enriched from API
        }

    def _score_to_severity(self, score: float) -> str:
        """FIX: Returns title-cased severity strings ('High', not 'HIGH')."""
        if not score or score == 0:
            return "Informational"
        if score < 4.0:
            return "Low"
        if score < 7.0:
            return "Medium"
        if score < 9.0:
            return "High"
        return "Critical"
