"""
Nuclei Scanner Adapter
======================
Wraps the Nuclei CLI tool for template-based vulnerability scanning.
Nuclei must be installed and available in PATH.

Install: https://github.com/projectdiscovery/nuclei/releases
"""

import subprocess
import json
import logging
import shutil
import os
from typing import List, Dict

logger = logging.getLogger(__name__)

NUCLEI_TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", "300"))  # seconds

# Severity mapping from Nuclei → SwitchGuard standard
SEVERITY_MAP = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Informational",
    "unknown":  "Low",
}


def is_nuclei_installed() -> bool:
    return shutil.which("nuclei") is not None


class NucleiScanner:
    """
    Runs Nuclei templates against a target and returns normalized findings.

    Each finding is normalized to match the SwitchGuard VulnerabilityInstance schema:
        title, description, severity, url, solution, cve_id, cwe_id, evidence
    """

    def run_scan(
        self,
        target: str,
        severity: str = "medium,high,critical",
        tags: str = None,
        templates: str = None,
    ) -> List[Dict]:
        """
        Execute a Nuclei scan against *target*.

        Args:
            target:    URL or IP address.
            severity:  Comma-separated severity filter (e.g. "high,critical").
            tags:      Optional comma-separated template tags (e.g. "cve,sqli").
            templates: Optional path to custom template directory.
        """
        if not is_nuclei_installed():
            logger.warning("Nuclei is not installed or not in PATH. Skipping Nuclei scan.")
            return []

        cmd = [
            "nuclei",
            "-u", target,
            "-severity", severity,
            "-json",           # structured output for parsing
            "-silent",         # suppress banner/progress noise
            "-no-interactsh",  # disable interactsh (requires network callback)
            "-timeout", "10",  # per-request timeout
        ]

        if tags:
            cmd += ["-tags", tags]
        if templates:
            cmd += ["-t", templates]

        logger.info("Running Nuclei on %r with args: %s", target, " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=NUCLEI_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.error("Nuclei scan timed out for %r after %ds", target, NUCLEI_TIMEOUT)
            return []
        except FileNotFoundError:
            logger.error("Nuclei binary not found. Ensure it is installed and in PATH.")
            return []
        except Exception as e:
            logger.error("Nuclei scan failed for %r: %s", target, e)
            return []

        findings = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                findings.append(self._normalize(raw))
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON Nuclei output line: %r", line[:80])

        logger.info("Nuclei scan completed. %d finding(s) for %r.", len(findings), target)
        return findings

    def _normalize(self, raw: dict) -> dict:
        """Convert a Nuclei JSON finding to the SwitchGuard vulnerability schema."""
        info      = raw.get("info", {})
        severity  = SEVERITY_MAP.get(info.get("severity", "unknown").lower(), "Low")
        cve_ids   = info.get("classification", {}).get("cve-id", [])
        cwe_ids   = info.get("classification", {}).get("cwe-id", [])
        cvss      = info.get("classification", {}).get("cvss-score")

        return {
            "title":       info.get("name", raw.get("template-id", "Unknown")),
            "description": info.get("description", ""),
            "severity":    severity,
            "url":         raw.get("matched-at", raw.get("host", "")),
            "solution":    info.get("remediation", ""),
            "evidence":    json.dumps(raw.get("extracted-results", raw.get("matcher-name", ""))),
            "cve_id":      cve_ids[0] if cve_ids else None,
            "cwe_id":      cwe_ids[0].replace("CWE-", "") if cwe_ids else None,
            "cvss_score":  float(cvss) if cvss else None,
            "source":      "nuclei",
            "template_id": raw.get("template-id"),
        }
