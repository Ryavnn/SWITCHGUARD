"""
Nikto Scanner Adapter
=====================
Wraps the Nikto web server scanner CLI.
Nikto must be installed: https://github.com/sullo/nikto
"""

import subprocess
import json
import logging
import shutil
import os
from typing import List, Dict

logger = logging.getLogger(__name__)

NIKTO_TIMEOUT = int(os.getenv("NIKTO_TIMEOUT", "300"))

SEVERITY_MAP = {
    "0": "Informational",
    "1": "Informational",
    "2": "Low",
    "3": "Medium",
    "4": "High",
    "5": "Critical",
}


def is_nikto_installed() -> bool:
    return shutil.which("nikto") is not None or shutil.which("nikto.pl") is not None


class NiktoScanner:
    """
    Runs Nikto against a web target and returns normalized findings.
    """

    def run_scan(self, target: str) -> List[Dict]:
        """
        Execute Nikto against *target* (URL or IP).

        Returns a list of normalized finding dicts.
        """
        binary = shutil.which("nikto") or shutil.which("nikto.pl")
        if not binary:
            logger.warning("Nikto is not installed or not in PATH. Skipping Nikto scan.")
            return []

        cmd = [
            binary,
            "-h", target,
            "-Format", "json",
            "-nointeractive",
            "-ask", "no",
        ]

        logger.info("Running Nikto on %r", target)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=NIKTO_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.error("Nikto scan timed out for %r", target)
            return []
        except Exception as e:
            logger.error("Nikto scan failed: %s", e)
            return []

        findings = []
        try:
            data = json.loads(result.stdout)
            vulnerabilities = data.get("vulnerabilities", [])
            for v in vulnerabilities:
                findings.append(self._normalize(v))
        except (json.JSONDecodeError, KeyError):
            # Older Nikto versions output plain text; parse line by line
            for line in result.stdout.strip().split("\n"):
                if line.startswith("+"):
                    findings.append({
                        "title":       line[2:80].strip(),
                        "description": line[2:].strip(),
                        "severity":    "Low",
                        "url":         target,
                        "solution":    "",
                        "evidence":    "",
                        "source":      "nikto",
                    })

        logger.info("Nikto scan completed. %d finding(s).", len(findings))
        return findings

    def _normalize(self, raw: dict) -> dict:
        return {
            "title":       raw.get("msg", raw.get("id", "Nikto Finding")),
            "description": raw.get("msg", ""),
            "severity":    SEVERITY_MAP.get(str(raw.get("osvdbid", "0")), "Low"),
            "url":         raw.get("url", ""),
            "solution":    "",
            "evidence":    raw.get("namelink", ""),
            "cve_id":      None,
            "cwe_id":      None,
            "cvss_score":  None,
            "source":      "nikto",
        }
