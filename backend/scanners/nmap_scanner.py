"""
Nmap Scanner — Extended with Scan Profiles
==========================================
Added:
  - Reusable scan profiles (fast/standard/deep/udp/vuln)
  - run_profile_scan() entry point
  - Improved error messages
"""

import nmap
import logging
import json
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

NMAP_SEARCH_PATH = (
    "nmap",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/sw/bin/nmap",
    "/opt/local/bin/nmap",
)

# ── Scan Profiles ──────────────────────────────────────────────────────────────
SCAN_PROFILES = {
    "fast":     "-sV -T4 --open -F",
    "standard": "-sV -T4 --open",
    "deep":     "-sV -sC -O -T3 -p- --open",
    "udp":      "-sU -sV -T4 --open --top-ports 200",
    "vuln":     "-sV --script vuln,smb-security-mode,ftp-anon,telnet-info -T4 --open",
}


class NmapScanner:
    """
    Wraps python-nmap to execute port/service scans.

    Profiles
    --------
    fast       – Quick top-port scan (default -F)
    standard   – Service version detection, most common ports
    deep       – Full port range, OS detection, default NSE scripts
    udp        – Top-200 UDP ports + service detection
    vuln       – Service detection + vulnerability NSE scripts
    """

    def __init__(self):
        try:
            self.nm = nmap.PortScanner(nmap_search_path=NMAP_SEARCH_PATH)
            logger.info("Nmap initialised successfully (version: %s).", self.nm.nmap_version())
        except nmap.PortScannerError as e:
            logger.error(
                "Nmap not found. Install Nmap (https://nmap.org/download.html) "
                "and ensure it is in your system PATH. Detail: %s", e
            )
            raise
        except Exception as e:
            logger.error("Unexpected error initialising Nmap: %s", e)
            raise

    def run_scan(self, target: str, arguments: str = "-sV -T4 --open") -> dict:
        """Execute an Nmap scan against *target* and return a JSON-safe dict."""
        logger.info("Starting Nmap scan on %r with args: %r", target, arguments)
        try:
            self.nm.scan(hosts=target, arguments=arguments)
        except nmap.PortScannerError as e:
            logger.error("Nmap PortScannerError for %r: %s", target, e)
            raise RuntimeError(f"Nmap scan failed: {e}") from e
        except Exception as e:
            logger.error("Nmap scan failed for %r: %s", target, e)
            raise

        hosts = self.nm.all_hosts()
        if not hosts:
            logger.warning(
                "Nmap returned no hosts for %r. "
                "The target may be offline or blocked by a firewall.",
                target,
            )
            return {"scan": {}, "nmap_info": self.nm.scaninfo()}

        raw    = self.nm._scan_result
        result = self._make_serializable(raw)

        for host in hosts:
            try:
                open_ports = [
                    p for p in self.nm[host].all_tcp()
                    if self.nm[host]["tcp"][p]["state"] == "open"
                ]
                logger.info("Host %s — %d open TCP port(s): %s", host, len(open_ports), open_ports)
            except Exception:
                pass

        return result

    def run_profile_scan(self, target: str, profile: str = "standard", custom_args: str = None) -> dict:
        """
        Run the scan using a named profile.

        Args:
            target:      IP, hostname, or CIDR block.
            profile:     One of fast / standard / deep / udp / vuln.
            custom_args: If provided, overrides profile entirely.
        """
        args = custom_args or SCAN_PROFILES.get(profile, SCAN_PROFILES["standard"])
        logger.info("Running Nmap profile=%r args=%r on %r", profile, args, target)
        return self.run_scan(target, arguments=args)

    def run_diagnostic(self) -> dict:
        """Ping-scan localhost to confirm Nmap is functional."""
        try:
            self.nm.scan("127.0.0.1", arguments="-sn")
            return {"ok": True, "version": str(self.nm.nmap_version()), "hosts": self.nm.all_hosts()}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _make_serializable(self, obj):
        """Recursively convert any non-JSON-native types to strings."""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._make_serializable(i) for i in obj]
        if isinstance(obj, (int, float, bool)) or obj is None:
            return obj
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)