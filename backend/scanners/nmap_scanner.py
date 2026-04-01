import nmap
import logging
import json
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Explicit search path — covers Windows default install + common Linux locations
NMAP_SEARCH_PATH = (
    "nmap",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/sw/bin/nmap",
    "/opt/local/bin/nmap",
)


class NmapScanner:
    """
    Wraps python-nmap to execute port/service scans.

    Notes
    -----
    • -O (OS detection) requires Administrator / root privileges.
      Pass arguments="-sV -O -T4" only when running elevated.
    • On Windows, Nmap must be installed and Npcap must be present.
      The scanner explicitly includes the default Windows install path.
    """

    def __init__(self):
        try:
            self.nm = nmap.PortScanner(nmap_search_path=NMAP_SEARCH_PATH)
            logger.info("Nmap initialised successfully (version: %s).", self.nm.nmap_version())
        except nmap.PortScannerError as e:
            logger.error(
                "Nmap not found. Install Nmap (https://nmap.org/download.html) "
                "and ensure it is in your system PATH or at one of the expected paths. "
                "Detail: %s", e
            )
            raise
        except Exception as e:
            logger.error("Unexpected error initialising Nmap: %s", e)
            raise

    def run_scan(self, target: str, arguments: str = "-sV -T4 --open") -> dict:
        """
        Execute an Nmap scan against *target* and return a JSON-safe dict.

        Parameters
        ----------
        target :
            IP address, hostname, or CIDR range (e.g. "192.168.1.0/24").
        arguments :
            Nmap flags. Default includes ``--open`` so only open ports are
            returned, making the result set smaller and easier to parse.
            Add ``-O`` when running as Administrator for OS detection.

        Returns
        -------
        dict
            Keys: ``scan`` (per-host data), ``nmap_info`` (scanner metadata).
            Always returns a dict — never raises on an empty result.
        """
        logger.info("Starting Nmap scan on %r with args: %r", target, arguments)

        try:
            self.nm.scan(hosts=target, arguments=arguments)
        except nmap.PortScannerError as e:
            # Common causes: nmap not found, insufficient privileges, bad target
            logger.error("Nmap PortScannerError for %r: %s", target, e)
            raise RuntimeError(f"Nmap scan failed: {e}") from e
        except Exception as e:
            logger.error("Nmap scan failed for %r: %s", target, e)
            raise

        hosts = self.nm.all_hosts()
        if not hosts:
            logger.warning(
                "Nmap returned no hosts for %r. "
                "The target may be offline, blocked by a firewall, or unreachable.",
                target,
            )
            return {"scan": {}, "nmap_info": self.nm.scaninfo()}

        raw = self.nm._scan_result
        result = self._make_serializable(raw)

        # Log a quick summary
        for host in hosts:
            open_ports = [
                p for p in self.nm[host].all_tcp()
                if self.nm[host]["tcp"][p]["state"] == "open"
            ]
            logger.info("Host %s — %d open TCP port(s): %s", host, len(open_ports), open_ports)

        return result

    def run_diagnostic(self) -> dict:
        """Ping-scan localhost to confirm Nmap is functional. Returns status dict."""
        try:
            self.nm.scan("127.0.0.1", arguments="-sn")
            return {"ok": True, "version": str(self.nm.nmap_version()), "hosts": self.nm.all_hosts()}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_serializable(self, obj):
        """Recursively convert any non-JSON-native types to strings."""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._make_serializable(i) for i in obj]
        if isinstance(obj, (int, float, bool)) or obj is None:
            return obj
        # Fallback: test serialisability, stringify if needed
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)