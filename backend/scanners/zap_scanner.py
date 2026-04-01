"""
OWASP ZAP Scanner
=================

Prerequisites — ZAP must be running in daemon mode BEFORE any scan:

    Windows (PowerShell):
        & "C:\\Program Files\\ZAP\\Zed Attack Proxy\\zap.bat" `
            -daemon -port 8080 `
            -config api.key=switchguard2024 `
            -config api.addrs.addr.name=.* `
            -config api.addrs.addr.regex=true

    Linux / macOS:
        zap.sh -daemon -port 8080 \\
            -config api.key=switchguard2024 \\
            -config api.addrs.addr.name=.* \\
            -config api.addrs.addr.regex=true

    Docker (quickest):
        docker run -d -p 8080:8080 \\
            ghcr.io/zaproxy/zaproxy:stable \\
            zap.sh -daemon -port 8080 \\
            -config api.key=switchguard2024 \\
            -config api.addrs.addr.name=.* \\
            -config api.addrs.addr.regex=true

Environment variables consumed (backend/.env):
    ZAP_URL      – default: http://127.0.0.1:8080
    ZAP_API_KEY  – default: switchguard2024   ← must match how ZAP was started
"""

import os
import time
import json
import logging
import requests
from zapv2 import ZAPv2
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ZAP_URL = os.getenv("ZAP_URL", "http://127.0.0.1:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "12345")

# Poll intervals (seconds)
SPIDER_POLL_INTERVAL = 3
ASCAN_POLL_INTERVAL  = 5
ZAP_CONNECT_TIMEOUT  = 5   # seconds for connectivity probe


def is_zap_running(url: str = ZAP_URL, timeout: int = ZAP_CONNECT_TIMEOUT) -> bool:
    """
    Quick liveness probe — returns True only if ZAP is accepting connections
    and responding to its own version endpoint.
    """
    try:
        resp = requests.get(
            f"{url}/JSON/core/view/version/",
            params={"apikey": ZAP_API_KEY},
            timeout=timeout,
        )
        return resp.status_code == 200
    except Exception:
        return False


class ZapScanner:
    """Wraps the OWASP ZAP REST API for spider + active scanning."""

    def __init__(self, target_url: str):
        self.target = target_url
        proxies = {"http": ZAP_URL, "https": ZAP_URL}
        self.zap = ZAPv2(apikey=ZAP_API_KEY, proxies=proxies)
        logger.info("ZapScanner initialised for %r via %s", target_url, ZAP_URL)

    # ------------------------------------------------------------------
    # Liveness / connectivity helpers
    # ------------------------------------------------------------------

    def _check_zap_alive(self):
        """
        Raises a descriptive RuntimeError if ZAP is not responding.
        Call this at the start of every public method.
        """
        if not is_zap_running():
            raise RuntimeError(
                f"Cannot connect to ZAP at {ZAP_URL}. "
                "ZAP must be running in daemon mode before a scan can be triggered. "
                "Start ZAP with: "
                "zap.bat -daemon -port 8080 -config api.key=switchguard2024 "
                "-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"
            )
        logger.info("ZAP liveness check passed (version: %s).", self.zap.core.version)

    def _access_target(self):
        """
        Forces ZAP to add the target to its Site Tree by loading the URL
        through the ZAP proxy.  Without this the Spider may return zero URLs.
        """
        logger.info("ZAP: seeding Site Tree with %r …", self.target)
        try:
            self.zap.urlopen(self.target)
        except Exception as e:
            # Non-fatal — ZAP may still be able to crawl without this seed
            logger.warning("ZAP urlopen failed (non-fatal): %s", e)
        time.sleep(2)

    def _validate_scan_id(self, scan_id, scan_label: str):
        """
        ZAP returns a numeric string on success or an error dict / string on
        failure (e.g. 'url_not_in_context', 'does_not_exist').  Raise a
        descriptive error immediately so the problem surfaces in logs.
        """
        if not str(scan_id).isdigit():
            raise RuntimeError(
                f"ZAP {scan_label} failed to start. "
                f"Response: {scan_id!r}. "
                "Ensure the target URL is reachable and has been added to ZAP's context."
            )

    # ------------------------------------------------------------------
    # Public scan methods
    # ------------------------------------------------------------------

    def run_spider(self, cancellation_check=None) -> list:
        """
        Spider the target and return the list of URLs found.

        Parameters
        ----------
        cancellation_check : callable, optional
            Zero-argument callable → True when the scan should be aborted.
        """
        self._check_zap_alive()
        self._access_target()

        logger.info("ZAP Spider starting on %r", self.target)
        scan_id = self.zap.spider.scan(self.target)
        self._validate_scan_id(scan_id, "Spider")

        while True:
            progress = int(self.zap.spider.status(scan_id))
            logger.info("  Spider progress: %d%%", progress)

            if cancellation_check and cancellation_check():
                logger.info("Cancellation requested — stopping spider.")
                self.zap.spider.stop(scan_id)
                return []

            if progress >= 100:
                break
            time.sleep(SPIDER_POLL_INTERVAL)

        urls = list(self.zap.spider.results(scan_id))
        logger.info("ZAP Spider completed. %d URL(s) found.", len(urls))
        return urls

    def run_active_scan(self, cancellation_check=None) -> list:
        """
        Run ZAP active scan against the target; return serialisable alert list.

        Parameters
        ----------
        cancellation_check : callable, optional
            Zero-argument callable → True when the scan should be aborted.
        """
        self._check_zap_alive()

        logger.info("ZAP Active Scan starting on %r", self.target)
        scan_id = self.zap.ascan.scan(self.target)
        self._validate_scan_id(scan_id, "Active Scan")

        while True:
            progress = int(self.zap.ascan.status(scan_id))
            logger.info("  Active Scan progress: %d%%", progress)

            if cancellation_check and cancellation_check():
                logger.info("Cancellation requested — stopping active scan.")
                self.zap.ascan.stop(scan_id)
                return []

            if progress >= 100:
                break
            time.sleep(ASCAN_POLL_INTERVAL)

        logger.info("ZAP Active Scan completed.")
        alerts = self.zap.core.alerts(baseurl=self.target)
        logger.info("ZAP found %d alert(s) for %r.", len(alerts), self.target)
        return self._make_serializable(alerts)

    def run_full_scan(self, cancellation_check=None) -> list:
        """
        Convenience method: Spider → Active Scan → alerts.
        This is the recommended entry-point for the background task.
        """
        self.run_spider(cancellation_check=cancellation_check)
        return self.run_active_scan(cancellation_check=cancellation_check)

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _make_serializable(self, obj):
        """Recursively convert any non-JSON-native types."""
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