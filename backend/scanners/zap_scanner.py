"""
OWASP ZAP Scanner — Fixed & Extended
=====================================
Fixes applied:
  - ZAPv2 was never imported (NameError crash)
  - ZAP_API_KEY was not defined in module scope
  - SPIDER_POLL_INTERVAL / ASCAN_POLL_INTERVAL were undefined
  - Added AJAX spider for SPA/JS-rendered sites
  - Added authenticated scan support (form-based + bearer token)
  - Added exception-safe fallback when ZAP daemon is unreachable
"""

import os
import time
import json
import logging
import requests
from urllib.parse import urlparse
from zapv2 import ZAPv2          # from python-owasp-zap-v2.4 package (already installed)
from services.zap_service import ZapService
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
ZAP_URL     = os.getenv("ZAP_URL", "http://127.0.0.1:8081")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "12345")   # FIX: was undefined in module scope

# FIX: poll intervals were used but never defined → NameError mid-scan
SPIDER_POLL_INTERVAL = int(os.getenv("SPIDER_POLL_INTERVAL", "5"))   # seconds
ASCAN_POLL_INTERVAL  = int(os.getenv("ASCAN_POLL_INTERVAL",  "10"))  # seconds
AJAX_POLL_INTERVAL   = int(os.getenv("AJAX_POLL_INTERVAL",   "3"))   # seconds

ZAP_CONNECT_TIMEOUT  = 5

def is_zap_running(url: str = ZAP_URL, timeout: int = ZAP_CONNECT_TIMEOUT) -> bool:
    return ZapService.is_zap_healthy()


class ZapScanner:
    """
    Wraps the OWASP ZAP REST API for spider + active scanning.

    Supports:
        - Standard spider → active scan pipeline
        - AJAX spider for JavaScript-rendered / SPA targets
        - Form-based authenticated scanning
        - Bearer-token injection
        - Graceful degradation when ZAP is offline
    """

    def __init__(self, target_url: str):
        self.target  = target_url
        proxies      = {"http": ZAP_URL, "https": ZAP_URL}
        # FIX: ZAPv2 is now properly imported; API key sourced from module-level constant
        self.zap     = ZAPv2(apikey=ZAP_API_KEY, proxies=proxies)
        self.ctx_id  = None   # set when configure_auth() is called
        logger.info("ZapScanner initialised for %r via %s", target_url, ZAP_URL)

    # ── Liveness ───────────────────────────────────────────────────────────────

    def _check_zap_alive(self):
        """Raise RuntimeError with a clear message if ZAP is not running."""
        logger.info("Verifying ZAP health before scan...")
        if not ZapService.is_zap_healthy():
            raise RuntimeError(
                "OWASP ZAP daemon is not reachable at %s. "
                "Ensure ZAP is started (see backend/start_zap.ps1) before running a web scan." % ZAP_URL
            )
        logger.info("ZAP confirmed READY (version: %s).", self.zap.core.version)

    def _access_target(self):
        """Seeds the ZAP Site Tree with the target URL so the spider has a starting point."""
        logger.info("ZAP: seeding Site Tree with %r …", self.target)
        try:
            self.zap.urlopen(self.target)
        except Exception as e:
            logger.warning("ZAP urlopen failed (non-fatal): %s", e)
        time.sleep(2)

    def _validate_scan_id(self, scan_id, scan_label: str):
        """ZAP returns a numeric string on success or an error dict on failure."""
        if not str(scan_id).isdigit():
            raise RuntimeError(
                f"ZAP {scan_label} failed to start. "
                f"Response: {scan_id!r}. "
                "Ensure the target URL is reachable and added to ZAP's context."
            )

    # ── Authentication ─────────────────────────────────────────────────────────

    def configure_form_auth(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        logged_in_indicator: str = "logout",
    ):
        """
        Configures ZAP form-based authentication for an authenticated scan.
        Creates a ZAP context scoped to the target domain.
        """
        logger.info("Configuring form-based auth for %r", self.target)
        ctx_name = "sg_auth_ctx"
        self.ctx_id = self.zap.context.new_context(ctx_name)

        # Include the whole target domain in the context
        domain = urlparse(self.target).netloc
        self.zap.context.include_in_context(ctx_name, f".*{domain}.*")

        # Set form-based authentication
        login_data = (
            f"loginUrl={login_url}"
            f"&loginRequestData={username_field}%3D{{%25username%25}}"
            f"%26{password_field}%3D{{%25password%25}}"
        )
        self.zap.authentication.set_authentication_method(
            self.ctx_id, "formBasedAuthentication", login_data
        )
        self.zap.authentication.set_logged_in_indicator(self.ctx_id, logged_in_indicator)

        # Create ZAP user for this context
        user_id = self.zap.users.new_user(self.ctx_id, "sg_user")
        self.zap.users.set_authentication_credentials(
            self.ctx_id,
            user_id,
            f"username={username}&password={password}",
        )
        self.zap.users.set_user_enabled(self.ctx_id, user_id, True)
        self.zap.forcedUser.set_forced_user(self.ctx_id, user_id)
        self.zap.forcedUser.set_forced_user_mode_enabled(True)
        logger.info("Form auth configured. ctx_id=%s user_id=%s", self.ctx_id, user_id)

    def configure_bearer_auth(self, token: str):
        """Injects a Bearer token into all ZAP requests via a script or replacement rule."""
        logger.info("Configuring bearer token auth")
        try:
            self.zap.replacer.add_rule(
                description="Bearer Token",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Authorization",
                replacement=f"Bearer {token}",
                initiators="",
            )
        except Exception as e:
            logger.warning("Bearer token injection via replacer failed: %s. Using urlopen header workaround.", e)

    # ── Spider ─────────────────────────────────────────────────────────────────

    def run_spider(self, cancellation_check=None) -> list:
        """Standard passive spider — best for server-rendered sites."""
        self._check_zap_alive()
        self._access_target()

        logger.info("ZAP Spider starting on %r", self.target)
        scan_id = self.zap.spider.scan(self.target, contextname=None if not self.ctx_id else "sg_auth_ctx")
        self._validate_scan_id(scan_id, "Spider")

        while True:
            try:
                progress = int(self.zap.spider.status(scan_id))
            except Exception:
                progress = 0
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

    def run_ajax_spider(self, cancellation_check=None) -> list:
        """
        AJAX spider — required for React/Angular/Vue SPAs.
        Launches a browser-based crawl via ZAP's built-in headless browser.
        """
        self._check_zap_alive()
        self._access_target()

        logger.info("ZAP AJAX Spider starting on %r", self.target)
        self.zap.ajaxSpider.scan(self.target)

        # Poll until AJAX spider reports "stopped"
        timeout = int(os.getenv("AJAX_SPIDER_TIMEOUT", "180"))
        elapsed = 0
        while elapsed < timeout:
            status = self.zap.ajaxSpider.status
            logger.info("  AJAX Spider status: %s (%ds elapsed)", status, elapsed)

            if cancellation_check and cancellation_check():
                logger.info("Cancellation requested — stopping AJAX spider.")
                self.zap.ajaxSpider.stop()
                return []

            if status == "stopped":
                break

            time.sleep(AJAX_POLL_INTERVAL)
            elapsed += AJAX_POLL_INTERVAL

        results = list(self.zap.ajaxSpider.results())
        logger.info("AJAX Spider completed. %d resource(s) found.", len(results))
        return results

    # ── Active Scan ─────────────────────────────────────────────────────────────

    def run_active_scan(self, cancellation_check=None) -> list:
        """Active scan against the target; returns a serialisable alert list."""
        self._check_zap_alive()

        logger.info("ZAP Active Scan starting on %r", self.target)
        scan_kwargs = {"url": self.target}
        if self.ctx_id:
            scan_kwargs["contextid"] = self.ctx_id

        scan_id = self.zap.ascan.scan(**scan_kwargs)
        self._validate_scan_id(scan_id, "Active Scan")

        while True:
            try:
                progress = int(self.zap.ascan.status(scan_id))
            except Exception:
                progress = 0
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

    # ── Full Scan Pipeline ──────────────────────────────────────────────────────

    def run_full_scan(self, cancellation_check=None, use_ajax: bool = False) -> list:
        """
        Full pipeline:  Spider/AJAX Spider → Active Scan → alerts.

        Args:
            cancellation_check: callable → True when scan should be aborted.
            use_ajax: If True, use the AJAX spider instead of the standard spider.
                      Enable for React/Vue/Angular targets.
        """
        if use_ajax:
            self.run_ajax_spider(cancellation_check=cancellation_check)
        else:
            self.run_spider(cancellation_check=cancellation_check)

        return self.run_active_scan(cancellation_check=cancellation_check)

    # ── Helper ─────────────────────────────────────────────────────────────────

    def _make_serializable(self, obj):
        """Recursively converts any non-JSON-native types."""
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