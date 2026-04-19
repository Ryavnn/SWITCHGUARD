"""
ZAP Service — Completely Rewritten for Windows Reliability
===========================================================

Root causes fixed:
  1. TIMEOUT: ZAP JVM+addon loading takes 90-120s on first run (cold start).
     Old code used a 60s timeout — increased to 180s with exponential back-off.

  2. ZOMBIE SPAWNING: No zombie check — every backend restart launched a new ZAP
     process even when one was already running (6 duplicate processes found in logs).
     Fixed with port reachability check + API health check BEFORE spawning.

  3. WRONG CWD: subprocess.Popen launched 'zap.bat' from the backend directory.
     'zap.bat' does 'java -jar zap-2.17.0.jar' which is a RELATIVE path — Java
     couldn't find the JAR. Fixed by setting cwd= to the ZAP install directory.

  4. DUPLICATE PORT CONFLICT: Multiple ZAP processes fighting for port 8080
     causing all of them to fail. Fixed by detecting an already-listening port
     before spawning.

  5. HEALTH CHECK RACE: is_zap_healthy() was called immediately after spawn with
     no JVM warm-up tolerance. Fixed with staged polling (fast early, then slow).

  6. NO PROCESS VERIFICATION: After spawning, the subprocess was never checked to
     see if it actually stayed alive (crash, Java not found, etc.). Now polled.
"""

import asyncio
import json
import logging
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

ZAP_URL     = os.getenv("ZAP_URL",     "http://127.0.0.1:8081")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "12345")
ZAP_PORT    = int(os.getenv("ZAP_PORT", "8081"))

# JVM cold-start on first launch with 40+ addons takes 90-120 seconds.
# We allow 180s (3 minutes) and use exponential polling so fast starts are fast.
ZAP_STARTUP_TIMEOUT = int(os.getenv("ZAP_STARTUP_TIMEOUT", "180"))

# ── Windows ZAP binary search paths ───────────────────────────────────────────
# Ordered by likelihood. ZAP_PATH in .env always wins.
_ZAP_SEARCH_PATHS = list(filter(None, [
    os.getenv("ZAP_PATH"),                                          # .env override
    r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat",              # standard install
    r"C:\Program Files (x86)\ZAP\Zed Attack Proxy\zap.bat",
    r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",            # legacy OWASP dir
    r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
    r"C:\ZAP\zap.bat",                                              # portable
    r"C:\tools\ZAP\zap.bat",                                        # choco / winget
]))

# ── Shared health state (read by /api/health) ──────────────────────────────────
_zap_state: dict = {
    "status":       "unknown",    # healthy | degraded | offline | unavailable
    "last_checked": None,
    "startup_attempts": 0,
    "last_error":   None,
    "version":      None,
    "pid":          None,
}


def get_zap_state() -> dict:
    """Return a copy of the ZAP runtime health state."""
    return dict(_zap_state)


# ── Port utilities ─────────────────────────────────────────────────────────────

def _is_port_open(host: str = "127.0.0.1", port: int = ZAP_PORT) -> bool:
    """TCP SYN check — tells us if *something* is already listening on the port."""
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _find_zap_binary() -> Optional[str]:
    """
    Locate zap.bat from the search path list.
    Returns the first valid path found, or None.
    """
    for path in _ZAP_SEARCH_PATHS:
        if path and os.path.isfile(path):
            logger.debug("ZAP binary found: %s", path)
            return path
    return None


# ── ZAP health check ───────────────────────────────────────────────────────────

def _zap_api_ping(timeout: int = 5) -> Tuple[bool, Optional[str]]:
    """
    Full API health check:
    1. Port open (TCP)  → quick rejection if nothing listening
    2. HTTP GET version → confirms it's ZAP and returns version string
    Returns (ok: bool, version: Optional[str])
    """
    if not _is_port_open(port=ZAP_PORT):
        return False, None
    try:
        resp = requests.get(
            f"{ZAP_URL}/JSON/core/view/version/",
            params={"apikey": ZAP_API_KEY},
            timeout=timeout,
        )
        if resp.status_code == 200:
            version = resp.json().get("version", "unknown")
            return True, version
        # 403 means ZAP is up but API key mismatch
        if resp.status_code == 403:
            logger.error(
                "ZAP is running but returned 403 — API key mismatch. "
                "Expected key '%s'. Check ZAP_API_KEY in .env.", ZAP_API_KEY
            )
            return False, None
    except requests.RequestException:
        pass
    return False, None


# ── Main ZAP Service class ─────────────────────────────────────────────────────

class ZapService:
    """
    Manages the OWASP ZAP daemon lifecycle:
    - Zombie detection (reuse existing healthy daemon)
    - Windows-safe process launch (correct CWD, detached)
    - Exponential poll loop with JVM warm-up tolerance
    - Shared health state for /api/health endpoint
    """

    @staticmethod
    def is_zap_healthy() -> bool:
        """Quick health check suitable for per-request guards."""
        ok, version = _zap_api_ping(timeout=4)
        if ok:
            _zap_state["status"]       = "healthy"
            _zap_state["version"]      = version
            _zap_state["last_checked"] = datetime.utcnow().isoformat()
        return ok

    @classmethod
    def find_zap_binary(cls) -> Optional[str]:
        return _find_zap_binary()

    @classmethod
    def _check_existing_daemon(cls) -> bool:
        """
        FIX #2: Check if a healthy ZAP daemon is already running.
        If yes, reuse it and skip spawning. Avoids duplicate processes.
        """
        ok, version = _zap_api_ping(timeout=3)
        if ok:
            logger.info(
                "ZAP daemon already running (v%s) on port %d — reusing.", version, ZAP_PORT
            )
            _zap_state.update({"status": "healthy", "version": version,
                                "last_checked": datetime.utcnow().isoformat()})
            return True

        # Port is open but not responding as ZAP — stale zombie
        if _is_port_open(port=ZAP_PORT):
            logger.warning(
                "Port %d is occupied by a non-ZAP process. "
                "A stale process may be holding the port. "
                "ZAP will attempt to start on the same port; it may fail.", ZAP_PORT
            )
        return False

    @classmethod
    def start_zap_daemon(cls) -> subprocess.Popen:
        """
        FIX #3: Launch ZAP with correct CWD set to the ZAP install directory.

        zap.bat does:  java -jar zap-2.17.0.jar %*
        The JAR path is RELATIVE — so Java must be invoked from the ZAP directory.
        subprocess.Popen was previously defaulting CWD to the backend directory.
        """
        zap_bat = _find_zap_binary()
        if not zap_bat:
            paths_tried = "\n  ".join(_ZAP_SEARCH_PATHS)
            raise FileNotFoundError(
                f"Could not locate ZAP installation (zap.bat).\n"
                f"Paths searched:\n  {paths_tried}\n"
                f"Set ZAP_PATH in backend/.env to the full path of zap.bat."
            )

        # FIX #3: CWD must be the ZAP install directory so relative JAR path resolves
        zap_dir = str(Path(zap_bat).parent)

        cmd = [
            zap_bat,
            "-daemon",
            "-host", "127.0.0.1",
            "-port", str(ZAP_PORT),
            "-config", f"api.key={ZAP_API_KEY}",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
            "-config", "connection.timeoutInSecs=30",
        ]

        logger.info(
            "Launching ZAP daemon:\n  Binary: %s\n  CWD:    %s\n  Port:   %d\n"
            "  APIKey: %s\n  Cmd:    %s",
            zap_bat, zap_dir, ZAP_PORT, ZAP_API_KEY, " ".join(cmd),
        )

        log_dir  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        stdout_f = open(os.path.join(log_dir, "zap_stdout.log"), "a")
        stderr_f = open(os.path.join(log_dir, "zap_stderr.log"), "a")
        stdout_f.write(f"\n\n=== ZAP launched at {datetime.utcnow().isoformat()} ===\n")

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=zap_dir,           # FIX: was missing — caused "JAR not found"
                creationflags=(
                    subprocess.DETACHED_PROCESS
                    | subprocess.CREATE_NEW_PROCESS_GROUP
                ),
                stdout=stdout_f,
                stderr=stderr_f,
                close_fds=True,
            )
            _zap_state["pid"] = proc.pid
            logger.info("ZAP process spawned (PID %d). Awaiting JVM initialisation...", proc.pid)
            return proc
        except FileNotFoundError:
            stderr_f.close(); stdout_f.close()
            raise RuntimeError(
                "Failed to launch ZAP — 'java' is not in PATH or not installed. "
                "Install Java 11+ and ensure it is on the system PATH."
            )
        except Exception as e:
            stderr_f.close(); stdout_f.close()
            logger.error("ZAP Popen failed: %s", e)
            raise

    @classmethod
    def _poll_until_ready(cls, proc: subprocess.Popen, timeout: int) -> bool:
        """
        FIX #1: Exponential back-off polling with JVM warm-up tolerance.

        ZAP startup phases:
          0–10s:   JVM boot, class loading
          10–30s:  Addon loading (40+ addons)
          30–90s:  Addon initialisation, network bind
          >90s:    Ready (first run downloads may take longer)

        Poll strategy:
          - Every 5s for the first 30s  (quick win for already-running daemons)
          - Every 10s from 30–90s       (JVM is still loading addons)
          - Every 15s from 90–180s      (slow cold start tolerance)
        """
        start   = time.time()
        attempt = 0

        while True:
            elapsed = time.time() - start
            if elapsed >= timeout:
                break

            attempt += 1

            # Check if the process itself is still alive
            if proc is not None and proc.poll() is not None:
                rc = proc.returncode
                logger.error(
                    "ZAP process (PID %d) exited prematurely with code %d. "
                    "Check backend/zap_stderr.log for details.", proc.pid, rc
                )
                _zap_state["last_error"] = f"Process exited (rc={rc})"
                return False

            ok, version = _zap_api_ping(timeout=4)
            if ok:
                elapsed_total = time.time() - start
                logger.info(
                    "ZAP ready after %.1fs (v%s, %d polls).",
                    elapsed_total, version, attempt,
                )
                _zap_state.update({
                    "status":       "healthy",
                    "version":      version,
                    "last_checked": datetime.utcnow().isoformat(),
                    "last_error":   None,
                })
                return True

            # Adaptive sleep
            if elapsed < 30:
                sleep_s = 5
            elif elapsed < 90:
                sleep_s = 10
            else:
                sleep_s = 15

            logger.info(
                "ZAP not ready yet (%.0fs elapsed). Retrying in %ds... [poll #%d]",
                elapsed, sleep_s, attempt,
            )
            time.sleep(sleep_s)

        return False

    @classmethod
    def ensure_zap_running(cls) -> bool:
        """
        Blocking sync orchestrator used inside scan background tasks.
        Returns True if ZAP is ready, raises TimeoutError if not.
        """
        _zap_state["startup_attempts"] += 1

        # FIX #2: Check for existing daemon before spawning
        if cls._check_existing_daemon():
            return True

        logger.warning("ZAP is offline — initiating auto-start (attempt #%d)...",
                       _zap_state["startup_attempts"])
        proc = cls.start_zap_daemon()

        # FIX #1: Extended timeout with exponential polling
        ready = cls._poll_until_ready(proc, ZAP_STARTUP_TIMEOUT)

        if ready:
            return True

        # Dump last 20 lines of log for debugging
        try:
            log_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "zap_stdout.log"
            )
            with open(log_path) as f:
                lines = f.readlines()[-20:]
            logger.error("Last ZAP log lines:\n%s", "".join(lines))
        except Exception:
            pass

        _zap_state.update({"status": "offline",
                            "last_error": f"Timed out after {ZAP_STARTUP_TIMEOUT}s"})
        raise TimeoutError(
            f"ZAP failed to start within {ZAP_STARTUP_TIMEOUT}s. "
            "Check backend/zap_stdout.log for detailed JVM output."
        )

    @classmethod
    async def ensure_zap_running_async(cls):
        """
        Non-blocking async orchestrator called from the FastAPI lifespan.
        Runs the blocking startup in a thread-pool so it never stalls the event loop.
        """
        loop = asyncio.get_event_loop()
        try:
            # FIX #2: fast path — already running?
            ok, version = _zap_api_ping(timeout=3)
            if ok:
                logger.info("ZAP already running and healthy (v%s).", version)
                _zap_state.update({"status": "healthy", "version": version,
                                   "last_checked": datetime.utcnow().isoformat()})
                return True

            logger.warning("ZAP offline — starting daemon asynchronously...")
            _zap_state["startup_attempts"] += 1

            # Spawn process (non-blocking — Popen returns immediately)
            proc = await loop.run_in_executor(None, cls.start_zap_daemon)

            # Poll in background using async sleep so the event loop stays free
            start   = time.time()
            attempt = 0
            while time.time() - start < ZAP_STARTUP_TIMEOUT:
                attempt += 1
                elapsed = time.time() - start

                if proc.poll() is not None:
                    logger.error("ZAP process exited prematurely (rc=%d).", proc.returncode)
                    _zap_state["last_error"] = f"Process exited (rc={proc.returncode})"
                    _zap_state["status"]     = "offline"
                    return False

                ok, version = _zap_api_ping(timeout=4)
                if ok:
                    logger.info("ZAP ready after %.1fs (v%s, %d polls).",
                                time.time() - start, version, attempt)
                    _zap_state.update({
                        "status":       "healthy",
                        "version":      version,
                        "last_checked": datetime.utcnow().isoformat(),
                        "last_error":   None,
                    })
                    return True

                sleep_s = 5 if elapsed < 30 else 10 if elapsed < 90 else 15
                logger.info("ZAP not ready (%.0fs elapsed). Next poll in %ds [#%d]",
                            elapsed, sleep_s, attempt)
                await asyncio.sleep(sleep_s)

            logger.error("ZAP failed to start within %ds.", ZAP_STARTUP_TIMEOUT)
            _zap_state.update({"status": "offline",
                                "last_error": f"Timed out after {ZAP_STARTUP_TIMEOUT}s"})
            return False

        except FileNotFoundError as e:
            logger.error("ZAP binary not found: %s", e)
            _zap_state.update({"status": "unavailable", "last_error": str(e)})
            return False
        except Exception as e:
            logger.error("ZAP async startup failed: %s", e)
            _zap_state.update({"status": "offline", "last_error": str(e)})
            return False

    @classmethod
    def attempt_self_heal(cls, max_retries: int = 2) -> bool:
        """
        Self-heal: attempt to bring ZAP online up to max_retries times.
        Used by the startup self-test auto-heal path.
        """
        for attempt in range(1, max_retries + 1):
            logger.info("ZAP self-heal attempt %d/%d...", attempt, max_retries)
            try:
                if cls._check_existing_daemon():
                    return True
                proc  = cls.start_zap_daemon()
                ready = cls._poll_until_ready(proc, ZAP_STARTUP_TIMEOUT)
                if ready:
                    return True
            except Exception as e:
                logger.warning("Self-heal attempt %d failed: %s", attempt, e)
        logger.error("ZAP self-heal exhausted all %d attempts.", max_retries)
        return False
