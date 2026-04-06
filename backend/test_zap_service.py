"""
ZAP Service Test Suite
======================
Tests: zombie detection, binary discovery, health check, and CWD resolution.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.zap_service import (
    ZapService, _zap_api_ping, _find_zap_binary,
    _is_port_open, get_zap_state, ZAP_PORT, ZAP_API_KEY,
)

PASS = lambda msg: print(f"  [PASS] {msg}")
FAIL = lambda msg: print(f"  [FAIL] {msg}")
INFO = lambda msg: print(f"  [INFO] {msg}")


def test_binary_discovery():
    print("\n=== Test 1: Binary Discovery ===")
    path = _find_zap_binary()
    if path and os.path.isfile(path):
        PASS(f"Binary found: {path}")
        cwd = os.path.dirname(path)
        jar = os.path.join(cwd, "zap-2.17.0.jar")
        if os.path.exists(jar):
            PASS(f"zap-2.17.0.jar found in ZAP dir: {cwd}")
        else:
            INFO(f"zap-2.17.0.jar not at expected path {jar} — may have different version")
    else:
        FAIL(f"Binary not found (path={path})")


def test_port_check():
    print("\n=== Test 2: Port Reachability ===")
    open_ = _is_port_open(port=ZAP_PORT)
    if open_:
        PASS(f"Port {ZAP_PORT} is OPEN (something is listening)")
    else:
        INFO(f"Port {ZAP_PORT} is closed (ZAP not running)")


def test_api_health():
    print("\n=== Test 3: ZAP API Health Ping ===")
    ok, version = _zap_api_ping(timeout=5)
    if ok:
        PASS(f"ZAP API healthy — version {version}, key='{ZAP_API_KEY}'")
    else:
        INFO("ZAP API not responding (daemon may be offline)")


def test_zombie_detection():
    print("\n=== Test 4: Zombie Detection (existing daemon check) ===")
    result = ZapService._check_existing_daemon()
    if result:
        PASS("Existing healthy daemon detected — would be reused (no duplicate spawn)")
    else:
        INFO("No existing daemon detected — fresh spawn would be triggered")


def test_is_healthy():
    print("\n=== Test 5: is_zap_healthy() ===")
    ok = ZapService.is_zap_healthy()
    state = get_zap_state()
    if ok:
        PASS(f"is_zap_healthy()=True, state: {state['status']}, v{state.get('version')}")
    else:
        INFO(f"is_zap_healthy()=False, state: {state['status']}")


if __name__ == "__main__":
    print("=" * 55)
    print("  ZAP Service Diagnostic Tests")
    print("=" * 55)
    test_binary_discovery()
    test_port_check()
    test_api_health()
    test_zombie_detection()
    test_is_healthy()
    print()
    print("=" * 55)
    print("  Tests complete. See [FAIL] lines above for issues.")
    print("=" * 55)
