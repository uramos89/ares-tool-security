#!/usr/bin/env python3
"""Tests for FullTestSec modules"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.reporter import AuditReport

def test_reporter_basic():
    r = AuditReport("https://example.com", "web-audit")
    r.add_finding("critical", "No HSTS", "HSTS header missing", "add_header Strict-Transport-Security")
    r.add_finding("ok", "HTTPS enabled")
    r.add_finding("high", "CORS wildcard", "Access-Control-Allow-Origin: *", "set specific origin")
    path = r.generate()
    assert os.path.exists(path), f"Report not generated at {path}"
    with open(path) as f:
        content = f.read()
    assert "🔴 CRITICAL" in content, "Critical finding missing"
    assert "🟠 HIGH" in content, "High finding missing"
    assert "✅ PASS" in content, "Pass finding missing"
    assert "Security Score" in content, "Score missing"
    print(f"  ✅ test_reporter_basic: {path}")
    os.remove(path)
    return True

def test_reporter_score():
    r = AuditReport("test", "score")
    r.add_finding("critical", "Crit1")
    r.add_finding("critical", "Crit2")
    r.add_finding("high", "High1")
    r.generate()
    assert r._build_summary(), "Summary failed"
    print(f"  ✅ test_reporter_score")
    return True

def test_reporter_empty():
    r = AuditReport("test", "empty")
    path = r.generate()
    assert os.path.exists(path)
    print(f"  ✅ test_reporter_empty")
    os.remove(path)
    return True

if __name__ == "__main__":
    print("\n🧪 FullTestSec Tests\n")
    tests = [test_reporter_basic, test_reporter_score, test_reporter_empty]
    passed = sum(1 for t in tests if t())
    total = len(tests)
    print(f"\n{'─' * 40}")
    print(f"Results: {passed}/{total} passed {'✅' if passed == total else '❌'}")
    sys.exit(0 if passed == total else 1)
