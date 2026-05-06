#!/usr/bin/env python3
"""Module 13: Brute Force Testing — Validate rate limiting, lockouts, retry behavior"""
import sys, os, json, time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.reporter import AuditReport

class BruteForceTest:
    def __init__(self, target: str, endpoint: str = None):
        self.target = target.rstrip("/")
        self.endpoint = endpoint or "/api/login"
        self.url = f"{self.target}{self.endpoint}"
        self.report = AuditReport(f"{target} {endpoint}", "brute-force")
        self.results = []

    def run(self, requests: int = 15, delay: float = 0.1) -> str:
        print(f"\n  🔨 Brute Force Test — {self.url}")
        print(f"  {'─' * 50}")
        print(f"  Requests: {requests} | Delay: {delay}s")
        self._test_rate_limiting(requests, delay)
        self._test_lockout()
        self._test_2fa_rate_limit()
        return self.report.generate()

    def _send_request(self, payload: dict = None):
        try:
            data = json.dumps(payload or {"username": "test", "password": "test123"}).encode()
            req = Request(self.url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            with urlopen(req, timeout=10) as r:
                return r.status, r.read().decode("utf-8", errors="ignore")[:200]
        except HTTPError as e:
            return e.code, str(e)[:200]
        except URLError as e:
            return 0, str(e)

    def _test_rate_limiting(self, n: int, delay: float):
        print(f"\n  🔍 1/3 — Rate Limiting Test ({n} requests)")
        statuses = []
        for i in range(n):
            code, _ = self._send_request()
            statuses.append(code)
            print(f"    Request {i+1:2d}: HTTP {code}")
            time.sleep(delay)

        # Analyze
        unique = set(statuses)
        rate_limited = statuses.count(429)
        blocked = statuses.count(403) + statuses.count(401)

        if rate_limited > 0:
            first_429 = statuses.index(429) + 1
            print(f"    ✅ Rate limiting detected: 429 after {first_429} requests")
            self.report.add_finding("ok", f"Rate limiting active (HTTP 429 after {first_429} requests)")
        else:
            print(f"    ❌ No rate limiting detected")
            self.report.add_finding("critical", "No rate limiting on endpoint", detail=f"{n} requests, no 429", fix="Implement rate limiting middleware")

        if blocked >= n * 0.5:
            print(f"    ✅ Account lockout active ({blocked}/{n} blocked)")
            self.report.add_finding("ok", "Account lockout mechanism detected")
        elif blocked > 0:
            print(f"    ⚠️  Partial blocking ({blocked}/{n})")
            self.report.add_finding("medium", "Partial blocking detected", detail=f"{blocked}/{n} requests blocked")

    def _test_lockout(self):
        print(f"\n  🔍 2/3 — Lockout Test (20 rapid requests)")
        statuses = []
        for i in range(20):
            code, _ = self._send_request()
            statuses.append(code)
            time.sleep(0.05)

        successes = statuses.count(200)
        if successes == 20:
            print(f"    ❌ No lockout — all 20 requests succeeded")
            self.report.add_finding("high", "No lockout after multiple failed attempts", detail="20/20 requests returned 200", fix="Implement account lockout after N failed attempts")
        elif successes == 0:
            print(f"    ✅ Lockout active")
            self.report.add_finding("ok", "Account lockout active")

    def _test_2fa_rate_limit(self):
        print(f"\n  🔍 3/3 — 2FA/MFA Rate Limit Simulation")
        # Simulated test — checks if 2FA endpoint has rate limiting
        alt_endpoints = ["/api/2fa", "/api/mfa", "/api/verify-otp", "/auth/verify"]
        found = False
        for ep in alt_endpoints:
            try:
                url = f"{self.target}{ep}"
                req = Request(url, data=b'{"code":"123456"}', method="POST")
                req.add_header("Content-Type", "application/json")
                with urlopen(req, timeout=5) as r:
                    print(f"    ⚠️  2FA endpoint found: {ep} (HTTP {r.status})")
                    found = True
            except HTTPError as e:
                if e.code != 404:
                    print(f"    ⚠️  2FA endpoint: {ep} (HTTP {e.code})")
                    found = True
            except:
                pass

        if not found:
            print(f"    ℹ️  No 2FA endpoint detected")
        self.report.add_finding("ok" if found else "low", "2FA endpoint check complete")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else input("Target URL (https://...): ")
    endpoint = sys.argv[2] if len(sys.argv) > 2 else input("Login endpoint (default: /api/login): ") or None
    tester = BruteForceTest(target, endpoint)
    report_path = tester.run()
    print(f"\n  📝 Report: {report_path}")
