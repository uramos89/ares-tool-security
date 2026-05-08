#!/usr/bin/env python3
"""Module 11: Brute Force Test — Rate limiting, lockout, 2FA detection."""
import sys, os, time
from urllib.request import Request, urlopen
from urllib.error import URLError
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.reporter import AuditReport

class BruteForceTest:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.report = AuditReport(target, "brute-force")
        self._homepage_body = None

    def _fetch(self, path="/", method="GET", data=None):
        try:
            req = Request(f"{self.target}{path}", method=method, data=data)
            with urlopen(req, timeout=10) as r:
                body = r.read().decode("utf-8", errors="ignore")
                return r.status, r.headers, body
        except URLError as e:
            return getattr(e, 'code', None), {}, str(e)
        except Exception as e:
            return None, {}, str(e)

    def _get_homepage(self) -> str:
        if self._homepage_body is None:
            # Fetch homepage from root of the target domain
            root = self.target.rstrip("/api/login").rstrip("/api").rstrip("/login")
            _, _, body = self._fetch("/")
            self._homepage_body = body or ""
        return self._homepage_body

    def _is_catch_all(self, body: str) -> bool:
        """Detect if server returns homepage content for unknown paths (catch-all)."""
        homepage = self._get_homepage()
        if not homepage or not body:
            return False
        if len(body) == len(homepage) and len(body) > 0:
            return True
        if len(body) > 200 and len(homepage) > 200:
            return body[:200] == homepage[:200]
        return False

    def run(self) -> str:
        login_path = input("  Login endpoint (default: /api/login): ").strip()
        if not login_path:
            login_path = "/api/login"

        self.target = self.target.rstrip("/")
        login_url = f"{self.target}{login_path}"
        print(f"\n  🔨 Brute Force Test — {login_url}")
        print(f"  {'─' * 50}")

        # First: check for catch-all on the login endpoint
        status, _, body = self._fetch(login_path)
        if status == 200 and body:
            if self._is_catch_all(body):
                print(f"\n  {'⚠️':<4} ⚠️  CATCH-ALL DETECTED — server returns homepage for '{login_path}'")
                print(f"  {'':<4} This endpoint likely doesn't exist. All results below are FALSE POSITIVES.")
                print(f"  {'':<4} Try a different login endpoint or check the actual site structure.\n")
                self.report.add_finding("medium", "Catch-all routing detected for login endpoint",
                    detail=f"The path '{login_path}' returns the homepage instead of a 404. Login endpoint may not exist.",
                    fix="Verify the actual login URL by inspecting the site's login form HTML.")
                # Still run the tests but note the catch-all

        DELAY = 0.1
        RAPID_COUNT = 20

        # ─── 1. Rate Limiting Test ───
        print(f"  🔍 1/3 — Rate Limiting Test (15 requests)")
        requests_made = 0
        rate_limited = False
        for i in range(15):
            s, _, body = self._fetch(login_path)
            status_code = s if s else "ERR"
            print(f"    Request {i+1}: HTTP {status_code}")
            if status_code == 429 or status_code == 503:
                rate_limited = True
                print(f"    {'✅':<4} Rate limiting detected at request {i+1}!")
                break
            requests_made += 1
            time.sleep(DELAY)

        if rate_limited:
            self.report.add_finding("ok", "Rate limiting detected", detail=f"Blocked after {requests_made} requests")
            print(f"\n  {'✅':<4} Rate limiting ACTIVE — {requests_made} requests before block")
        else:
            self.report.add_finding("critical", "No rate limiting detected", 
                detail=f"{requests_made} requests with {DELAY}s delay — all succeeded (HTTP 200). Catch-all may cause false positive.",
                fix="Implement rate limiting: max 5 login attempts/min per IP")
            print(f"\n  {'❌':<4} No rate limiting detected")

        # ─── 2. Lockout Test ───
        print(f"\n  🔍 2/3 — Lockout Test ({RAPID_COUNT} rapid requests)")
        locked_out = False
        for i in range(RAPID_COUNT):
            s, _, body = self._fetch(login_path)
            status_code = s if s else "ERR"
            if status_code in (429, 403, 401, 423):
                locked_out = True
                print(f"    {'✅':<4} Lockout triggered at attempt {i+1}!")
                break
        if locked_out:
            self.report.add_finding("ok", "Account lockout detected", detail=f"Blocked after {i+1} rapid attempts")
            print(f"\n  {'✅':<4} Lockout ACTIVE")
        else:
            self.report.add_finding("critical", "No lockout detected",
                detail=f"All {RAPID_COUNT} rapid requests succeeded. Catch-all may cause false positive.",
                fix="Implement account lockout after 5 failed attempts (temporary block + email recovery)")
            print(f"\n  {'❌':<4} No lockout — all {RAPID_COUNT} requests succeeded")

        # ─── 3. 2FA Endpoint Scan ───
        print(f"\n  🔍 3/3 — 2FA/MFA Rate Limit Simulation")
        twofa_paths = ["/api/2fa", "/api/mfa", "/api/verify-otp", "/auth/verify"]
        found_2fa = False
        for path in twofa_paths:
            s, _, body = self._fetch(path)
            status_code = s if s else "ERR"
            is_catch_all = self._is_catch_all(body) if body else False
            if status_code == 200 and not is_catch_all:
                print(f"    {'⚠️':<4} 2FA endpoint found: {path} (HTTP {status_code})")
                self.report.add_finding("medium", f"2FA endpoint exposed: {path}", detail=f"HTTP {status_code}")
                found_2fa = True
            elif status_code == 200 and is_catch_all:
                print(f"    {'⏭️':<4} {path} → HTTP 200 (catch-all, skipping)")
            elif status_code and status_code < 500:
                print(f"    {'ℹ️':<4} {path} → HTTP {status_code}")

        if not found_2fa:
            print(f"    {'ℹ️':<4} No 2FA endpoints detected")
            self.report.add_finding("ok", "No exposed 2FA endpoints found")

        print(f"\n  {'📝':<4} Report: {self.report.generate()}")
        return self.report.filename


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Target URL/IP: ")
    test = BruteForceTest(target)
    test.run()
