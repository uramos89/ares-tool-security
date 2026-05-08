#!/usr/bin/env python3
"""Module 12: Web Audit — Security audit for URLs and IPs"""
import sys, os, json, ssl, socket, hashlib
from urllib.request import Request, urlopen
from urllib.error import URLError
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.reporter import AuditReport

class WebAudit:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.target_clean = target.replace("https://", "").replace("http://", "").rstrip("/")
        self.report = AuditReport(target, "web-audit")
        self._homepage_body = None  # Cache for catch-all detection

    def run(self) -> str:
        print(f"\n  🌐 Web Audit — {self.target}")
        print(f"  {'─' * 50}")
        self._check_ssl()
        self._check_headers()
        self._check_stack()
        self._check_ports()
        return self.report.generate()

    def _fetch(self, path="/", method="GET"):
        try:
            req = Request(f"{self.target}{path}", method=method)
            try:
                with urlopen(req, timeout=10) as r:
                    body = r.read().decode("utf-8", errors="ignore")
                    return r.status, r.headers, body
            except URLError as e:
                return None, {}, str(e)
        except Exception as e:
            return None, {}, str(e)

    def _get_homepage(self) -> str:
        """Fetch and cache the homepage body for catch-all detection."""
        if self._homepage_body is None:
            _, _, body = self._fetch("/")
            self._homepage_body = body or ""
        return self._homepage_body

    def _is_catch_all(self, body: str) -> bool:
        """Detect if server returns homepage content for non-existent paths (catch-all)."""
        homepage = self._get_homepage()
        if not homepage or not body:
            return False
        # Compare length and first 500 chars (if they match, it's likely catch-all)
        if len(body) == len(homepage) and len(body) > 0:
            return True
        # Compare first 200 chars (head section usually differs between pages)
        if len(body) > 200 and len(homepage) > 200:
            return body[:200] == homepage[:200]
        return False

    def _check_ssl(self):
        print(f"\n  🔍 1/4 — SSL/TLS")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.target_clean.split(":")[0], 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target_clean.split(":")[0]) as ssock:
                    cert = ssock.getpeercert()
                    cn = dict(cert.get("subject", [[("", "")]])[0]).get("commonName", "unknown")
                    issuer = dict(cert.get("issuer", [[("", "")]])[0]).get("organizationName", "unknown")
                    print(f"    {'✅':<4} SSL válido — CN: {cn}")
                    print(f"    {'ℹ️':<4} Issuer: {issuer}")
                    self.report.add_finding("ok", f"SSL Certificate valid. Issuer: {issuer}")
        except Exception as e:
            print(f"    {'❌':<4} SSL Error: {e}")
            self.report.add_finding("critical", "SSL/TLS connection failed", detail=str(e))

    def _check_headers(self):
        print(f"\n  🔍 2/4 — Security Headers")
        try:
            status, headers, _ = self._fetch()
            if not status:
                status, headers, _ = None, {}, ""
        except:
            status, headers, _ = None, {}, ""
        if not status:
            print(f"    {'❌':<4} Could not reach {self.target}")
            self.report.add_finding("critical", "Site unreachable", detail=self.target)
            return

        checks = {
            "Strict-Transport-Security": ("high", "Missing HSTS header", "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains';"),
            "Content-Security-Policy": ("critical", "Missing CSP header", "add_header Content-Security-Policy \"default-src 'self';\";"),
            "X-Frame-Options": ("high", "Missing X-Frame-Options (clickjacking risk)", "add_header X-Frame-Options DENY;"),
            "X-Content-Type-Options": ("medium", "Missing X-Content-Type-Options", "add_header X-Content-Type-Options nosniff;"),
        }
        for header, (severity, msg, fix) in checks.items():
            val = headers.get(header)
            if val:
                print(f"    {'✅':<4} {header}: {val}")
                self.report.add_finding("ok", f"{header} present")
            else:
                print(f"    {'❌':<4} {msg}")
                self.report.add_finding(severity, msg, fix=fix)

    def _check_stack(self):
        print(f"\n  🔍 3/4 — Web Stack")
        status, headers, body = self._fetch()
        if not status:
            return

        server = headers.get("Server", "unknown")
        print(f"    {'🖥️':<4} Server: {server}")
        self.report.add_finding("ok" if server != "unknown" else "low", f"Server: {server}")

        # Check for sensitive paths with catch-all detection
        print(f"\n    {'🔍':<4} Scanning sensitive paths (catch-all detection enabled)...")
        homepage = self._get_homepage()
        catch_all_detected = False

        for sensitive_path in ["/admin", "/login", "/.env", "/config", "/api", "/wp-admin", "/.git/config"]:
            s, _, resp_body = self._fetch(sensitive_path)
            if s and s < 400:
                # Check for catch-all
                is_catch_all = self._is_catch_all(resp_body)
                if is_catch_all and s == 200:
                    if not catch_all_detected:
                        print(f"    {'⚠️':<4} ⚠️  CATCH-ALL DETECTED — server returns homepage for unknown paths")
                        self.report.add_finding("medium", "Catch-all routing detected", 
                            detail="Server returns 200 with homepage content for non-existent paths. All path findings below are FALSE POSITIVES.", 
                            fix="Configure Apache/Nginx to return 404 for unknown routes")
                        catch_all_detected = True
                    print(f"    {'⏭️':<4} {sensitive_path} → {s} (catch-all, skipping)")
                else:
                    print(f"    {'⚠️':<4} {sensitive_path} → {s} (visible)")
                    self.report.add_finding("high" if s == 200 else "medium", f"Path exposed: {sensitive_path}", detail=f"HTTP {s}")

        if catch_all_detected:
            print(f"\n    {'💡':<4} Tip: All paths showing 200 are false positives due to catch-all routing.")
            print(f"    {'':<4} The script now detects this automatically. ✅")

    def _check_ports(self):
        print(f"\n  🔍 4/4 — Network Ports")
        common_ports = {"80": "HTTP", "443": "HTTPS", "22": "SSH", "8080": "HTTP-Alt", "3306": "MySQL", "5432": "PostgreSQL"}
        host = self.target_clean.split(":")[0]
        for port, service in common_ports.items():
            try:
                with socket.create_connection((host, int(port)), timeout=3) as s:
                    s.close()
                    if port == "443":
                        print(f"    {'✅':<4} Port {port} ({service}) — open")
                    elif port == "80":
                        print(f"    {'⚠️':<4} Port {port} ({service}) — open")
                    elif port in ("22", "8080"):
                        print(f"    {'⚠️':<4} Port {port} ({service}) — open")
                    else:
                        print(f"    {'❌':<4} Port {port} ({service}) — EXPUESTO")
            except:
                pass

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Target URL/IP: ")
    audit = WebAudit(target)
    report_path = audit.run()
    print(f"\n  {'📝':<4} Report: {report_path}")
