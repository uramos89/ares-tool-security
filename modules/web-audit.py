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
            with urlopen(req, timeout=10) as r:
                return r.status, r.headers, r.read().decode("utf-8", errors="ignore")
        except URLError as e:
            return None, {}, str(e)

    def _check_ssl(self):
        print(f"\n  🔍 1/4 — SSL/TLS")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.target_clean.split(":")[0], 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target_clean.split(":")[0]) as ssock:
                    cert = ssock.getpeercert()
                    cn = dict(cert.get("subject", [[("", "")]])[0]).get("commonName", "unknown")
                    issuer = dict(cert.get("issuer", [[("", "")]])[0]).get("organizationName", "unknown")
                    print(f"    ✅ SSL válido — CN: {cn}")
                    print(f"    ℹ️  Issuer: {issuer}")
                    self.report.add_finding("ok", f"SSL Certificate valid. Issuer: {issuer}")
        except Exception as e:
            print(f"    ❌ SSL Error: {e}")
            self.report.add_finding("critical", "SSL/TLS connection failed", detail=str(e))

    def _check_headers(self):
        print(f"\n  🔍 2/4 — Security Headers")
        status, headers, _ = self._fetch() if self._fetch()[0] else (None, {}, "")
        if not status:
            print(f"    ❌ Could not reach {self.target}")
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
                print(f"    ✅ {header}: {val}")
                self.report.add_finding("ok", f"{header} present")
            else:
                print(f"    ❌ {msg}")
                self.report.add_finding(severity, msg, fix=fix)

    def _check_stack(self):
        print(f"\n  🔍 3/4 — Web Stack")
        status, headers, body = self._fetch()
        if not status:
            return

        server = headers.get("Server", "unknown")
        print(f"    🖥️  Server: {server}")
        self.report.add_finding("ok" if server != "unknown" else "low", f"Server: {server}")

        # Check for sensitive paths
        for sensitive_path in ["/admin", "/login", "/.env", "/config", "/api", "/wp-admin", "/.git/config"]:
            s, _, _ = self._fetch(sensitive_path)
            if s and s < 400:
                print(f"    ⚠️  {sensitive_path} → {s} (visible)")
                self.report.add_finding("high" if s == 200 else "medium", f"Path exposed: {sensitive_path}", detail=f"HTTP {s}")

    def _check_ports(self):
        print(f"\n  🔍 4/4 — Network Ports")
        common_ports = {"80": "HTTP", "443": "HTTPS", "22": "SSH", "8080": "HTTP-Alt", "3306": "MySQL", "5432": "PostgreSQL"}
        host = self.target_clean.split(":")[0]
        for port, service in common_ports.items():
            try:
                with socket.create_connection((host, int(port)), timeout=3) as s:
                    s.close()
                    if port == "443":
                        print(f"    ✅ Port {port} ({service}) — open")
                    elif port == "80":
                        print(f"    ⚠️  Port 80 ({service}) — open")
                    elif port in ("22", "8080"):
                        print(f"    ⚠️  Port {port} ({service}) — open")
                    else:
                        print(f"    ❌ Port {port} ({service}) — EXPUESTO")
            except:
                pass

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Target URL/IP: ")
    audit = WebAudit(target)
    report_path = audit.run()
    print(f"\n  📝 Report: {report_path}")
