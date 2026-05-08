#!/usr/bin/env python3
"""Module: Vulnerability Scanner — XSS, SQLi, Open Redirect, Form Analysis."""
import sys, os, html
from urllib.request import Request, urlopen
from urllib.parse import urlparse, parse_qs
from urllib.error import URLError
import re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.reporter import AuditReport

class VulnScan:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.parsed = urlparse(self.target)
        self.report = AuditReport(target, "vuln-scan")
        self._homepage_body = None

    def _fetch(self, path="/", method="GET", data=None):
        try:
            req = Request(f"{self.target}{path}", method=method, data=data)
            with urlopen(req, timeout=10) as r:
                body = r.read().decode("utf-8", errors="ignore")
                return r.status, dict(r.headers), body
        except Exception:
            return None, {}, ""

    def _get_homepage(self) -> str:
        if self._homepage_body is None:
            _, _, body = self._fetch("/")
            self._homepage_body = body or ""
        return self._homepage_body

    def run(self) -> str:
        print(f"\n  {'⚠️':<4} ⚠️  Solo ejecutar en sitios con AUTORIZACIÓN explícita")
        print(f"  {'':<4} El escaneo inyecta payloads de prueba en parámetros URL.")
        print(f"  {'─' * 50}")
        self._check_forms()
        self._check_cookies()
        self._check_cors()
        self._check_xss()
        self._check_sqli()
        self._check_open_redirect()
        self._check_info_disclosure()
        return self.report.generate()

    def _check_forms(self):
        print(f"\n  🔍 1/7 — Form Analysis & CSRF")
        status, _, body = self._fetch()
        if not body:
            return

        # Find all forms
        forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
        if not forms:
            print(f"    {'ℹ️':<4} No forms detected on homepage")
            self.report.add_finding("ok", "No forms on homepage")
            return

        print(f"    {'📋':<4} Found {len(forms)} form(s)")
        
        for i, form_html in enumerate(forms, 1):
            form_method = "GET"
            form_action = ""
            
            m = re.search(r'<form[^>]*method=["\'](GET|POST)["\']', form_html, re.IGNORECASE)
            if m: form_method = m.group(1)
            
            m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if m: form_action = m.group(1)
            
            has_csrf = bool(re.search(r'csrf|token|_token|nonce|authenticity_token', form_html, re.IGNORECASE))
            has_password = 'type="password"' in form_html or "type='password'" in form_html
            inputs = re.findall(r'<input[^>]*>', form_html, re.IGNORECASE)
            
            print(f"    {'':<4} Form {i}: method={form_method}, action={form_action or '/'}")
            print(f"    {'':<4}   Inputs: {len(inputs)} | Password: {'✅' if has_password else '❌'} | CSRF: {'✅' if has_csrf else '❌'}")

            if not has_csrf and form_method == "POST":
                print(f"    {'':<4}   ⚠️  Missing CSRF token on POST form")
                self.report.add_finding("high", f"Form #{i} lacks CSRF protection",
                    detail=f"Method: {form_method}, Action: {form_action or '/'}",
                    fix="Add CSRF token to all POST forms")

        if not has_csrf:
            self.report.add_finding("medium", "Forms without CSRF tokens detected",
                fix="Implement CSRF protection (e.g., Django CSRF middleware, Rails authenticity_token)")

    def _check_cookies(self):
        print(f"\n  🔍 2/7 — Cookie Security Audit")
        status, headers, _ = self._fetch()
        if not status:
            return

        raw_cookies = headers.get_all("Set-Cookie") if hasattr(headers, 'get_all') else []
        if not raw_cookies:
            # Try to find Set-Cookie in headers dict
            raw_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]

        if not raw_cookies:
            print(f"    {'ℹ️':<4} No cookies set on homepage")
            self.report.add_finding("ok", "No cookies on homepage")
            return

        print(f"    {'🍪':<4} Found {len(raw_cookies)} cookie(s)")
        
        for i, cookie in enumerate(raw_cookies, 1):
            has_secure = "secure" in cookie.lower()
            has_httponly = "httponly" in cookie.lower()
            has_samesite = "samesite" in cookie.lower()
            has_path = "path=" in cookie.lower()
            
            name = cookie.split("=")[0] if "=" in cookie else "unknown"
            
            print(f"    {'':<4} Cookie {i}: {name}")
            print(f"    {'':<4}   Secure: {'✅' if has_secure else '❌'} | HttpOnly: {'✅' if has_httponly else '❌'} | SameSite: {'✅' if has_samesite else '❌'}")

            if not has_secure:
                self.report.add_finding("high", f"Cookie '{name}' missing Secure flag",
                    fix="Set Secure flag on all cookies to prevent transmission over HTTP")
            if not has_httponly:
                self.report.add_finding("medium", f"Cookie '{name}' missing HttpOnly flag",
                    fix="Set HttpOnly flag to prevent JavaScript access to cookies")
            if not has_samesite:
                self.report.add_finding("medium", f"Cookie '{name}' missing SameSite attribute",
                    fix="Set SameSite=Lax or SameSite=Strict to prevent CSRF via cookies")

    def _check_cors(self):
        print(f"\n  🔍 3/7 — CORS Misconfiguration")
        try:
            req = Request(f"{self.target}/")
            req.add_header("Origin", "https://evil.com")
            req.add_header("Host", self.parsed.netloc)
            with urlopen(req, timeout=10) as r:
                cors = r.headers.get("Access-Control-Allow-Origin", "")
                if cors == "*":
                    print(f"    {'❌':<4} CORS: wildcard (*) — any site can read data")
                    self.report.add_finding("critical", "CORS wildcard origin (*)",
                        fix="Restrict Access-Control-Allow-Origin to specific trusted domains")
                elif cors:
                    print(f"    {'⚠️':<4} CORS: {cors}")
                    if "evil.com" in cors:
                        print(f"    {'❌':<4} CORS MIRRORING — reflects any origin!")
                        self.report.add_finding("critical", "CORS origin reflection (vulnerable)",
                            detail=f"Reflected origin: {cors}",
                            fix="Do not reflect Origin header. Whitelist specific origins.")
                    else:
                        self.report.add_finding("ok", f"CORS restricted to: {cors}")
                else:
                    print(f"    {'✅':<4} CORS: not set (secure default)")
                    self.report.add_finding("ok", "No CORS header (secure default)")
        except Exception:
            print(f"    {'✅':<4} CORS: not set (secure default)")
            self.report.add_finding("ok", "No CORS header (secure default)")

    def _check_xss(self):
        print(f"\n  🔍 4/7 — Reflected XSS Test")
        status, _, body = self._fetch()
        if not body:
            return

        # Find URL parameters (links with ?param=value)
        params = re.findall(r'\?([^"\'\s>]+)', body)
        param_names = set()
        for p in params:
            for kv in p.split('&'):
                if '=' in kv:
                    param_names.add(kv.split('=')[0])

        xss_payloads = [
            '<script>alert(1)</script>',
            '"<script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
        ]

        payload_char = '<>"\'()'  # Characters that XSS payloads contain

        if not param_names:
            # Try common params on the URL
            param_names = {'q', 's', 'search', 'query', 'id', 'page', 'term', 'keyword', 'lang'}
            print(f"    {'':<4} Testing {len(param_names)} common parameters...")
        else:
            print(f"    {'':<4} Found {len(param_names)} parameter(s): {', '.join(list(param_names)[:6])}")

        reflected = []
        for param in list(param_names)[:8]:  # Limit to 8 params
            for payload in xss_payloads[:3]:  # 3 payloads per param
                try:
                    test_url = f"{self.target}/?{param}={__import__('urllib').parse.quote(payload)}"
                    req = Request(test_url)
                    with urlopen(req, timeout=10) as r:
                        resp_body = r.read().decode("utf-8", errors="ignore")
                        # Check if payload chars appear unescaped in response
                        if any(c in resp_body for c in ['<script>alert', 'onerror=alert', 'onload=alert']):
                            reflected.append(param)
                            print(f"    {'❌':<4} Possible XSS via ?{param}= (payload reflected unescaped)")
                            self.report.add_finding("critical", f"Reflected XSS via parameter '{param}'",
                                detail=f"Payload '{payload[:30]}' reflected in response without sanitization",
                                fix="Sanitize all user input with context-aware encoding. Use CSP headers.")
                            break
                except Exception:
                    pass
            if param in reflected:
                continue

        if not reflected:
            print(f"    {'✅':<4} No obvious reflected XSS detected (tested {len(param_names)} params × 3 payloads)")
            self.report.add_finding("ok", "No reflected XSS found in tested parameters")

    def _check_sqli(self):
        print(f"\n  🔍 5/7 — SQL Injection Test")
        status, _, body = self._fetch()
        if not body:
            return

        # Find URL parameters
        params = re.findall(r'\?([^"\'\s>]+)', body)
        param_names = set()
        for p in params:
            for kv in p.split('&'):
                if '=' in kv:
                    param_names.add(kv.split('=')[0])

        sqli_payloads = [
            ("'", "Single quote"),
            ("\"", "Double quote"),
            ("' OR '1'='1", "Basic auth bypass"),
            ("' OR 1=1--", "OR 1=1 comment"),
            ("' UNION SELECT NULL--", "UNION NULL"),
            ("'; DROP TABLE users--", "DROP TABLE"),
            ("' AND 1=1--", "AND true"),
            ("' AND 1=2--", "AND false (blind)"),
        ]

        sqli_error_signs = [
            "sql", "mysql", "sqlite", "postgresql", "ora-", "ora ",
            "syntax error", "unclosed quotation", "incorrect syntax",
            "warning: mysql", "driver", "odbc", "db2",
            "you have an error", "column count", "unexpected token",
            "division by zero", "mysql_fetch", "pg_", "sqlsrv",
        ]

        if not param_names:
            param_names = {'id', 'page', 'cat', 'product', 'user', 'order', 'num'}
            print(f"    {'':<4} Testing {len(param_names)} common parameters...")
        else:
            print(f"    {'':<4} Found {len(param_names)} parameter(s): {', '.join(list(param_names)[:6])}")

        vulnerable = []
        for param in list(param_names)[:8]:
            for payload, ptype in sqli_payloads[:4]:  # 4 payloads per param
                try:
                    encoded = __import__('urllib').parse.quote(payload)
                    test_url = f"{self.target}/?{param}={encoded}"
                    req = Request(test_url)
                    with urlopen(req, timeout=10) as r:
                        resp_body = r.read().decode("utf-8", errors="ignore").lower()
                        # Check for SQL error messages
                        for sign in sqli_error_signs:
                            if sign in resp_body:
                                vulnerable.append(param)
                                print(f"    {'❌':<4} Possible SQLi via ?{param}= ('{ptype}' triggered: '{sign}')")
                                self.report.add_finding("critical", f"SQL Injection via parameter '{param}'",
                                    detail=f"Payload '{ptype}' triggered error pattern '{sign}'",
                                    fix="Use parameterized queries (prepared statements). Never concatenate user input into SQL.")
                                break
                        if param in vulnerable:
                            break
                except Exception:
                    pass

        if not vulnerable:
            print(f"    {'✅':<4} No obvious SQL injection detected (tested {len(param_names)} params × 4 payloads)")
            self.report.add_finding("ok", "No SQL injection found in tested parameters")

    def _check_open_redirect(self):
        print(f"\n  🔍 6/7 — Open Redirect Check")
        # Check common redirect parameters
        redirect_params = ["redirect", "url", "next", "return", "goto", "target", "r", "u", "to", "dest", "destination"]
        found_redirects = 0
        
        status, _, body = self._fetch()
        if not body:
            return

        # Scan page for external links
        links = re.findall(r'href=["\'](https?://[^"\']+)["\']', body)
        external_links = [l for l in links if self.parsed.netloc not in l]
        
        if external_links:
            # Check if any external links can be used for redirect
            for param in redirect_params:
                try:
                    test_url = f"{self.target}/?{param}=https://evil.com"
                    req = Request(test_url)
                    req.add_header("Host", self.parsed.netloc)
                    # Don't follow redirects
                    from urllib.request import HTTPRedirectHandler, build_opener
                    class NoRedirect(HTTPRedirectHandler):
                        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                            return None
                    opener = build_opener(NoRedirect)
                    resp = opener.open(req, timeout=10)
                    if resp.status in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location:
                            print(f"    {'❌':<4} Open redirect via ?{param}= (redirects to {location})")
                            self.report.add_finding("critical", f"Open redirect via parameter '{param}'",
                                detail=f"Redirects to: {location}",
                                fix="Validate redirect URLs against a whitelist of allowed domains")
                            found_redirects += 1
                except Exception:
                    pass

        if found_redirects == 0:
            print(f"    {'✅':<4} No open redirects detected")
            self.report.add_finding("ok", "No open redirects found")

    def _check_info_disclosure(self):
        print(f"\n  🔍 7/7 — Information Disclosure")
        status, headers, body = self._fetch()
        if not body:
            return

        disclosures = []
        
        # Check for exposed comments
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        sensitive_comments = [c.strip() for c in comments if any(x in c.lower() for x in 
            ["todo", "fixme", "password", "secret", "key", "token", "user", "admin", "debug", "test"])]
        
        if sensitive_comments:
            for c in sensitive_comments[:3]:
                print(f"    {'⚠️':<4} HTML comment with potential info: {c[:100]}")
                self.report.add_finding("medium", "Sensitive info in HTML comments",
                    detail=c[:200],
                    fix="Remove development comments before production deployment")

        # Check for version disclosure
        if "Server" in headers:
            server = headers["Server"]
            if "/" in server and any(c.isdigit() for c in server):
                print(f"    {'⚠️':<4} Server version disclosed: {server}")
                self.report.add_finding("medium", "Server version disclosed",
                    detail=server,
                    fix="Disable server signature (ServerTokens Prod in Apache, server_tokens off in Nginx)")

        # Check for debug endpoints
        debug_paths = ["/debug", "/status", "/info", "/phpinfo.php", "/server-status", "/.env", "/config.json"]
        for path in debug_paths:
            s, _, db_body = self._fetch(path)
            if s == 200 and db_body and len(db_body) > 50:
                print(f"    {'❌':<4} Potential info leak: {path} (HTTP 200)")
                self.report.add_finding("high", f"Information disclosure via {path}",
                    detail=f"Returns HTTP 200 with {len(db_body)} bytes",
                    fix=f"Restrict access to {path} or return 404")

        if not disclosures:
            print(f"    {'✅':<4} No obvious information leaks")
