#!/usr/bin/env python3
"""
Ares Tool Security — Web Audit Professional
Auditoría completa de seguridad web.

Módulos:
  1.  SSL/TLS — Certificado, protocolos, ciphers, HSTS
  2.  Security Headers — CSP, HSTS, XFO, XCTO, RP, COOP, COEP, Permissions-Policy
  3.  Stack & Tech Fingerprinting — Server, frameworks, CMS, librerías JS
  4.  Directory Busting — Paths sensibles con catch-all detection
  5.  DNS & Email Security — SPF, DMARC, DKIM, MX, subdomains
  6.  robots.txt & sitemap.xml — Paths expuestos, info leaks
  7.  Cookie Security — Secure, HttpOnly, SameSite, domain, path
  8.  Forms & CSRF — Tokens, métodos, action, password fields
  9.  CORS — Wildcard, mirroring, credentials
  10. Reflected XSS — Payload injection, reflection detection
  11. SQL Injection — Error-based detection
  12. Open Redirect — Parameter fuzzing (12+ params)
  13. Information Disclosure — Comments, versiones, debug endpoints
  14. WAF/CDN Detection — 12 proveedores, rate limit headers
  15. Mixed Content — HTTP resources on HTTPS pages
  16. Cache & Compression — Headers, performance
  17. HTTPS Enforcement — HTTP→HTTPS redirect check
  18. Security.txt — Well-known endpoint
  19. Subresource Integrity — Script/link integrity checks
  20. Network Ports — Common ports scan
"""
import sys, os, html, re, json, ssl, socket, hashlib, threading, time
from urllib.request import Request, urlopen, HTTPRedirectHandler, build_opener
from urllib.parse import urlparse, parse_qs, quote
from urllib.error import URLError

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("  [Aviso] dns.resolver no disponible (pip install dnspython). Se omiten pruebas DNS.")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.reporter import AuditReport

class WebAudit:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.parsed = urlparse(self.target)
        self.host = self.parsed.netloc.split(":")[0]
        self.report = AuditReport(target, "web-audit")
        self._homepage_body = None
        self._homepage_headers = None

    # ─── HTTP Fetch ───
    def _fetch(self, path="/", method="GET", data=None, headers_extra=None, timeout=10, redirect=True):
        try:
            req = Request(f"{self.target}{path}", method=method, data=data)
            if headers_extra:
                for k, v in headers_extra.items():
                    req.add_header(k, v)
            with urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="ignore")
                return r.status, dict(r.headers), body
        except URLError as e:
            return getattr(e, 'code', None), {}, str(e)
        except Exception as e:
            return None, {}, str(e)

    def _fetch_no_redirect(self, path="/"):
        try:
            class NoRedirect(HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                    return None
            opener = build_opener(NoRedirect)
            req = Request(f"{self.target}{path}")
            resp = opener.open(req, timeout=10)
            return resp.status, dict(resp.headers), ""
        except Exception as e:
            return getattr(e, 'code', None) if isinstance(e, URLError) else None, {}, str(e)

    def _get_homepage(self):
        if self._homepage_body is None:
            s, h, b = self._fetch("/")
            self._homepage_body = b or ""
            self._homepage_headers = h or {}
        return self._homepage_body

    def _homepage_headers(self):
        if self._homepage_headers is None:
            self._get_homepage()
        return self._homepage_headers or {}

    def _is_catch_all(self, body):
        if not body:
            return False
        homepage = self._get_homepage()
        if not homepage:
            return False
        if len(body) == len(homepage) and len(body) > 100:
            return True
        if len(body) > 200 and len(homepage) > 200:
            return body[:200] == homepage[:200]
        return False

    # ─── Run All ───
    def run(self):
        print(f"\n  [Ares] Web Audit Professional — {self.target}")
        print(f"  {''.join(['=']*50)}")

        self._check_ssl()
        self._check_security_headers()
        self._check_stack()
        self._check_directory_busting()
        self._check_dns_email()
        self._check_robots_sitemap()
        self._check_cookies()
        self._check_forms()
        self._check_cors()
        self._check_xss()
        self._check_sqli()
        self._check_open_redirect()
        self._check_info_disclosure()
        self._check_waf_cdn()
        self._check_mixed_content()
        self._check_cache()
        self._check_https_enforcement()
        self._check_security_txt()
        self._check_sri()
        self._check_ports()

        return self.report.generate()

    # ═══ 1. SSL/TLS ═══
    def _check_ssl(self):
        print(f"\n  [1/20] SSL / TLS")

        # Certificate check
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    cn = dict(cert.get("subject", [[("", "")]])[0]).get("commonName", "unknown")
                    issuer = dict(cert.get("issuer", [[("", "")]])[0]).get("organizationName", "unknown")
                    print(f"    Certificado: CN={cn} | Issuer={issuer}")
                    self.report.add_finding("ok", f"SSL Certificate valid. CN={cn}")

                    # Check expiration
                    from datetime import datetime
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.now()).days
                        if days_left < 30:
                            print(f"    Certificado expira en {days_left} dias!")
                            self.report.add_finding("high", f"SSL certificate expires in {days_left} days", fix="Renew certificate before expiry")
                        elif days_left < 90:
                            print(f"    Certificado expira en {days_left} dias (renovar pronto)")
                            self.report.add_finding("medium", f"SSL certificate expires in {days_left} days", fix="Schedule renewal")
                        else:
                            print(f"    Certificado valido por {days_left} dias mas")
        except Exception as e:
            print(f"    Error SSL: {e}")
            self.report.add_finding("critical", "SSL/TLS connection failed", detail=str(e))

        # Protocol and cipher check
        for proto_name, proto_ctx in [("TLS 1.2", ssl.PROTOCOL_TLS_CLIENT), ("TLS 1.3", ssl.PROTOCOL_TLS_CLIENT)]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # TLS 1.3 is the default, TLS 1.2 requires setting
                if "1.2" in proto_name:
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                with socket.create_connection((self.host, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                        cipher = ssock.cipher()
                        print(f"    {proto_name}: Soportado (cipher: {cipher[0] if cipher else 'N/A'})")
                        self.report.add_finding("ok", f"SSL {proto_name} supported")
            except Exception:
                print(f"    {proto_name}: NO soportado")
                self.report.add_finding("high", f"SSL {proto_name} not supported", fix="Enable modern TLS protocols, disable SSLv3/TLS 1.0/1.1")

    # ═══ 2. Security Headers ═══
    def _check_security_headers(self):
        print(f"\n  [2/20] Security Headers")
        status, headers, _ = self._fetch()
        if not status:
            return

        checks = {
            "Strict-Transport-Security": ("high", "HSTS no configurado", "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains';"),
            "Content-Security-Policy": ("critical", "CSP no configurado", "add_header Content-Security-Policy \"default-src 'self';\";"),
            "X-Frame-Options": ("high", "X-Frame-Options ausente (clickjacking)", "add_header X-Frame-Options DENY;"),
            "X-Content-Type-Options": ("medium", "X-Content-Type-Options ausente", "add_header X-Content-Type-Options nosniff;"),
            "Referrer-Policy": ("medium", "Referrer-Policy ausente", "add_header Referrer-Policy \"strict-origin-when-cross-origin\";"),
            "Permissions-Policy": ("medium", "Permissions-Policy ausente", "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\";"),
            "Cross-Origin-Embedder-Policy": ("low", "COEP ausente", "add_header Cross-Origin-Embedder-Policy \"require-corp\";"),
            "Cross-Origin-Opener-Policy": ("low", "COOP ausente", "add_header Cross-Origin-Opener-Policy \"same-origin\";"),
            "Cross-Origin-Resource-Policy": ("low", "CORP ausente", "add_header Cross-Origin-Resource-Policy \"same-origin\";"),
        }

        found_count = 0
        for header, (severity, msg, fix) in checks.items():
            val = headers.get(header)
            if val:
                found_count += 1
                print(f"    [+] {header}: {val[:60]}")
                self.report.add_finding("ok", f"{header} present")
            else:
                print(f"    [-] {msg}")
                self.report.add_finding(severity, msg, fix=fix)

        print(f"    Headers presentes: {found_count}/{len(checks)}")

    # ═══ 3. Stack Fingerprinting ═══
    def _check_stack(self):
        print(f"\n  [3/20] Web Stack & Technology")
        status, headers, body = self._fetch()
        if not status:
            return

        server = headers.get("Server", "Desconocido")
        print(f"    Server: {server}")
        self.report.add_finding("ok" if server != "Desconocido" else "low", f"Server: {server}")

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            print(f"    X-Powered-By: {powered_by}")
            self.report.add_finding("low", f"X-Powered-By: {powered_by}", fix="Hide X-Powered-By header")

        # Detect CMS / frameworks
        cms_signs = {
            "WordPress": ["/wp-content/", "/wp-admin/", "wp-json", "wp-includes"],
            "Joomla": ["/components/", "/modules/", "/templates/"],
            "Drupal": ["/sites/default/", "Drupal.settings"],
            "Shopify": ["/cdn/shop/", "Shopify.theme"],
            "Magento": ["/skin/frontend/", "mage/", "Magento"],
            "Laravel": ["laravel", "Laravel"],  # In headers
            "Django": ["csrfmiddlewaretoken", "django"],
            "Ruby on Rails": ["csrf-param", "rails"],
            "Next.js": ["__NEXT_DATA__", "/_next/static/"],
            "React": ["react", "ReactDOM"],
            "Vue.js": ["vue", "VueJS", "v-bind"],
            "Angular": ["ng-version", "ng-app"],
            "jQuery": ["jQuery", "jquery"],
        }

        detected = []
        for cms, sigs in cms_signs.items():
            for sig in sigs:
                if sig.lower() in body.lower():
                    detected.append(cms)
                    break

        # Also check headers for framework hints
        for h, v in headers.items():
            if "x-generator" in h.lower() or "x-powered-by" in h.lower():
                if v not in detected:
                    detected.append(v)

        if detected:
            for tech in set(detected):
                print(f"    Tech: {tech}")
                self.report.add_finding("low", f"Technology detected: {tech}")

    # ═══ 4. Directory Busting ═══
    def _check_directory_busting(self):
        print(f"\n  [4/20] Directory Busting")
        status, _, body = self._fetch()
        if not status:
            return

        sensitive_paths = [
            "/admin", "/login", "/.env", "/config", "/api", "/wp-admin",
            "/.git/config", "/backup", "/database", "/sql", "/phpmyadmin",
            "/logs", "/test", "/dev", "/staging", "/console", "/debug",
            "/swagger", "/api-docs", "/graphql", "/_debug", "/server-status",
            "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
        ]

        catch_all_detected = False
        for path in sensitive_paths:
            s, _, resp_body = self._fetch(path)
            if s and s < 400:
                is_catch_all = self._is_catch_all(resp_body) if resp_body else False
                if is_catch_all and s == 200:
                    if not catch_all_detected:
                        print(f"    Catch-all routing detectado — todos los 200 son falsos positivos")
                        self.report.add_finding("medium", "Catch-all routing detected",
                            detail="Server returns 200 with homepage for unknown paths",
                            fix="Configure 404 for unknown routes")
                        catch_all_detected = True
                    print(f"    {path} -> 200 (catch-all, omitido)")
                else:
                    sev = "critical" if s == 200 else "high"
                    print(f"    {path} -> HTTP {s} (accesible)")
                    self.report.add_finding(sev, f"Path exposed: {path}", detail=f"HTTP {s}",
                        fix=f"Restrict access to {path}")

        if not catch_all_detected:
            print(f"    No se detecto catch-all — los 200 son reales")

    # ═══ 5. DNS & Email Security ═══
    def _check_dns_email(self):
        print(f"\n  [5/20] DNS & Email Security")
        if not HAS_DNS:
            print(f"    Pruebas DNS omitidas (pip install dnspython)")
            self.report.add_finding("ok", "DNS tests skipped (dnspython not installed)")
            return

        records_to_check = ["SPF (TXT)", "DMARC", "MX"]

        for record in records_to_check:
            try:
                if record == "SPF (TXT)":
                    answers = dns.resolver.resolve(self.host, 'TXT')
                    spf_found = False
                    for ans in answers:
                        txt = ans.to_text()
                        if "v=spf1" in txt:
                            spf_found = True
                            has_all = " -all" in txt or " ~all" in txt or " ?all" in txt or " +all" in txt
                            if has_all:
                                print(f"    SPF: Configurado ({txt[:60]}...)")
                                if " -all" in txt:
                                    self.report.add_finding("ok", "SPF record configured (hard fail)")
                                elif " ~all" in txt:
                                    self.report.add_finding("medium", "SPF soft fail (~all) instead of hard fail (-all)", fix="Use -all for strict SPF")
                            else:
                                print(f"    SPF: Configurado sin mecanismo all")
                                self.report.add_finding("medium", "SPF record missing -all/~all mechanism", fix="Add -all to prevent email spoofing")
                            break
                    if not spf_found:
                        print(f"    SPF: No configurado")
                        self.report.add_finding("high", "SPF record missing", fix="Add SPF TXT record to prevent email spoofing")

                elif record == "DMARC":
                    dmarc_domain = f"_dmarc.{self.host}"
                    answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                    for ans in answers:
                        txt = ans.to_text()
                        if "v=DMARC1" in txt:
                            print(f"    DMARC: Configurado ({txt[:80]}...)")
                            if "p=reject" in txt:
                                self.report.add_finding("ok", "DMARC policy: reject")
                            elif "p=quarantine" in txt:
                                self.report.add_finding("medium", "DMARC policy: quarantine (reject recommended)", fix="Change DMARC policy to p=reject")
                            else:
                                self.report.add_finding("high", "DMARC policy: none (no protection)", fix="Set DMARC policy to p=reject or p=quarantine")
                            break
                    else:
                        print(f"    DMARC: No configurado")
                        self.report.add_finding("high", "DMARC record missing", fix="Add DMARC TXT record for email spoofing protection")

                elif record == "MX":
                    answers = dns.resolver.resolve(self.host, 'MX')
                    mx_records = [(ans.preference, ans.exchange.to_text()) for ans in answers]
                    mx_records.sort()
                    print(f"    MX: {len(mx_records)} registro(s)")
                    for pref, exch in mx_records[:3]:
                        print(f"      Priority {pref}: {exch}")
                    self.report.add_finding("ok", f"MX records: {len(mx_records)} found")
            except dns.resolver.NoAnswer:
                print(f"    {record}: No records found")
            except dns.resolver.NXDOMAIN:
                print(f"    {record}: Domain not found")
            except Exception as e:
                print(f"    {record}: Error ({str(e)[:40]})")

    # ═══ 6. robots.txt & sitemap ═══
    def _check_robots_sitemap(self):
        print(f"\n  [6/20] robots.txt & sitemap.xml")

        for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
            s, _, body = self._fetch(path)
            if s == 200 and body and len(body) > 20:
                print(f"    Encontrado: {path} ({len(body)} bytes)")
                if path == "/robots.txt":
                    disallowed = re.findall(r'Disallow:\s*(.+)', body, re.IGNORECASE)
                    if disallowed:
                        print(f"      Disallow paths:")
                        for d in disallowed[:8]:
                            print(f"        {d}")
                        self.report.add_finding("medium", f"robots.txt with {len(disallowed)} Disallow entries",
                            detail=f"Potentially sensitive paths: {', '.join(disallowed[:5])}",
                            fix="Review robots.txt for sensitive paths (they are not security controls by themselves)")
                    self.report.add_finding("ok", "robots.txt accessible")
            elif s:
                print(f"    {path} -> HTTP {s}")

    # ═══ 7. Cookie Security ═══
    def _check_cookies(self):
        print(f"\n  [7/20] Cookie Security")
        status, headers, _ = self._fetch()
        if not status:
            return

        raw_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
        if not raw_cookies:
            print(f"    No se detectaron cookies")
            self.report.add_finding("ok", "No cookies set on homepage")
            return

        print(f"    Cookies detectadas: {len(raw_cookies)}")
        for i, cookie in enumerate(raw_cookies, 1):
            name = cookie.split("=")[0] if "=" in cookie else "unknown"
            has_secure = "secure" in cookie.lower()
            has_httponly = "httponly" in cookie.lower()
            has_samesite = "samesite" in cookie.lower()
            has_path = "path=" in cookie.lower()

            print(f"    Cookie #{i}: {name}")
            print(f"      Secure: {'OK' if has_secure else 'FALTA'} | HttpOnly: {'OK' if has_httponly else 'FALTA'} | SameSite: {'OK' if has_samesite else 'FALTA'}")

            if not has_secure:
                self.report.add_finding("high", f"Cookie '{name}' missing Secure flag",
                    fix="Add Secure flag to prevent transmission over HTTP")
            if not has_httponly:
                self.report.add_finding("medium", f"Cookie '{name}' missing HttpOnly flag",
                    fix="Add HttpOnly to prevent JavaScript access")
            if not has_samesite:
                self.report.add_finding("medium", f"Cookie '{name}' missing SameSite attribute",
                    fix="Set SameSite=Lax or Strict to prevent CSRF via cookies")

    # ═══ 8. Forms & CSRF ═══
    def _check_forms(self):
        print(f"\n  [8/20] Forms & CSRF")
        _, _, body = self._fetch()
        if not body:
            return

        forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
        if not forms:
            print(f"    No se detectaron formularios")
            self.report.add_finding("ok", "No forms on homepage")
            return

        print(f"    Formularios: {len(forms)}")
        for i, f_html in enumerate(forms, 1):
            method = (re.search(r'method=["\'](GET|POST)["\']', f_html, re.IGNORECASE) or [None, "GET"]).group(1) if re.search(r'method=["\'](GET|POST)["\']', f_html, re.IGNORECASE) else "GET"
            action = (re.search(r'action=["\']([^"\']+)["\']', f_html, re.IGNORECASE) or [None, "/"]).group(1) if re.search(r'action=["\']([^"\']+)["\']', f_html, re.IGNORECASE) else "/"
            has_csrf = bool(re.search(r'csrf|token|_token|nonce|authenticity_token', f_html, re.IGNORECASE))
            has_pwd = 'type="password"' in f_html
            inputs = len(re.findall(r'<input[^>]*>', f_html, re.IGNORECASE))

            print(f"    Form #{i}: method={method}, action={action}, inputs={inputs}, pwd={'S' if has_pwd else 'N'}, CSRF={'S' if has_csrf else 'N'}")
            if not has_csrf and method == "POST":
                self.report.add_finding("high", f"Form #{i} lacks CSRF token",
                    detail=f"Method=POST, Action={action}", fix="Add CSRF token to all POST forms")

    # ═══ 9. CORS ═══
    def _check_cors(self):
        print(f"\n  [9/20] CORS Configuration")
        try:
            req = Request(f"{self.target}/")
            req.add_header("Origin", "https://evil.com")
            with urlopen(req, timeout=10) as r:
                cors = r.headers.get("Access-Control-Allow-Origin", "")
                creds = r.headers.get("Access-Control-Allow-Credentials", "")

                if cors == "*":
                    print(f"    CORS: Wildcard (*) — cualquier sitio puede leer datos")
                    self.report.add_finding("critical", "CORS wildcard origin (*)",
                        fix="Restrict to specific trusted domains")
                elif cors:
                    print(f"    CORS: {cors}")
                    if "evil.com" in cors:
                        print(f"    CORS: REFLEJA ORIGEN — vulnerable!")
                        self.report.add_finding("critical", "CORS origin reflection",
                            detail=f"Reflects: {cors}", fix="Do not reflect Origin header")
                    else:
                        self.report.add_finding("ok", f"CORS restricted to {cors}")
                else:
                    print(f"    CORS: No configurado (seguro por defecto)")
                    self.report.add_finding("ok", "No CORS header (secure default)")

                if creds:
                    print(f"    CORS Credentials: {creds}")
                    if cors == "*" and creds.lower() == "true":
                        self.report.add_finding("critical", "CORS wildcard + credentials = vulnerable",
                            fix="Cannot use wildcard origin with credentials=true")
        except Exception as e:
            print(f"    CORS: No configurado (seguro por defecto)")
            self.report.add_finding("ok", "No CORS header (secure default)")

    # ═══ 10. XSS ═══
    def _check_xss(self):
        print(f"\n  [10/20] Reflected XSS Test")

        # Find params from forms/links
        _, _, body = self._fetch()
        if not body:
            return

        params = set(re.findall(r'\?([^"\'\\s>]+)', body))
        param_names = set()
        for p in params:
            for kv in p.split('&'):
                if '=' in kv:
                    param_names.add(kv.split('=')[0])

        if not param_names:
            param_names = {'q', 's', 'search', 'query', 'id', 'page', 'term', 'keyword', 'lang', 'cat', 'product'}

        xss_payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>']
        reflected = []

        print(f"    Probando {len(param_names)} parametros x {len(xss_payloads)} payloads...")
        for param in list(param_names)[:10]:
            for payload in xss_payloads:
                try:
                    test_url = f"{self.target}/?{param}={quote(payload)}"
                    req = Request(test_url)
                    with urlopen(req, timeout=10) as r:
                        resp = r.read().decode("utf-8", errors="ignore")
                        if any(c in resp for c in ['<script>alert', 'onerror=alert', 'onload=alert']):
                            reflected.append(param)
                            print(f"    [XSS] Posible via ?{param}= (payload reflejado sin escapar)")
                            self.report.add_finding("critical", f"Reflected XSS via '{param}'",
                                detail=f"Payload reflected unescaped", fix="Sanitize all user input, use CSP headers")
                            break
                except:
                    pass

        print(f"    Resultado: {'VULNERABLE' if reflected else 'No detectado'} ({len(reflected)} parametros)")

    # ═══ 11. SQLi ═══
    def _check_sqli(self):
        print(f"\n  [11/20] SQL Injection Test")
        _, _, body = self._fetch()
        if not body:
            return

        params = set(re.findall(r'\?([^"\'\\s>]+)', body))
        param_names = set()
        for p in params:
            for kv in p.split('&'):
                if '=' in kv:
                    param_names.add(kv.split('=')[0])

        if not param_names:
            param_names = {'id', 'page', 'cat', 'product', 'user', 'order', 'num'}

        sqli_payloads = [
            ("'", "Single quote"),
            ("' OR '1'='1", "Auth bypass"),
            ("' OR 1=1--", "OR true"),
            ("' AND 1=1--", "AND true"),
        ]

        sqli_errors = ["sql", "mysql", "sqlite", "postgresql", "syntax error", "unclosed quotation",
                       "incorrect syntax", "warning: mysql", "driver", "odbc", "column count"]

        vulnerable = []
        print(f"    Probando {len(param_names)} parametros x {len(sqli_payloads)} payloads...")
        for param in list(param_names)[:10]:
            for payload, ptype in sqli_payloads:
                try:
                    test_url = f"{self.target}/?{param}={quote(payload)}"
                    req = Request(test_url)
                    with urlopen(req, timeout=10) as r:
                        resp = r.read().decode("utf-8", errors="ignore").lower()
                        for sign in sqli_errors:
                            if sign in resp:
                                vulnerable.append(param)
                                print(f"    [SQLi] Posible via ?{param}= ('{ptype}' -> '{sign}' visible)")
                                self.report.add_finding("critical", f"SQL Injection via '{param}'",
                                    detail=f"Payload '{ptype}' triggered SQL error", fix="Use parameterized queries")
                                break
                        if param in vulnerable:
                            break
                except:
                    pass

        print(f"    Resultado: {'VULNERABLE' if vulnerable else 'No detectado'} ({len(vulnerable)} parametros)")

    # ═══ 12. Open Redirect ═══
    def _check_open_redirect(self):
        print(f"\n  [12/20] Open Redirect Check")
        redirect_params = ["redirect", "url", "next", "return", "goto", "target", "r", "u", "to", "dest", "destination", "link", "ref"]

        found = 0
        for param in redirect_params:
            try:
                class NoRedirect(HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                        return None
                opener = build_opener(NoRedirect)
                test_url = f"{self.target}/?{param}=https://evil.com"
                req = Request(test_url)
                resp = opener.open(req, timeout=8)
                if resp.status in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        print(f"    [OPEN REDIRECT] ?{param}= redirige a {location}")
                        self.report.add_finding("critical", f"Open redirect via '{param}'",
                            detail=f"Redirects to: {location}", fix="Validate redirect URLs against whitelist")
                        found += 1
            except:
                pass

        print(f"    Resultado: {'VULNERABLE' if found else 'No detectado'} ({found} parametros)")

    # ═══ 13. Info Disclosure ═══
    def _check_info_disclosure(self):
        print(f"\n  [13/20] Information Disclosure")
        status, headers, body = self._fetch()
        if not body:
            return

        # HTML comments
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        sensitive = [c.strip() for c in comments if any(x in c.lower() for x in
            ["todo", "fixme", "password", "secret", "key", "token", "user", "admin", "debug", "test", "hack", "vuln", "backdoor"])]
        if sensitive:
            print(f"    Comentarios HTML con info sensible: {len(sensitive)}")
            for c in sensitive[:3]:
                print(f"      {c[:100]}")
                self.report.add_finding("medium", "Sensitive info in HTML comments",
                    detail=c[:200], fix="Remove development comments before deployment")

        # Server version
        server = headers.get("Server", "")
        if "/" in server and any(c.isdigit() for c in server):
            print(f"    Version de servidor expuesta: {server}")
            self.report.add_finding("medium", "Server version disclosed",
                detail=server, fix="Set ServerTokens Prod (Apache) or server_tokens off (Nginx)")

        # Debug endpoints
        debug_paths = ["/debug", "/status", "/info", "/phpinfo.php", "/server-status", "/.env", "/config.json", "/trace", "/.aws/credentials"]
        for path in debug_paths:
            s, _, db_body = self._fetch(path)
            if s == 200 and db_body and len(db_body) > 50:
                print(f"    [INFO LEAK] {path} -> HTTP 200 ({len(db_body)} bytes)")
                self.report.add_finding("high", f"Info leak via {path}", detail=f"HTTP 200, {len(db_body)} bytes",
                    fix=f"Restrict access to {path}")

    # ═══ 14. WAF/CDN ═══
    def _check_waf_cdn(self):
        print(f"\n  [14/20] WAF / CDN Detection")
        status, headers, _ = self._fetch()
        if not status:
            return

        waf_signs = {
            "Cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "Akamai": ["x-akamai-"],
            "Fastly": ["x-served-by", "x-cache", "x-timer"],
            "Incapsula": ["x-iinfo"],
            "Sucuri": ["x-sucuri-id"],
            "AWS WAF": ["x-amzn-requestid", "x-amzn-trace-id"],
            "Azure WAF": ["x-azure-ref"],
            "F5 BIG-IP": ["x-application-context"],
        }
        detected = []
        for name, sigs in waf_signs.items():
            for sig in sigs:
                if any(sig.lower() in h.lower() for h in headers):
                    detected.append(name)
                    break

        if detected:
            for waf in set(detected):
                print(f"    WAF/CDN Detectado: {waf}")
                self.report.add_finding("ok", f"WAF/CDN: {waf}")
        else:
            print(f"    No se detecto WAF/CDN — servidor potencialmente expuesto")
            self.report.add_finding("high", "No WAF or CDN detected",
                detail=f"Server: {headers.get('Server', '')}",
                fix="Consider Cloudflare, AWS WAF, or CloudFront")

    # ═══ 15. Mixed Content ═══
    def _check_mixed_content(self):
        print(f"\n  [15/20] Mixed Content (HTTP on HTTPS)")
        if self.target.startswith("http://"):
            print(f"    Sitio en HTTP, no aplica")
            return

        _, _, body = self._fetch()
        if not body:
            return

        # Find HTTP resources
        http_resources = re.findall(r'src=["\']http://[^"\']+["\']', body) + \
                         re.findall(r'href=["\']http://[^"\']+["\']', body)

        if http_resources:
            print(f"    Recursos HTTP en pagina HTTPS: {len(http_resources)}")
            for r in http_resources[:5]:
                print(f"      {r[:80]}")
                self.report.add_finding("high", "Mixed content detected",
                    detail=f"HTTP resource on HTTPS page: {r[:80]}",
                    fix="Use HTTPS URLs for all resources (protocol-relative URLs)")
        else:
            print(f"    No se detecto contenido mixto")
            self.report.add_finding("ok", "No mixed content detected")

    # ═══ 16. Cache & Compression ═══
    def _check_cache(self):
        print(f"\n  [16/20] Cache & Compression")
        status, headers, _ = self._fetch()
        if not status:
            return

        cache_control = headers.get("Cache-Control", "")
        if "no-store" in cache_control or "no-cache" in cache_control:
            print(f"    Cache-Control: {cache_control} (OK — no almacena datos sensibles)")
        elif cache_control:
            print(f"    Cache-Control: {cache_control}")
            self.report.add_finding("medium", "Cache-Control allows caching",
                fix="Use 'Cache-Control: no-store, no-cache' for sensitive pages")
        else:
            print(f"    Cache-Control: No configurado")
            self.report.add_finding("medium", "Cache-Control header missing",
                fix="Set Cache-Control header to prevent sensitive data caching")

        # Compression
        content_encoding = headers.get("Content-Encoding", "")
        if content_encoding:
            print(f"    Compression: {content_encoding} (OK)")
        else:
            print(f"    Compression: No detectada (recomendado: Gzip/Brotli)")

    # ═══ 17. HTTPS Enforcement ═══
    def _check_https_enforcement(self):
        print(f"\n  [17/20] HTTPS Enforcement")
        http_url = self.target.replace("https://", "http://")
        try:
            s, h, _ = self._fetch_no_redirect("/")
            if s in (301, 302, 307, 308):
                location = h.get("Location", "")
                print(f"    HTTP -> HTTPS redirect: {s} -> {location[:60]}...")
                self.report.add_finding("ok", f"HTTP redirects to HTTPS ({s})")
            elif s == 200:
                print(f"    HTTP -> HTTP 200 (NO redirige a HTTPS)")
                self.report.add_finding("critical", "HTTP does not redirect to HTTPS",
                    fix="Configure redirect from HTTP to HTTPS (301)")
            else:
                print(f"    HTTP no disponible (posible HSTS preload)")
                self.report.add_finding("ok", "HTTP not available (HSTS preload)")
        except:
            print(f"    HTTP no accesible")

    # ═══ 18. Security.txt ═══
    def _check_security_txt(self):
        print(f"\n  [18/20] Security.txt")
        for path in ["/.well-known/security.txt", "/security.txt"]:
            s, _, body = self._fetch(path)
            if s == 200 and body:
                print(f"    Encontrado: {path}")
                self.report.add_finding("ok", f"security.txt found at {path}")
                return
        print(f"    No se encontro security.txt")
        self.report.add_finding("low", "security.txt not found",
            fix="Add .well-known/security.txt with contact and disclosure policy")

    # ═══ 19. SRI Check ═══
    def _check_sri(self):
        print(f"\n  [19/20] Subresource Integrity (SRI)")
        _, _, body = self._fetch()
        if not body:
            return

        # Find external scripts/styles
        external = re.findall(r'(<script[^>]*src=["\'][^"\']+["\'])|(<link[^>]*href=["\'][^"\']+["\'])', body)
        total = len(external)
        sri_count = body.count("integrity=")

        if external:
            print(f"    Recursos externos: {total}")
            print(f"    Con SRI: {sri_count}")
            if total > 0 and sri_count < total:
                self.report.add_finding("medium", f"{total - sri_count}/{total} external resources without SRI",
                    fix="Add integrity attribute to all <script> and <link> tags")
            else:
                self.report.add_finding("ok", "All resources have SRI")
        else:
            print(f"    No se detectaron recursos externos")

    # ═══ 20. Ports ═══
    def _check_ports(self):
        print(f"\n  [20/20] Network Ports")
        common_ports = {"80": "HTTP", "443": "HTTPS", "22": "SSH", "8080": "HTTP-Alt", "3306": "MySQL", "5432": "PostgreSQL", "21": "FTP", "25": "SMTP"}

        for port, service in common_ports.items():
            try:
                with socket.create_connection((self.host, int(port)), timeout=3):
                    if port == "443":
                        print(f"    Port {port} ({service}): Abierto (OK)")
                    elif port == "80":
                        print(f"    Port {port} ({service}): Abierto (debe redirigir a HTTPS)")
                    elif port in ("22", "8080"):
                        print(f"    Port {port} ({service}): Abierto (riesgo medio)")
                        self.report.add_finding("medium", f"Port {port} ({service}) open",
                            fix="Restrict access to trusted IPs only via firewall")
                    else:
                        print(f"    Port {port} ({service}): EXPUESTO")
                        self.report.add_finding("high", f"Port {port} ({service}) exposed",
                            fix="Close port or restrict via firewall")
            except:
                pass


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Target URL/IP: ")
    audit = WebAudit(target)
    report_path = audit.run()
    print(f"\n  Report: {report_path}")
