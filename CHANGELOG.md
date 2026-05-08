# Changelog

## v2.0.0 — 2026-05-08
### Added
- 🛡️ **Módulo DDoS Audit** (ddos-audit.py)
  - WAF/CDN detection (Cloudflare, CloudFront, Akamai, Fastly, AWS WAF, etc.)
  - Rate limiting headers analysis
  - Concurrent load test (10 parallel requests with timing)
  - Timeout & connection analysis
- 🎯 **Módulo Vulnerability Scan** (vuln-scan.py)
  - Form analysis + CSRF token detection
  - Cookie security audit (Secure, HttpOnly, SameSite)
  - CORS misconfiguration detection (wildcard + mirroring)
  - Open redirect parameter fuzzing (12 redirect params)
  - Information disclosure (HTML comments, server version, debug endpoints)
- 🌐 **Web Audit** mejorado
  - Catch-all routing detection (falsos positivos en sitios PHP legacy)
  - Directory busting con detección de catch-all
  - Reportes con encoding UTF-8 forzado (compatible Windows cp1252)
- 🔨 **Brute Force** mejorado
  - Catch-all detection automático antes de ejecutar tests
  - No pregunta login endpoint (usa /api/login por defecto)
  - DDoS resilience indicators (concurrent request handling)
- 📋 **Full Scan** ahora incluye los 4 módulos

### Fixed
- UnicodeEncodeError en Windows (cp1252) — encoding UTF-8 forzado en reporter.py
- Falsos positivos en sitios con catch-all routing (Apache/PHP legacy)
- Prompt innecesario de login endpoint eliminado

## v0.1.0 — 2026-05-06
### Added
- 🎯 Entry point interactivo (audit.sh) con menú coloreado
- 🌐 Módulo Web Audit — SSL, security headers, stack fingerprint, puertos
- 🔨 Módulo Brute Force — Rate limiting, account lockout, 2FA
- 📊 Generador de reportes .md con scoring y severidades
- 🧪 Tests unitarios (3 tests)
- 🔧 CI/CD pipeline (GitHub Actions)
- 📚 Scrum docs (BACKLOG, SPRINT, ADRs)
- 📖 README con instrucciones de uso
