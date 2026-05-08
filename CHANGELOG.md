# Changelog

## v2.1.0 — 2026-05-08
### Added
- **HTML Report Generator** (`lib/report-html.py`)
  - Converts any .md report into professional HTML
  - Dark theme, responsive, ESP/ENG toggle
  - Score circle, severity badges, CWE/OWASP/ISO mapping
  - Prioritized recommendations, technical references table
- **Documentation**
  - `docs/FORGE_REPORT.md` — universal AI prompt for HTML report generation
  - Full English documentation across all files
- **Native HTML Converter** — no external AI needed

## v2.0.0 — 2026-05-08
### Added
- 🛡️ **DDoS Audit Module** (`ddos-audit.py`)
  - WAF/CDN detection (Cloudflare, CloudFront, Akamai, Fastly, AWS WAF, etc.)
  - Rate limiting headers analysis
  - Concurrent load test (10 parallel requests with timing)
  - Timeout & connection analysis
- 🎯 **Vulnerability Scan Module** (`vuln-scan.py`)
  - Form analysis + CSRF token detection
  - Cookie security audit (Secure, HttpOnly, SameSite)
  - CORS misconfiguration detection (wildcard + mirroring)
  - Open redirect parameter fuzzing (12 redirect params)
  - Information disclosure (HTML comments, server version, debug endpoints)
- 🌐 **Web Audit** enhanced
  - Catch-all routing detection (false positives in PHP legacy sites)
  - Directory busting with catch-all detection
  - Forced UTF-8 encoding for Windows compatibility
- 🔨 **Brute Force** enhanced
  - Automatic catch-all detection before running tests
  - No login endpoint prompt (uses /api/login by default)
  - DDoS resilience indicators (concurrent request handling)
- 📋 **Full Scan** now includes all 4 modules

### Fixed
- UnicodeEncodeError on Windows (cp1252) — forced UTF-8 encoding in reporter.py
- False positives on catch-all routing sites (Apache/PHP legacy)
- Unnecessary login endpoint prompt removed

## v0.1.0 — 2026-05-06
### Added
- 🎯 Interactive entry point (`audit.sh`) with colored menu
- 🌐 Web Audit module — SSL, security headers, stack fingerprint, ports
- 🔨 Brute Force module — Rate limiting, account lockout, 2FA
- 📊 Report generator — .md with scoring and severity levels
- 🧪 Unit tests (3 tests)
- 🔧 CI/CD pipeline (GitHub Actions)
- 📚 Scrum documentation (BACKLOG, SPRINT, ADRs)
- 📖 README with usage instructions
