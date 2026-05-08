# 🔐 Ares Tool Security

> Interactive security auditing suite for systems and web applications.
> CLI bash + Python. Reports in Markdown and HTML.

[![CI](https://github.com/uramos89/ares-tool-security/actions/workflows/ci.yml/badge.svg)](https://github.com/uramos89/ares-tool-security/actions/workflows/ci.yml)

---

## 📋 Prerequisites

### Required for both OS

| Requirement | Description | Download |
|-------------|-------------|----------|
| **Git** | Version control system to clone the repository | [git-scm.com](https://git-scm.com/downloads) |
| **Python 3.12+** | Core runtime for all audit modules | [python.org](https://www.python.org/downloads/) |

### Verify Installation

**Linux (Ubuntu/Debian):**
```bash
git --version
python3 --version
```

**Windows (PowerShell):**
```powershell
git --version
python --version
```
> **Note:** On Windows, use `python` instead of `python3`.

---

## 🚀 Quick Start

### Linux / macOS

```bash
# 1. Clone the repository
git clone https://github.com/uramos89/ares-tool-security.git
cd ares-tool-security

# 2. Make scripts executable
chmod +x audit.sh
chmod +x scripts/full-scan.py

# 3. Run interactive menu
./audit.sh

# Or run full scan directly
python3 scripts/full-scan.py https://example.com
```

### Windows (PowerShell)

```powershell
# 1. Clone the repository
git clone https://github.com/uramos89/ares-tool-security.git
cd ares-tool-security

# 2. Run full scan (all 4 modules)
python scripts/full-scan.py https://example.com

# Or run modules individually
python modules/web-audit.py https://example.com
python modules/brute-force.py https://example.com
python modules/ddos-audit.py https://example.com
python modules/vuln-scan.py https://example.com
python modules/harpoon.py https://example.com
python modules/harpoon.py 192.168.1.1 --ports 22,80,3306
```

---

## 📋 Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | 🌐 Web Audit | SSL, security headers (9), stack fingerprinting, directory busting (22 paths), DNS/SPF/DMARC, cookie security, forms & CSRF, CORS, reflected XSS, SQL injection, open redirect, info disclosure, WAF/CDN (12 providers), mixed content, cache & compression, HTTPS enforcement, security.txt, SRI (Subresource Integrity), network ports (8 ports) |
| 2 | 🔨 Brute Force | Catch-all detection, rate limiting test (15 requests), lockout test (20 rapid requests), 2FA endpoint scan |
| 3 | 🛡️ DDoS Audit | WAF/CDN detection (Cloudflare, CloudFront, Akamai, Fastly, AWS WAF, etc.), rate limiting headers analysis, concurrent load test (10 parallel), timeout & connection analysis |
| 4 | 🎯 Vuln Scan | Form analysis + CSRF detection, cookie security audit (Secure/HttpOnly/SameSite), CORS misconfiguration, reflected XSS (7 payloads × 8 params), SQL injection (8 payloads × 8 params), open redirect (12 params), information disclosure |
| 5 | 🎯 **Harpoon** | **Service validation**: SSH (banner, ciphers, auth methods, CVE lookup), HTTP/HTTPS (server, methods, default panels, default creds), MySQL/PostgreSQL/Redis/MongoDB (anonymous access), FTP (anonymous login), SMTP (STARTTLS), SMB/Telnet. Reads banners, probes default credentials, checks for CVEs by version |

---

## ⚡ Examples

```bash
# Interactive audit menu (Linux only)
./audit.sh

# Full scan — all 4 modules, single command
python3 scripts/full-scan.py https://example.com

# Individual modules
python3 modules/web-audit.py https://example.com
python3 modules/brute-force.py https://example.com
python3 modules/ddos-audit.py https://example.com
python3 modules/vuln-scan.py https://example.com
python3 modules/harpoon.py https://example.com

# Harpoon with custom ports
python3 modules/harpoon.py 192.168.1.1 --ports 22,80,443,3306,6379
```

---

## 🧠 Catch-All Detection

Ares automatically detects servers with **catch-all routing** (returning 200 instead of 404 for non-existent paths). When detected, sensitive paths are flagged as **false positives** with a ⚠️ badge and excluded from critical findings.

---

## 📊 Reports

### Markdown Format (.md)

All reports are saved in `reports/` as `.md` with scoring, severity levels, and fix recommendations.

### Professional HTML via AI

Use the [`docs/FORGE_REPORT.md`](docs/FORGE_REPORT.md) as a **universal prompt** for ANY AI model (ChatGPT, Claude, Gemini, Copilot) to generate a professional HTML report with:

- 🎨 **Light corporate theme** (`#f4f6f9` background, white cards, Bootstrap 5.3)
- 🌐 **ESP 🇪🇸 / ENG 🇬🇧 language toggle**
- ✨ **CSS animations** (fadeInUp, card hover)
- 📊 **Animated score circle** with weighted formula `(avg + min) / 2`
- 🔍 **Each finding** with CWE, OWASP, and ISO 27001 tags
- 📋 **Prioritized recommendations**
- 📄 **PDF export button** (html2pdf.js)
- 📚 **Technical references table** with MITRE links
- ⚖️ **Auditable legal footer**

#### How to Generate the HTML

```bash
# 1. Run all 4 modules
python3 scripts/full-scan.py https://example.com

# 2. Open ChatGPT/Claude/Gemini and paste:
#    - The contents of docs/FORGE_REPORT.md
#    - The contents of all .md files from reports/
#    - Ask: "Generate the HTML report"
#    → The AI returns a complete .html file
```

---

## 📂 Project Structure

```
ares-tool-security/
├── audit.sh              ← Interactive entry point (Linux)
├── scripts/
│   └── full-scan.py      ← Run all 4 modules: python3 scripts/full-scan.py <url>
├── modules/              ← Audit modules
│   ├── web-audit.py      ← 20 security checks
│   ├── brute-force.py    ← Rate limiting + lockout
│   ├── ddos-audit.py     ← WAF/CDN + load test
│   ├── vuln-scan.py      ← XSS, SQLi, CORS, CSRF
│   └── harpoon.py        ← Service validation (SSH, DB, FTP, HTTP methods, panels)
├── lib/                  ← Libraries
│   ├── reporter.py       ← .md report generator
│   ├── report-html.py    ← .md → .html converter (native)
│   ├── mailer.py         ← Email sender (AgentMail + SMTP)
│   └── colors.sh         ← Terminal colors
├── tests/                ← Unit tests
├── reports/              ← Generated reports (.md / .html)
├── scrum/                ← Agile methodology docs
└── docs/
    └── FORGE_REPORT.md   ← Universal AI prompt for HTML generation
```

---

## 🤝 Contributing

```bash
git clone https://github.com/uramos89/ares-tool-security.git
cd ares-tool-security
./audit.sh
```

---

*Built with ❤️ by uramos89 and Alicia ✨*
