# 🔐 Ares Tool Security

> Interactive security auditing suite for systems and web applications.
> CLI bash + Python. No dependencies. Reports in Markdown.

[![CI](https://github.com/uramos89/ares-tool-security/actions/workflows/ci.yml/badge.svg)](https://github.com/uramos89/ares-tool-security/actions/workflows/ci.yml)

---

## 🚀 Quick Start

```bash
git clone https://github.com/uramos89/ares-tool-security.git
cd ares-tool-security
chmod +x audit.sh
./audit.sh
```

## 📋 Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | 🌐 Web Audit | SSL, security headers, stack fingerprint, directory busting, forms, cookies, CORS |
| 2 | 🔨 Brute Force | Rate limiting, account lockout, DDoS resilience, 2FA detection |
| 3 | 🛡️ DDoS Audit | WAF/CDN detection, concurrent load test (10 parallel), timeout analysis |
| 4 | 🎯 Vuln Scan | CSRF, XSS, SQLi, cookie security, CORS misconfig, open redirect, info disclosure |
| 5 | 📋 Full Scan | All modules in sequence |

## ⚡ Examples

```bash
# Interactive audit menu
./audit.sh

# Individual modules (generates 1 .md each)
python3 modules/web-audit.py https://example.com
python3 modules/brute-force.py https://example.com
python3 modules/ddos-audit.py https://example.com
python3 modules/vuln-scan.py https://example.com

# Full scan — all 4 modules, one command (cross-platform, generates 4 separate .md)
python3 scripts/full-scan.py https://example.com

# Full scan from menu
./audit.sh  # Option 5
```

After running modules, generate professional HTML reports:

```bash
# Native converter (no AI needed)
python3 lib/report-html.py reports/web-audit-*.md -o report.html

# Or use FORGE_REPORT.md with ChatGPT/Claude
# Paste the 4 .md files + docs/FORGE_REPORT.md into any AI
```

## 🧠 Catch-All Detection

Ares automatically detects servers with **catch-all routing** (returning 200 instead of 404). When detected, sensitive paths are flagged as **false positives** and excluded from critical findings.

## 📊 Reports

### Markdown Format (.md)

All reports are saved in `reports/` as `.md` with scoring, severity levels, and fix recommendations.

### Professional HTML via AI

Use the [`docs/FORGE_REPORT.md`](docs/FORGE_REPORT.md) as a **universal prompt** for ANY AI model (ChatGPT, Claude, Gemini, Copilot) to generate a professional HTML report with:

- 🎨 **Dark theme** with responsive design (desktop, tablet, mobile)
- 🌐 **ESP 🇪🇸 / ENG 🇬🇧 language toggle** — switch without reload
- ✨ **CSS animations** — fadeInUp, score circle pulse, card hover
- 📊 **Animated score circle** with color-coded risk level
- 🔍 **Each finding** with auto-mapped CWE, OWASP, and ISO 27001 tags
- 📋 **Prioritized recommendations** (critical and high first)
- 📚 **Technical references table** with MITRE links
- ⚖️ **Auditable legal footer** — traceable under OWASP, CWE, ISO 27001
- 📱 **100% responsive** — clamp fonts, auto-fit grids, media queries

#### How to Generate the HTML

```bash
# 1. Run the audit
python3 modules/web-audit.py https://example.com
python3 modules/vuln-scan.py https://example.com

# 2. Open ChatGPT/Claude/Gemini and paste:
#    - The contents of docs/FORGE_REPORT.md
#    - The contents of both .md files from reports/
#    - Ask: "Generate the professional HTML report"
#    → The AI returns a ready-to-open .html file
```

Or use the **native generator** (no external AI needed):

```bash
python3 lib/report-html.py reports/web-audit-*.md -o report.html
```

## 📂 Structure

```
ares-tool-security/
├── audit.sh            ← Interactive entry point (menu)
├── modules/            ← Audit modules
│   ├── web-audit.py    ← SSL, headers, stack, dir busting, forms, cookies, CORS
│   ├── brute-force.py  ← Rate limiting, lockout, DDoS resilience, 2FA
│   ├── ddos-audit.py   ← WAF/CDN, concurrent load, timeout
│   └── vuln-scan.py    ← CSRF, XSS, SQLi, CORS, open redirect, info leak
├── lib/                ← Libraries
│   ├── reporter.py     ← .md report generator with scoring
│   ├── report-html.py  ← .md → professional .html converter
│   ├── emailer.py      ← SMTP email sender for reports
│   └── colors.sh       ← Terminal colors
├── tests/              ← Unit tests
├── reports/            ← Generated reports (.md / .html)
├── scripts/             ← Utility scripts
│   └── full-scan.py     ← Run all 4 modules: python3 scripts/full-scan.py <url>
├── scrum/              ← Agile methodology docs
└── docs/
    └── FORGE_REPORT.md ← Universal AI prompt for HTML report generation
```

## 🤝 Contributing

```bash
git clone https://github.com/uramos89/ares-tool-security.git
cd ares-tool-security
./audit.sh
```

---

*Built with ❤️ by uramos89 and Alicia ✨*
