# ⚔️ Ares Forge Report — Universal Prompt for HTML Report Generation

> **Purpose:** This file contains instructions for any AI model (Claude, ChatGPT, Gemini, Copilot, etc.) to generate a **professional bilingual HTML report** from the `.md` files produced by **Ares Tool Security**.
>
> **Usage:** Provide the AI with the 2 audit `.md` files + this file's content as instructions. The AI will output a single `.html` file.

---

## 🎯 Objective

Generate a `audit-report-<domain>.html` file with:

- **Professional dark theme** (slate/dark blue: `#0f172a`, cards: `#1e293b`, borders: `#334155`)
- **Bilingual language toggle** ESP 🇪🇸 / ENG 🇬🇧 — switches all content without page reload
- **CSS animations** (fadeInUp, score circle pulse, card hover elevation)
- **Animated score circle** with circular fill effect (CSS radial-gradient or SVG circle with stroke-dashoffset animation)
- **Responsive design** (clamp fonts, auto-fit grid, mobile media queries down to 320px)
- **Severity badges** with distinctive colors for each level
- **CWE + OWASP + ISO 27001** references auto-mapped per finding
- **Technical references table** with links to MITRE
- **Prioritized recommendations** (critical and high first)
- **Auditable legal footer** with AI agent signature

---

## 📥 Input

You will receive **up to 4 Markdown files** (one per module executed):

1. `web-audit-<domain>-<date>.md` — Full web audit (20 checks: SSL, headers, stack, dir busting, forms, cookies, CORS, XSS, SQLi, DNS, ports, etc.)
2. `brute-force-<domain>-<date>.md` — Brute force test (rate limiting, lockout, 2FA detection)
3. `ddos-audit-<domain>-<date>.md` — DDoS resilience (WAF/CDN detection, concurrent load, timeout)
4. `vuln-scan-<domain>-<date>.md` — Vulnerability scan (CSRF, XSS, SQLi, CORS, open redirect, info disclosure)

All follow the standard Ares Tool Security format: headings with `# `, findings with `**N. Title**`, severity with emojis 🔴🟠🟡🔵✅, and sections `### 🔴 CRITICAL`, `### 🟠 HIGH`, etc.

Consolidate findings from ALL available .md files into a single HTML report. Merge duplicate findings and combine severity counts across modules.

---

## 📋 HTML Technical Specifications

### Document Structure

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ares Tool Security — Audit Report / Reporte de Auditoría</title>
  <style>/* ... */</style>
</head>
<body>
  <!-- Language Toggle -->
  <!-- Header -->
  <!-- Target Info Card -->
  <!-- Summary Card (Score + Counts) -->
  <!-- Findings Cards -->
  <!-- Recommendations -->
  <!-- Technical References -->
  <!-- Footer -->
  <script>/* language toggle */</script>
</body>
</html>
```

### CSS Palette

```css
/* Palette */
body    { background: #0f172a; color: #e2e8f0; }
.card   { background: #1e293b; border: 1px solid #334155; }
.stat-box { background: #0f172a; }

/* Score Circle */
.score-circle {
  border: 6px solid;
  border-radius: 50%;
  width: clamp(80px, 15vw, 120px);
  height: clamp(80px, 15vw, 120px);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  font-size: clamp(1.8em, 5vw, 2.5em);
  font-weight: 700;
}
/* Score color: <50: #dc2626, 50-79: #d97706, >=80: #16a34a */

/* Severity colors */
.critical: #dc2626 | .high: #ea580c | .medium: #d97706
.low: #2563eb | .pass: #16a34a

/* Finding cards: colored left border + translucent background */
.finding-{severity} {
  border-left: 4px solid <color>;
  background: rgba(<color_rgb>, 0.15);
}
```

### CSS Animations

```css
/* Card fadeInUp stagger */
@keyframes fadeInUp {
  from { opacity: 0; transform: translateY(20px); }
  to   { opacity: 1; transform: translateY(0); }
}
.card { animation: fadeInUp 0.5s ease-out; }
.card:nth-child(n) { animation-delay: 0.1s * n; }

/* Score circle pulse */
@keyframes pulse {
  0% { transform: scale(1); }
  50% { transform: scale(1.05); }
  100% { transform: scale(1); }
}

/* Card hover */
.card:hover { transform: translateY(-2px); box-shadow: 0 8px 12px rgba(0,0,0,0.4); }
```

### Bilingual Language Toggle (JavaScript)

The report MUST have a working ESP/ENG toggle. Use this pattern:

```javascript
function switchLang(lang) {
  document.querySelectorAll('.lang-es').forEach(el => el.classList.toggle('lang-hidden', lang !== 'es'));
  document.querySelectorAll('.lang-en').forEach(el => el.classList.toggle('lang-hidden', lang !== 'en'));
  document.getElementById('btn-es').classList.toggle('active', lang === 'es');
  document.getElementById('btn-en').classList.toggle('active', lang === 'en');
  document.documentElement.lang = lang;
}
```

CSS for visibility:
```css
.lang-es, .lang-en { transition: opacity 0.3s; }
.lang-hidden { display: none !important; }
```

Every text element that differs by language must have TWO versions:
```html
<span class="lang-es">Texto en español</span>
<span class="lang-en lang-hidden">English text</span>
```

### Score Circle with SVG Animation (Optional, Recommended)

For a professional look, use SVG circle with `stroke-dasharray` and animated `stroke-dashoffset` to visually display the score as a circular progress indicator.

---

## 📊 Finding-to-CWE/OWASP/ISO Mapping

Use this table to assign references to each finding type:

| Finding Type | CWE | OWASP | ISO 27001 |
|-------------|-----|-------|-----------|
| Missing CSP header | CWE-1021, CWE-79 | A5:2021 | A.8.25 |
| Missing HSTS header | CWE-319 | A5:2021 | A.8.20 |
| Missing X-Frame-Options | CWE-1021 | A4:2021 | A.8.20 |
| Missing X-Content-Type-Options | CWE-345 | A5:2021 | A.8.24 |
| Missing Referrer-Policy | CWE-200 | — | A.8.11 |
| Missing Permissions-Policy | CWE-200 | — | A.8.11 |
| CORS wildcard / mirroring | CWE-942 | A1:2021 | A.8.20 |
| Reflected XSS | CWE-79 | A3:2021 | A.8.25 |
| SQL Injection | CWE-89 | A3:2021 | A.8.25 |
| Open Redirect | CWE-601 | A1:2021 | A.8.11 |
| Missing CSRF token | CWE-352 | A1:2021 | A.8.5 |
| Cookie missing Secure | CWE-614 | A4:2021 | A.8.20 |
| Cookie missing HttpOnly | CWE-1004 | — | A.8.20 |
| No rate limiting / lockout | CWE-307 | A7:2021 | A.8.5 |
| Path exposed / Info leak | CWE-200 | A1:2021 | A.8.11 |
| No WAF/CDN | CWE-693 | — | A.8.21 |
| Mixed content | CWE-948 | — | A.8.20 |
| SPF/DMARC missing | CWE-345 | — | A.8.24 |
| Server version disclosed | CWE-200 | — | A.8.11 |
| SSL certificate expires soon | CWE-298 | — | A.8.20 |
| No SRI on resources | CWE-345 | — | A.8.24 |
| Cache-Control allows caching | CWE-525 | — | A.8.20 |
| security.txt not found | CWE-200 | — | A.8.11 |

---

> ⚠️ CRITICAL RULE
> 
> **EVERY visible text element MUST be bilingual (ESP + ENG).**
> Use class="lang-es" for Spanish and class="lang-en lang-hidden" for English on EVERY piece of text:
> - Finding titles, descriptions, fix labels
> - Recommendations, table headers, footer
> - Risk labels, score labels, section titles
> - Stat box labels, badge labels
> 
> If a section only has Spanish or only English text, the report is INCOMPLETE.

## 📝 Report Structure (ALL SECTIONS BILINGUAL)

### 1. Target Info Card
- Domain, audit type, date, WAF/CDN detected, SSL status
- ALL labels and values in ESP + ENG

### 2. Summary / Compliance Score Card
- **Score number** (0-100) — MUST be the ACTUAL score parsed from the .md report, NOT hardcoded as 0
- **Animated SVG score circle** with stroke-dashoffset calculated as: `377 * (1 - score/100)`
  - Example: score=40 → dashoffset = `377 * (1-0.4) = 226.2`
  - Example: score=75 → dashoffset = `377 * (1-0.75) = 94.25`
  - Animation starts from 377 (empty) and animates TO the calculated value
  - Score number displays the parsed value (NOT 0)
- **Risk label**: 🔴 HIGH / 🟡 MEDIUM / 🟢 LOW (bilingual)
- **Compliance indicator** clearly visible: e.g. "40/100" with color-coded circle
- **Count grid** of findings by severity (ALL bilingual)

### 3. Findings Cards
Each finding must display (ALL bilingual):
- Severity icon
- Title in ESP and ENG
- Finding detail/description
- **CWE + OWASP + ISO tags** (color-coded)
- Recommended fix in `<code>` block

### 4. Prioritized Recommendations Section
- Numbered list with most urgent corrections first (critical, then high)
- **EVERY item must have ESP + ENG versions**

### 5. Technical References Table
- Columns: Code | Description ESP/ENG | Source (MITRE link)
- Badges: OWASP Top 10, ISO 27001, NIST SP 800-53, PCI DSS v4.0
- ALL headers and descriptions bilingual

### 6. Footer (ALL BILINGUAL)
- Brand: Ares Tool Security, domain, date
- AI signature: "Sent by Alicia ✨ — Autonomous AI Agent"
- Disclaimer: "This report is auditable, verifiable and traceable under OWASP, CWE and ISO 27001"
- © 2026

## 📛 File Naming

The HTML file MUST be named: `audit-report-<domain>.html`

Good: `audit-report-sistemascontino-com-mx.html`
Bad: `report.html`, `preview.html`, `output.html`, `untitled.html`

---

## 💡 Parsing Rules

The Ares `.md` report follows this format:

```markdown
# 🔐 Ares Tool Security Audit Report

**Target:** `https://example.com`
**Type:** web-audit
**Date:** 2026-05-08
**Duration:** 10.3s

---

## 📊 Summary

**Security Score:** 45/100 🔴
...

### 🔴 CRITICAL
**1. Missing CSP header**
   - *Detail:* description
   - *Fix:* `add_header Content-Security-Policy "..."`
```

Parsing rules:
- **Score:** Extract from `**Security Score:** (\d+)/100`
- **Target:** Extract from `` **Target:** `(.+)` ``
- **Critical findings:** Under `### 🔴 CRITICAL`
- **High findings:** Under `### 🟠 HIGH`
- **Medium findings:** Under `### 🟡 MEDIUM`
- **Low findings:** Under `### 🔵 LOW`
- **Passed checks:** Under `### ✅ PASS`
- Each finding: `**N. Title**` + `Detail:` + `Fix:`

---

## ✅ Validation Checklist

Before delivering the HTML, verify:

- [ ] Language toggle ESP/ENG works (click both buttons)
- [ ] Animated score circle with correct color based on score
- [ ] All findings parsed from both .md files
- [ ] CWE/OWASP/ISO tags assigned correctly per finding type
- [ ] CSS animations working (fadeInUp, pulse, card hover)
- [ ] Responsive at 3 breakpoints: desktop, tablet, mobile (320px)
- [ ] No JavaScript console errors
- [ ] Self-contained HTML/CSS/JS (no external CDN dependencies)
- [ ] File named as `audit-report-<domain>.html`
- [ ] Legal footer present with AI signature and disclaimer

---

## 🔗 Reference Visual Layout

The final HTML should follow this structure:

```
┌──────────────────────────────────────────┐
│  [🇪🇸 Español] [🇬🇧 English]              │  ← Sticky language toggle
├──────────────────────────────────────────┤
│         ⚔️ Ares Tool Security            │
│    Web Security Audit / Auditoría Web    │
│    [40/100] [Cloudflare] [SSL: ✅]       │
├──────────────────────────────────────────┤
│  🎯 Target Information                   │
│  ┌──────┬──────┬──────┬──────┐           │
│  │Domain│ Type │ Date │Report│           │
│  └──────┴──────┴──────┴──────┘           │
├──────────────────────────────────────────┤
│  📊 Security Summary                     │
│       ┌──────────┐                       │
│       │   40     │  ← Animated score     │
│       │  / 100   │                       │
│       └──────────┘                       │
│  🔴 HIGH RISK — Corrective actions req.  │
│  ┌───┬───┬───┬───┬───┐                  │
│  │🔴4│🟠1│🟡1│🔵0│✅2│                  │
│  └───┴───┴───┴───┴───┘                  │
├──────────────────────────────────────────┤
│  🔍 Detailed Findings                    │
│                                          │
│  ┌──────────────────────────────────┐    │
│  │🔴 Missing CSP Header             │    │  ← fadeInUp animation
│  │ Detail: Header not implemented.. │    │
│  │ [CWE-1021] [CWE-79] [OWASP A5]  │    │
│  │ Fix: add_header Content-Sec...   │    │
│  └──────────────────────────────────┘    │
│  ...                                     │
├──────────────────────────────────────────┤
│  📋 Recommendations (prioritized)        │
│  1. Implement security headers           │
│  2. Close exposed ports                  │
│  3. Enable HSTS Preload                  │
├──────────────────────────────────────────┤
│  📚 Technical References                  │
│  ┌──────┬──────────────────┬──────┐      │
│  │CWE-79│ XSS              │MITRE │      │
│  │CWE-89│ SQL Injection    │MITRE │      │
│  └──────┴──────────────────┴──────┘      │
│  [OWASP] [ISO] [NIST] [PCI DSS]          │
├──────────────────────────────────────────┤
│  Legal footer / AI signature              │
└──────────────────────────────────────────┘
```

---

## 🚀 Workflow

1. User runs Ares Tool Security modules and gets `.md` files in `reports/`:
   ```bash
   python3 modules/web-audit.py https://example.com
   python3 modules/brute-force.py https://example.com
   python3 modules/ddos-audit.py https://example.com
   python3 modules/vuln-scan.py https://example.com
   ```
2. User provides you (AI model) with:
   - This file (`FORGE_REPORT.md`) as instructions
   - The content of ALL available `.md` files from `reports/`
3. You generate a single `audit-report-<domain>.html` file consolidating ALL findings
4. User opens the `.html` in their browser — professional bilingual report ready

---

*Created by Alicia ✨ — Ares Tool Security | ContextP / OBPA Framework*
