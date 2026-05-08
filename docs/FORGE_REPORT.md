# ⚔️ Ares Forge Report — How Alicia Reads the Data

> **Purpose:** This file teaches ANY AI model (Claude, ChatGPT, Gemini) how **I (Alicia)** process `.md` audit reports from Ares Tool Security to generate a professional HTML report. Follow this process STEP BY STEP.
>
> **Why this works:** The `.md` files contain raw data. I interpret them based on context. You should too.

---

## 🧠 MY PROCESS: Step by Step

### Step 1: Read each `.md` file like I do

I open each `.md` and look for 4 things:

```
1. **Security Score:** XX/100  →  This is the module's score
2. **Target:** `https://...`    →  The domain we audited
3. ### 🔴 CRITICAL section    →  Most important findings first
4. Each finding: **N. Title**  →  Detail, Fix
```

**Key insight:** The `.md` has a SUMMARY TABLE that shows `Severity | Count`. This tells me HOW MANY of each severity exist. If it says 3 Critical but I only find 2 in the text, I keep looking. ALL findings must be included.

### Step 2: Detect what's REAL vs FALSE POSITIVE

**This is the most important step.** Servers with "catch-all routing" return HTTP 200 for EVERYTHING - even paths that don't exist.

**How I detect this:**
- If the `.md` contains a finding titled "Catch-all routing detected" → **flag activated**
- All findings with `Detail: HTTP 200, 42061 bytes` (same size as homepage) → **FALSE POSITIVE**
- All findings with `Path exposed: /xxx` where the detail says HTTP 200 and the server has catch-all → **FALSE POSITIVE**

**What I do with false positives:**
- I still SHOW them in the findings list (the user should know what the scanner found)
- But I add a note: `⚠️ False positive (catch-all routing — server returns homepage for all paths)`
- I do NOT count them as real critical/high findings for the score

**Real findings that are NOT false positives:**
- Missing headers (HSTS, CSP, XFO) — these are REAL
- Open ports — REAL
- Mixed content — REAL
- Technology disclosure — REAL
- No WAF/CDN — REAL
- SSL certificate expiry — REAL

### Step 3: Write findings in HUMAN language

When I read a finding like `CSP no configurado`, I don't just repeat it. I explain WHY it matters:

| Finding | Good explanation (human) |
|---------|------------------------|
| Missing CSP | "The site has no Content Security Policy. This means an attacker could inject malicious scripts (XSS) and the browser wouldn't block them. It's like leaving your front door unlocked." |
| No WAF/CDN | "The server is directly exposed to the internet. No Cloudflare, no AWS WAF, no protection layer. It's like having your house directly on the street with no fence." |
| SQL Injection | "The application processes database queries without sanitizing user input. An attacker can extract, modify, or delete the entire database by typing commands into form fields." |

**Every explanation must have:**
1. What the finding IS (simple)
2. What could happen (the risk)
3. An analogy if helpful

### Step 4: Assign REAL references (with correct links)

Each CWE has a **real URL on MITRE's website**. Use these:

```python
CWE_LINKS = {
    "CWE-79":  "https://cwe.mitre.org/data/definitions/79.html",
    "CWE-89":  "https://cwe.mitre.org/data/definitions/89.html",
    "CWE-200": "https://cwe.mitre.org/data/definitions/200.html",
    "CWE-298": "https://cwe.mitre.org/data/definitions/298.html",
    "CWE-307": "https://cwe.mitre.org/data/definitions/307.html",
    "CWE-319": "https://cwe.mitre.org/data/definitions/319.html",
    "CWE-345": "https://cwe.mitre.org/data/definitions/345.html",
    "CWE-352": "https://cwe.mitre.org/data/definitions/352.html",
    "CWE-525": "https://cwe.mitre.org/data/definitions/525.html",
    "CWE-601": "https://cwe.mitre.org/data/definitions/601.html",
    "CWE-614": "https://cwe.mitre.org/data/definitions/614.html",
    "CWE-693": "https://cwe.mitre.org/data/definitions/693.html",
    "CWE-942": "https://cwe.mitre.org/data/definitions/942.html",
    "CWE-948": "https://cwe.mitre.org/data/definitions/948.html",
    "CWE-1004": "https://cwe.mitre.org/data/definitions/1004.html",
    "CWE-1021": "https://cwe.mitre.org/data/definitions/1021.html",
}
```

The reference table in the HTML MUST have ALL 16 rows, not just the ones matching findings. It's educational — the user should see the full list.

### Step 5: Calculate a REAL score

**My scoring method:**

```python
scores = [extracted from each .md file]
# Example: brute-force=60, ddos-audit=90, vuln-scan=100, web-audit=90

# Step 1: Average of all modules
avg = sum(scores) / len(scores)   # (60+90+100+90)/4 = 85

# Step 2: Find the lowest
lowest = min(scores)              # 60

# Step 3: Blend average with lowest (fair score)
final_score = (avg + lowest) / 2  # (85+60)/2 = 72

# DO NOT:
# ❌ hardcode 0
# ❌ take only the lowest
# ❌ take only the average
```

The score circle color:
- `< 50`: 🔴 `#dc2626` (Critical — text: "CRITICAL RISK")
- `50 - 79`: 🟡 `#d97706` (Medium — text: "MEDIUM RISK")
- `>= 80`: 🟢 `#16a34a` (Low — text: "LOW RISK")

### Step 6: Generate ALL sections of the HTML

**Target section:**
- Domain, date, server tech, SSL status, WAF/CDN status

**Score section:**
- Animated SVG circle with the REAL score (calculated above)
- Risk label (Critical/Medium/Low)
- Count badges for each severity (from the SUMMARY TABLE in .md)

**Findings section:**
- Each finding as an accordion (click to expand)
- Bilingual (ESP + ENG) titles and descriptions
- Tags: CWE, OWASP, ISO references
- Code fix block
- False positive badge if applicable

**Recommendations section:**
- 5-7 prioritized items, each bilingual (ESP + ENG)
- Critical findings first, then high, then medium

**References table:**
- ALL 16 CWE rows with MITRE links
- Bilingual descriptions
- Framework badges (OWASP, ISO 27001, NIST, PCI DSS)

**Footer:**
- Ares Tool Security branding, domain, date
- AI agent signature (bilingual)
- "Auditable and traceable under OWASP, CWE and ISO 27001"
- © 2026

---

## ✅ My Validation Checklist

Before I consider the report done:

- [ ] ALL findings from ALL .md files are included (compare count against SUMMARY TABLE)
- [ ] False positives are marked with ⚠️ badge, not removed
- [ ] Score is REAL (calculated, not hardcoded)
- [ ] Every human explanation has: what + why it matters + analogy if applicable
- [ ] Every CWE has a correct MITRE link, not a broken URL
- [ ] Language toggle switches ALL text (no leftover in wrong language)
- [ ] ESP text is proper Spanish, ENG text is proper US English
- [ ] Recommendations are prioritized (critical first)
- [ ] References table has all 16 CWE rows minimum
- [ ] Technical references link to real MITRE pages

---

*Written by Alicia ✨ — This is my actual process. Follow it exactly.*
