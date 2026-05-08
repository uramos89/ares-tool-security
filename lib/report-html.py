#!/usr/bin/env python3
"""
Ares Tool Security — HTML Report Generator
Convierte reportes .md en HTML profesional con ESP/ENG, CWE mapping, y scoring.

Uso:
    python3 lib/report-html.py reports/web-audit-ejemplo-com-2026-05-08.md
    python3 lib/report-html.py reports/web-audit-ejemplo-com-2026-05-08.md -o informe.html
"""
import sys, os, re, json
from datetime import datetime
from pathlib import Path

# ═══ Severity Colors & Icons ═══
SEVERITY = {
    "critical": {"color": "#dc2626", "icon": "🔴", "label_es": "Crítico", "label_en": "Critical"},
    "high":     {"color": "#ea580c", "icon": "🟠", "label_es": "Alto",    "label_en": "High"},
    "medium":   {"color": "#d97706", "icon": "🟡", "label_es": "Medio",   "label_en": "Medium"},
    "low":      {"color": "#2563eb", "icon": "🔵", "label_es": "Bajo",    "label_en": "Low"},
    "ok":       {"color": "#16a34a", "icon": "✅", "label_es": "Aprobado","label_en": "Pass"},
}

# CWE mapping
CWE_MAP = {
    "Missing CSP header": ["CWE-1021", "CWE-79"],
    "Missing HSTS header": ["CWE-319"],
    "Missing X-Frame-Options": ["CWE-1021"],
    "Missing X-Content-Type-Options": ["CWE-345"],
    "Missing Referrer-Policy": ["CWE-200"],
    "Missing Permissions-Policy": ["CWE-200"],
    "CORS wildcard": ["CWE-942"],
    "CORS origin reflection": ["CWE-942"],
    "CORS wildcard": ["CWE-942"],
    "SQL Injection": ["CWE-89"],
    "Reflected XSS": ["CWE-79"],
    "Open redirect": ["CWE-601"],
    "Path exposed": ["CWE-200"],
    "Port exposed": ["CWE-200"],
    "Info leak": ["CWE-200"],
    "No rate limiting": ["CWE-307"],
    "No lockout": ["CWE-307"],
    "Missing CSRF": ["CWE-352"],
    "Cookie missing Secure": ["CWE-614"],
    "Cookie missing HttpOnly": ["CWE-1004"],
    "No WAF": ["CWE-693"],
    "Mixed content": ["CWE-948"],
    "SPF record missing": ["CWE-345"],
    "DMARC record missing": ["CWE-345"],
    "Server version disclosed": ["CWE-200"],
    "security.txt not found": ["CWE-200"],
    "SSL certificate expires": ["CWE-298"],
    "No SRI": ["CWE-345"],
    "Catch-all routing": ["CWE-200"],
    "Cache-Control allows caching": ["CWE-525"],
}

OWASP_MAP = {
    "CWE-79": "A3:2021",
    "CWE-89": "A3:2021",
    "CWE-200": "A1:2021",
    "CWE-307": "A7:2021",
    "CWE-319": "A2:2021",
    "CWE-345": "A4:2021",
    "CWE-352": "A1:2021",
    "CWE-601": "A1:2021",
    "CWE-614": "A4:2021",
    "CWE-942": "A1:2021",
    "CWE-1021": "A4:2021",
}

ISO_MAP = {
    "CWE-79": "A.8.25",
    "CWE-89": "A.8.25",
    "CWE-200": "A.8.11",
    "CWE-307": "A.8.5",
    "CWE-319": "A.8.20",
    "CWE-345": "A.8.24",
    "CWE-352": "A.8.5",
    "CWE-601": "A.8.11",
    "CWE-614": "A.8.20",
    "CWE-942": "A.8.20",
    "CWE-1021": "A.8.20",
    "CWE-298": "A.8.20",
    "CWE-525": "A.8.20",
    "CWE-1004": "A.8.20",
    "CWE-693": "A.8.21",
    "CWE-948": "A.8.20",
}


def parse_report(md_path: str) -> dict:
    """Parse an Ares .md report into structured data."""
    with open(md_path, "r", encoding="utf-8") as f:
        text = f.read()

    # Extract target and type
    target_match = re.search(r'Target:\s*`([^`]+)`', text)
    type_match = re.search(r'Type:\s*(\S+)', text)
    date_match = re.search(r'Date:\s*(.+)', text)
    score_match = re.search(r'Score:\s*(\d+)/100', text)

    target = target_match.group(1) if target_match else "Unknown"
    report_type = type_match.group(1) if type_match else "audit"
    date = date_match.group(1).strip() if date_match else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    score = int(score_match.group(1)) if score_match else 50

    # Extract findings
    findings = []
    finding_blocks = re.split(r'###\s+[🔴🟠🟡🔵✅]\s+\w+', text)[1:] if text else []
    
    # Find severity sections
    sev_sections = re.findall(r'###\s+([🔴🟠🟡🔵✅])\s+(\w+)(.*?)(?=###|\Z)', text, re.DOTALL)
    
    sev_map = {"🔴": "critical", "🟠": "high", "🟡": "medium", "🔵": "low", "✅": "ok"}
    
    for icon, sev_name, content in sev_sections:
        severity = sev_map.get(icon, "medium")
        # Find individual findings in this section
        items = re.findall(r'\*\*(\d+)\.\s*(.+?)\*\*.*?(?:\s+-\s+\*Detail:\*\s*(.*?))?(?:\s+-\s+\*Fix:\*\s*`(.*?)`)?', content, re.DOTALL)
        
        for _, title, detail, fix in items:
            title = title.strip()
            if title:
                findings.append({
                    "severity": severity,
                    "title": title,
                    "detail": detail.strip() if detail else "",
                    "fix": fix.strip() if fix else "",
                })

    if not findings:
        # Fallback: parse line by line
        lines = text.split("\n")
        current_sev = "medium"
        for line in lines:
            for icon, sev in sev_map.items():
                if line.strip().startswith(icon):
                    current_sev = sev
                    break
            
            m = re.match(r'\*\*(\d+)\.\s*(.+?)\*\*', line)
            if m:
                findings.append({"severity": current_sev, "title": m.group(2).strip(), "detail": "", "fix": ""})

    # Count severity
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "ok": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    # Detect WAF/CDN
    waf = "N/A"
    for f in findings:
        if "WAF" in f["title"] or "Cloudflare" in f["title"]:
            waf = f["title"].replace("WAF/CDN: ", "").replace("WAF/CDN detected: ", "")
            break

    # SSL status
    ssl_ok = any("SSL" in f["title"] and "valid" in f["title"].lower() for f in findings)

    return {
        "target": target,
        "type": report_type,
        "date": date,
        "score": score,
        "findings": findings,
        "counts": counts,
        "waf": waf,
        "ssl_ok": ssl_ok,
        "total": sum(counts.values()),
        "report_file": os.path.basename(md_path),
    }


def get_cwe_refs(title: str) -> list:
    """Get CWE references for a finding title."""
    for key, cwes in CWE_MAP.items():
        if key.lower() in title.lower():
            return cwes
    return []


def get_source_color(cwe: str) -> str:
    """Color tag for CWE/OWASP/ISO references."""
    if cwe.startswith("CWE"):
        if cwe in ["CWE-79", "CWE-89", "CWE-352", "CWE-601"]:
            return "red"
        return "orange"
    elif cwe.startswith("OWASP"):
        return "orange"
    elif cwe.startswith("A."):
        return "blue"
    return "blue"


def generate_html(data: dict) -> str:
    """Generate HTML report from parsed data."""
    t = data
    
    # Determine risk level
    if t["score"] >= 80:
        risk_es, risk_en, risk_color = "✅ RIESGO BAJO", "✅ LOW RISK", "16a34a"
    elif t["score"] >= 50:
        risk_es, risk_en, risk_color = "⚠️ RIESGO MEDIO", "⚠️ MEDIUM RISK", "d97706"
    else:
        risk_es, risk_en, risk_color = "🔴 RIESGO ALTO", "🔴 HIGH RISK", "dc2626"
    
    score_class = "score-critical" if t["score"] < 50 else ("score-warning" if t["score"] < 80 else "score-good")
    score_border = f"border-color: #{risk_color}; color: #{risk_color}"
    
    findings_html = ""
    for i, f in enumerate(t["findings"]):
        sev = SEVERITY.get(f["severity"], SEVERITY["medium"])
        sev_class = f"finding-{f['severity']}"
        cwes = get_cwe_refs(f["title"])
        
        cwe_html = ""
        if cwes:
            tags = []
            for cwe in cwes:
                owasp = OWASP_MAP.get(cwe, "")
                iso = ISO_MAP.get(cwe, "")
                color = get_source_color(cwe)
                ctag = f'<span class="cwe-tag cwe-tag-{color}">{cwe}</span>'
                tags.append(ctag)
                if owasp:
                    tags.append(f'<span class="cwe-tag cwe-tag-orange">OWASP {owasp}</span>')
                if iso:
                    tags.append(f'<span class="cwe-tag cwe-tag-blue">ISO {iso}</span>')
            cwe_html = f'<div class="cwe-ref">{"".join(tags)}</div>'
        
        fix_html = ""
        if f["fix"]:
            fix_html = f'<div style="margin-top:6px;font-size:0.85em;color:#facc15;"><span class="lang-es">Fix:</span><span class="lang-en lang-hidden">Fix:</span> <code style="background:#0f172a;padding:2px 6px;border-radius:4px;">{f["fix"][:80]}</code></div>'
        
        findings_html += f'''
        <div class="finding {sev_class}">
            <div class="icon">{sev['icon']}</div>
            <div class="content">
                <div class="title">{f['title']}</div>
                <div class="detail">{f['detail'][:200]}</div>
                {cwe_html}
                {fix_html}
            </div>
        </div>'''
    
    # Stats boxes
    stats = ""
    for sev_key in ["critical", "high", "medium", "low", "ok"]:
        color = SEVERITY[sev_key]["color"]
        icon = SEVERITY[sev_key]["icon"]
        count = t["counts"].get(sev_key, 0)
        sev_label_es = SEVERITY[sev_key]["label_es"]
        sev_label_en = SEVERITY[sev_key]["label_en"]
        if count > 0:
            stats += f'''
            <div class="stat-box">
                <div class="value" style="color:{color}">{icon} {count}</div>
                <div class="label lang-es">{sev_label_es}</div>
                <div class="label lang-en lang-hidden">{sev_label_en}</div>
            </div>'''
    
    # Badges
    waf_badge = f'<span class="badge badge-blue">{t["waf"]}</span>' if t["waf"] != "N/A" else ""
    ssl_badge = '<span class="badge badge-green">SSL: ✅</span>' if t["ssl_ok"] else ""
    
    # Score color
    score_color = "#dc2626" if t["score"] < 50 else ("#d97706" if t["score"] < 80 else "#16a34a")
    
    html = f'''<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ares Tool Security — Audit Report / Reporte de Auditoría</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f172a; color: #e2e8f0; padding: 20px;
}}
.container {{ max-width: 960px; margin: 0 auto; width: 100%; }}
.lang-toggle {{ position: sticky; top: 10px; z-index: 100; text-align: right; margin-bottom: 10px; }}
.lang-btn {{ background: #1e293b; border: 1px solid #475569; color: #94a3b8; padding: 8px 20px; border-radius: 8px; cursor: pointer; font-size: 0.85em; font-weight: 600; transition: all 0.2s; }}
.lang-btn:hover {{ background: #334155; color: #f1f5f9; }}
.lang-btn.active {{ background: #2563eb; border-color: #2563eb; color: white; }}
.lang-btn:first-child {{ border-radius: 8px 0 0 8px; }}
.lang-btn:last-child {{ border-radius: 0 8px 8px 0; border-left: none; }}
.lang-es, .lang-en {{ transition: opacity 0.3s; }}
.lang-hidden {{ display: none !important; }}
.header {{ text-align: center; padding: 30px 10px; border-bottom: 2px solid #1e293b; margin-bottom: 30px; }}
.header h1 {{ font-size: clamp(1.5em, 4vw, 2.5em); background: linear-gradient(135deg, #f59e0b, #ef4444); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px; }}
.header .subtitle {{ color: #94a3b8; font-size: clamp(0.9em, 2vw, 1.1em); }}
.badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: clamp(0.7em, 1.5vw, 0.85em); font-weight: 600; margin: 4px; }}
.badge-red {{ background: #dc2626; color: white; }}
.badge-yellow {{ background: #d97706; color: white; }}
.badge-green {{ background: #16a34a; color: white; }}
.badge-blue {{ background: #2563eb; color: white; }}
.badge-gray {{ background: #475569; color: white; }}
.card {{ background: #1e293b; border-radius: 16px; padding: clamp(16px, 3vw, 24px); margin-bottom: 20px; border: 1px solid #334155; }}
.card h2 {{ font-size: clamp(1.1em, 2.5vw, 1.3em); margin-bottom: 14px; padding-bottom: 10px; border-bottom: 1px solid #334155; }}
.score-circle {{ width: clamp(80px, 15vw, 120px); height: clamp(80px, 15vw, 120px); border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-direction: column; margin: 0 auto 16px; font-size: clamp(1.8em, 5vw, 2.5em); font-weight: 700; border: 6px solid #{score_color}; color: #{score_color}; }}
.score-circle .label {{ font-size: 0.3em; font-weight: 400; margin-top: 2px; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 16px 0; }}
.stat-box {{ background: #0f172a; border-radius: 12px; padding: clamp(12px, 2vw, 16px); text-align: center; }}
.stat-box .value {{ font-size: clamp(1.3em, 3vw, 2em); font-weight: 700; }}
.stat-box .label {{ font-size: clamp(0.7em, 1.5vw, 0.85em); color: #94a3b8; margin-top: 4px; }}
.finding {{ padding: clamp(10px, 2vw, 14px); margin-bottom: 8px; border-radius: 10px; display: flex; align-items: flex-start; gap: 10px; }}
.finding-critical {{ background: rgba(220,38,38,0.15); border-left: 4px solid #dc2626; }}
.finding-high {{ background: rgba(234,88,12,0.15); border-left: 4px solid #ea580c; }}
.finding-medium {{ background: rgba(217,119,6,0.15); border-left: 4px solid #d97706; }}
.finding-low {{ background: rgba(37,99,235,0.15); border-left: 4px solid #2563eb; }}
.finding-pass {{ background: rgba(22,163,74,0.15); border-left: 4px solid #16a34a; }}
.finding .icon {{ font-size: clamp(1em, 2vw, 1.3em); width: 20px; flex-shrink: 0; }}
.finding .content {{ flex: 1; min-width: 0; }}
.finding .content .title {{ font-weight: 600; font-size: clamp(0.9em, 2vw, 1em); }}
.finding .content .detail {{ font-size: clamp(0.8em, 1.5vw, 0.88em); color: #94a3b8; margin-top: 2px; }}
.finding .cwe-ref {{ font-size: clamp(0.75em, 1.5vw, 0.85em); color: #facc15; margin-top: 6px; display: flex; flex-wrap: wrap; gap: 6px; }}
.cwe-tag {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.78em; font-weight: 500; }}
.cwe-tag-red {{ background: rgba(220,38,38,0.3); color: #fca5a5; }}
.cwe-tag-orange {{ background: rgba(234,88,12,0.3); color: #fdba74; }}
.cwe-tag-blue {{ background: rgba(37,99,235,0.3); color: #93c5fd; }}
.cwe-tag-green {{ background: rgba(22,163,74,0.3); color: #86efac; }}
ol {{ margin-left: clamp(16px, 3vw, 20px); color: #cbd5e1; line-height: 1.8; }}
ol li {{ margin-bottom: 8px; font-size: clamp(0.85em, 1.8vw, 0.95em); }}
.ref-table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: clamp(0.75em, 1.5vw, 0.88em); }}
.ref-table th {{ text-align: left; padding: 8px 10px; background: #0f172a; color: #94a3b8; font-weight: 600; }}
.ref-table td {{ padding: 8px 10px; border-top: 1px solid #334155; color: #cbd5e1; vertical-align: top; }}
.ref-table a {{ color: #60a5fa; text-decoration: none; }}
.footer {{ text-align: center; padding: 24px 10px; color: #64748b; font-size: clamp(0.75em, 1.5vw, 0.9em); border-top: 1px solid #1e293b; margin-top: 30px; }}
.footer .sig {{ margin-top: 12px; font-size: 0.85em; color: #475569; line-height: 1.6; }}
@media (max-width: 480px) {{ body {{ padding: 10px; }} .stats-grid {{ grid-template-columns: repeat(2, 1fr); gap: 8px; }} }}
</style>
</head>
<body>
<div class="container">

<div class="lang-toggle">
<button class="lang-btn active" onclick="switchLang('es')" id="btn-es">🇪🇸 Español</button>
<button class="lang-btn" onclick="switchLang('en')" id="btn-en">🇬🇧 English</button>
</div>

<div class="header">
<h1>⚔️ Ares Tool Security</h1>
<div class="subtitle lang-es">Auditoría de Seguridad Web — Reporte Técnico</div>
<div class="subtitle lang-en lang-hidden">Web Security Audit — Technical Report</div>
<div style="margin-top: 12px;">
<span class="badge badge-red">Score: {t["score"]}/100</span>
{waf_badge}
{ssl_badge}
<span class="badge badge-gray">ISO 27001:2022</span>
</div>
</div>

<div class="card">
<h2>🎯 <span class="lang-es">Información del Objetivo</span><span class="lang-en lang-hidden">Target Information</span></h2>
<div class="stats-grid">
<div class="stat-box">
<div class="value" style="color:#f59e0b;font-size:1em;word-break:break-all;">{t["target"]}</div>
<div class="label lang-es">Dominio</div>
<div class="label lang-en lang-hidden">Domain</div>
</div>
<div class="stat-box">
<div class="value" style="color:#3b82f6;">{t["type"]}</div>
<div class="label lang-es">Tipo</div>
<div class="label lang-en lang-hidden">Type</div>
</div>
<div class="stat-box">
<div class="value" style="color:#94a3b8;font-size:0.85em;">{t["date"]}</div>
<div class="label lang-es">Fecha</div>
<div class="label lang-en lang-hidden">Date</div>
</div>
<div class="stat-box">
<div class="value" style="color:#94a3b8;font-size:1em;">{t["report_file"][:30]}</div>
<div class="label lang-es">Reporte</div>
<div class="label lang-en lang-hidden">Report</div>
</div>
</div>
</div>

<div class="card">
<h2>📊 <span class="lang-es">Resumen de Seguridad</span><span class="lang-en lang-hidden">Security Summary</span></h2>
<div class="score-circle">{t["score"]}<span class="label">/ 100</span></div>
<p style="text-align:center;color:#{risk_color};font-weight:600;" class="lang-es">{risk_es}</p>
<p style="text-align:center;color:#{risk_color};font-weight:600;" class="lang-en lang-hidden">{risk_en}</p>
<div class="stats-grid">{stats}</div>
</div>

<div class="card">
<h2>🔍 <span class="lang-es">Hallazgos Detallados</span><span class="lang-en lang-hidden">Detailed Findings</span></h2>
{findings_html if findings_html else '<p class="lang-es">No se encontraron hallazgos en el reporte.</p><p class="lang-en lang-hidden">No findings in this report.</p>'}
</div>

<div class="card" style="border-color: #f59e0b;">
<h2>📋 <span class="lang-es">Recomendaciones</span><span class="lang-en lang-hidden">Recommendations</span></h2>
<ol>
{chr(10).join([f'<li class="lang-es"><strong>Prioridad {i+1}</strong> — Revisar hallazgo: {f["title"][:60]}</li><li class="lang-en lang-hidden"><strong>Priority {i+1}</strong> — Review: {f["title"][:60]}</li>' for i, f in enumerate(t["findings"][:6]) if f["severity"] in ("critical", "high")])}
</ol>
</div>

<div class="card">
<h2>📚 <span class="lang-es">Referencias Técnicas</span><span class="lang-en lang-hidden">Technical References</span></h2>
<p style="color:#94a3b8;margin-bottom:12px;font-size:0.9em;">
<span class="lang-es">Cada hallazgo mapeado a CWE, OWASP e ISO para trazabilidad en auditorías formales.</span>
<span class="lang-en lang-hidden">Each finding mapped to CWE, OWASP and ISO standards for audit traceability.</span>
</p>
<table class="ref-table">
<thead>
<tr><th width="80">Código</th><th><span class="lang-es">Descripción</span><span class="lang-en lang-hidden">Description</span></th><th width="120">Fuente<br>Source</th></tr>
</thead>
<tbody>
<tr><td><span class="cwe-tag cwe-tag-red">CWE-79</span></td><td class="lang-es">Cross-Site Scripting (XSS)</td><td class="lang-en lang-hidden">Cross-Site Scripting (XSS)</td><td><a href="https://cwe.mitre.org/data/definitions/79.html" target="_blank">MITRE</a></td></tr>
<tr><td><span class="cwe-tag cwe-tag-red">CWE-89</span></td><td class="lang-es">Inyección SQL</td><td class="lang-en lang-hidden">SQL Injection</td><td><a href="https://cwe.mitre.org/data/definitions/89.html" target="_blank">MITRE</a></td></tr>
<tr><td><span class="cwe-tag cwe-tag-red">CWE-200</span></td><td class="lang-es">Exposición de información sensible</td><td class="lang-en lang-hidden">Information Exposure</td><td><a href="https://cwe.mitre.org/data/definitions/200.html" target="_blank">MITRE</a></td></tr>
<tr><td><span class="cwe-tag cwe-tag-red">CWE-319</span></td><td class="lang-es">Transmisión en texto claro</td><td class="lang-en lang-hidden">Cleartext Transmission</td><td><a href="https://cwe.mitre.org/data/definitions/319.html" target="_blank">MITRE</a></td></tr>
<tr><td><span class="cwe-tag cwe-tag-red">CWE-352</span></td><td class="lang-es">Cross-Site Request Forgery</td><td class="lang-en lang-hidden">Cross-Site Request Forgery</td><td><a href="https://cwe.mitre.org/data/definitions/352.html" target="_blank">MITRE</a></td></tr>
<tr><td><span class="cwe-tag cwe-tag-red">CWE-601</span></td><td class="lang-es">Open Redirect</td><td class="lang-en lang-hidden">Open Redirect</td><td><a href="https://cwe.mitre.org/data/definitions/601.html" target="_blank">MITRE</a></td></tr>
<tr><td><span class="cwe-tag cwe-tag-red">CWE-1021</span></td><td class="lang-es">Clickjacking / UI Redress</td><td class="lang-en lang-hidden">Clickjacking / UI Redress</td><td><a href="https://cwe.mitre.org/data/definitions/1021.html" target="_blank">MITRE</a></td></tr>
</tbody>
</table>
<div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:6px;">
<span class="cwe-tag cwe-tag-orange">OWASP Top 10:2021</span>
<span class="cwe-tag cwe-tag-blue">ISO 27001:2022</span>
<span class="cwe-tag cwe-tag-blue">NIST SP 800-53</span>
<span class="cwe-tag cwe-tag-blue">PCI DSS v4.0</span>
</div>
</div>

<div class="footer">
<p>⚔️ <strong>Ares Tool Security</strong></p>
<p>{t["target"]} — {t["date"]}</p>
<div class="sig">
—<br>
<span class="lang-es">Enviado por Alicia ✨ — Agente de IA Autónoma</span>
<span class="lang-en lang-hidden">Sent by Alicia ✨ — Autonomous AI Agent</span><br>
Ares Tool Security — Suite de Auditoría de Seguridad<br>
<span class="lang-es">Este informe es auditable, verificable y trazable bajo OWASP, CWE e ISO 27001</span>
<span class="lang-en lang-hidden">This report is auditable, verifiable and traceable under OWASP, CWE and ISO 27001</span><br>
© 2026
</div>
</div>

</div>
<script>
function switchLang(lang) {{
document.querySelectorAll('.lang-es').forEach(el => el.classList.toggle('lang-hidden', lang !== 'es'));
document.querySelectorAll('.lang-en').forEach(el => el.classList.toggle('lang-hidden', lang !== 'en'));
document.getElementById('btn-es').classList.toggle('active', lang === 'es');
document.getElementById('btn-en').classList.toggle('active', lang === 'en');
document.documentElement.lang = lang;
}}
</script>
</body>
</html>'''
    return html


def main():
    if len(sys.argv) < 2:
        print("Ares Tool Security — HTML Report Generator")
        print()
        print("Uso:")
        print("  python3 lib/report-html.py <reporte.md>              -> reports/<nombre>.html")
        print("  python3 lib/report-html.py <reporte.md> -o salida.html")
        print()
        print("Ejemplo:")
        print("  python3 lib/report-html.py reports/web-audit-misitio-2026-05-08.md")
        print("  python3 lib/report-html.py reports/web-audit-misitio-2026-05-08.md -o informe-ejecutivo.html")
        return

    md_path = sys.argv[1]
    if not os.path.exists(md_path):
        print(f"Error: No se encuentra el archivo: {md_path}")
        sys.exit(1)

    # Check for output argument
    out_path = None
    if "-o" in sys.argv:
        idx = sys.argv.index("-o")
        if idx + 1 < len(sys.argv):
            out_path = sys.argv[idx + 1]

    if not out_path:
        base = os.path.splitext(md_path)[0]
        out_path = f"{base}.html"

    print(f"  Leyendo: {md_path}")
    data = parse_report(md_path)
    print(f"  Hallazgos: {len(data['findings'])} | Score: {data['score']}/100")

    html = generate_html(data)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"  HTML generado: {out_path}")
    print(f"  Abrir en navegador para ver el reporte profesional")


if __name__ == "__main__":
    main()
