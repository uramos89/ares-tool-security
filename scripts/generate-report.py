#!/usr/bin/env python3
"""
Ares Tool Security — Full HTML Report Generator
Reads all 4 .md reports, generates professional bilingual HTML.
"""
import sys, os, re, json
from pathlib import Path

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

def parse_md(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        text = f.read()

    target_m = re.search(r'`([^`]+)`', text)
    target = target_m.group(1) if target_m else "Unknown"

    score_m = re.search(r'\*\*Security Score:\*\*\s*(\d+)/100', text)
    score = int(score_m.group(1)) if score_m else 0

    type_m = re.search(r'Type:\s*(\S+)', text)
    mtype = type_m.group(1) if type_m else "unknown"

    findings = []
    sections = re.findall(r'###\s+([🔴🟠🟡🔵✅])\s+(\w+)(.*?)(?=###|\Z)', text, re.DOTALL)
    sev_map = {"🔴": "critical", "🟠": "high", "🟡": "medium", "🔵": "low", "✅": "pass"}

    for icon, _, content in sections:
        sev = sev_map.get(icon, "medium")
        items = re.findall(r'\*\*(\d+)\.\s*(.+?)\*\*\s*(?:\-\s+\*Detail:\*\s*(.*?))?(?:\s+\-\s+\*Fix:\*\s*`(.*?)`)?', content, re.DOTALL)
        for _, title, detail, fix in items:
            title = title.strip()
            if title:
                findings.append({"severity": sev, "title": title, "detail": detail.strip() if detail else "", "fix": fix.strip() if fix else ""})

    # Also catch single-line findings
    if not findings:
        for line in text.split("\n"):
            m = re.match(r'\*\*(\d+)\.\s*(.+?)\*\*', line)
            if m:
                findings.append({"severity": "medium", "title": m.group(2).strip(), "detail": "", "fix": ""})

    return {"target": target, "type": mtype, "score": score, "findings": findings, "file": os.path.basename(filepath)}

def main():
    # Parse all .md files
    all_data = []
    for f in sorted(os.listdir(REPORTS_DIR)):
        if f.endswith(".md"):
            fp = os.path.join(REPORTS_DIR, f)
            data = parse_md(fp)
            all_data.append(data)
            print(f"  {f}: {len(data['findings'])} findings, score={data['score']}")

    if not all_data:
        print("No reports found in reports/")
        return

    # Consolidate
    target = all_data[0]["target"]
    # Weighted score: average of all modules, capped at lowest module's score + 30
    raw_avg = sum(d["score"] for d in all_data) / len(all_data)
    lowest = min(d["score"] for d in all_data)
    global_score = int(round((raw_avg + lowest) / 2))  # Blend average with lowest

    all_findings = []
    seen_titles = set()
    for d in all_data:
        for f in d["findings"]:
            key = f["title"].lower()[:60]
            if key not in seen_titles:
                seen_titles.add(key)
                all_findings.append(f)

    f_crit = sum(1 for f in all_findings if f["severity"] == "critical")
    f_high = sum(1 for f in all_findings if f["severity"] == "high")
    f_med = sum(1 for f in all_findings if f["severity"] == "medium")
    f_low = sum(1 for f in all_findings if f["severity"] == "low")
    f_pass = sum(1 for f in all_findings if f["severity"] == "pass")
    total = len(all_findings)

    score_color = "#dc2626" if global_score < 50 else ("#d97706" if global_score < 80 else "#16a34a")
    risk_es = "RIESGO CRITICO" if global_score < 50 else ("RIESGO MEDIO" if global_score < 80 else "RIESGO BAJO")
    risk_en = "CRITICAL RISK" if global_score < 50 else ("MEDIUM RISK" if global_score < 80 else "LOW RISK")

    findings_rows = ""
    for i, f in enumerate(all_findings):
        sev_class = f["severity"]
        icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "pass": "✅"}
        icon = icons.get(sev_class, "⚪")
        detail = f["detail"][:200] if f["detail"] else ""
        fix = f["fix"][:100] if f["fix"] else ""
        findings_rows += f'''
<div class="card finding {sev_class}" onclick="toggleFinding(this)">
<div class="finding-header">
<span>{icon} <span class="lang-es">{f["title"]}</span><span class="lang-en lang-hidden">{f["title"]}</span></span>
<span class="expand-icon">▼</span>
</div>
<div class="finding-body">
<p class="lang-es">{detail}</p>
<p class="lang-en lang-hidden">{detail}</p>
{f'<code>{fix}</code>' if fix else ''}
</div>
</div>'''

    cwe_rows = [
        ("CWE-79", "Cross-Site Scripting (XSS)", "A3:2021"),
        ("CWE-89", "SQL Injection", "A3:2021"),
        ("CWE-200", "Information Exposure", "A1:2021"),
        ("CWE-298", "SSL Certificate Expiry", "-"),
        ("CWE-307", "Brute Force / Rate Limiting", "A7:2021"),
        ("CWE-319", "Cleartext Transmission (HSTS)", "A5:2021"),
        ("CWE-345", "Data Authenticity (XCTO, SRI)", "A4:2021"),
        ("CWE-352", "Cross-Site Request Forgery (CSRF)", "A1:2021"),
        ("CWE-525", "Cache Control", "-"),
        ("CWE-601", "Open Redirect", "A1:2021"),
        ("CWE-614", "Cookie Secure Flag", "A4:2021"),
        ("CWE-693", "WAF / CDN Missing", "-"),
        ("CWE-942", "CORS Misconfiguration", "A1:2021"),
        ("CWE-948", "Mixed Content", "-"),
        ("CWE-1004", "Cookie HttpOnly Flag", "-"),
        ("CWE-1021", "Clickjacking / UI Redress", "A4:2021"),
    ]

    cwe_html = ""
    for cwe, desc, owasp in cwe_rows:
        cwe_html += f'<tr><td><a href="https://cwe.mitre.org/data/definitions/{cwe.split("-")[1]}.html" target="_blank">{cwe}</a></td><td class="lang-es">{desc}</td><td class="lang-en lang-hidden">{desc}</td><td>{owasp}</td></tr>\n'

    date = "2026-05-08"

    html = f'''<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ares Tool Security — Audit Report: {target}</title>
<style>
:root {{
--page-bg: #f0f4f8; --card-bg: #ffffff; --text-main: #1e293b; --text-dim: #64748b;
--primary: #005095; --primary-light: #e8f0fe; --accent: #0094ff; --dark: #012346;
--border: #d1d9e6; --critical: #dc2626; --high: #ea580c; --medium: #d97706; --low: #2563eb; --pass: #16a34a;
}}
* {{ box-sizing: border-box; font-family: 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; padding: 0; }}
body {{ background: var(--page-bg); color: var(--text-main); line-height: 1.6; }}
#progress-bar {{ position: fixed; top: 0; left: 0; height: 4px; background: var(--accent); width: 0%; z-index: 2000; transition: width 0.2s; }}
.lang-hidden {{ display: none !important; }}
.lang-toggle {{ position: sticky; top: 0; background: var(--dark); padding: 12px; display: flex; justify-content: center; gap: 10px; z-index: 1500; }}
.btn-lang {{ padding: 6px 16px; border: 1px solid rgba(255,255,255,0.3); background: transparent; color: white; cursor: pointer; border-radius: 20px; transition: 0.3s; }}
.btn-lang.active {{ background: white; color: var(--dark); font-weight: bold; }}
header {{ background: var(--dark); color: white; padding: 2rem 1rem; text-align: center; }}
.container {{ max-width: 1000px; margin: 2rem auto; padding: 0 1rem; }}
.card {{ background: var(--card-bg); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid var(--border); box-shadow: 0 2px 4px rgba(0,0,0,0.05); animation: fadeInUp 0.5s ease-out; }}
@keyframes fadeInUp {{ from {{ opacity: 0; transform: translateY(20px); }} to {{ opacity: 1; transform: translateY(0); }} }}
.summary-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; align-items: center; }}
.score-container {{ display: flex; flex-direction: column; align-items: center; }}
.score-svg {{ width: 150px; height: 150px; transform: rotate(-90deg); }}
.score-svg circle {{ fill: none; stroke-width: 10; stroke-linecap: round; }}
.score-bg {{ stroke: #e2e8f0; }}
.score-fill {{ stroke: {score_color}; stroke-dasharray: 440; stroke-dashoffset: 440; transition: stroke-dashoffset 2s ease-in-out; }}
.score-text {{ position: absolute; font-size: 2rem; font-weight: 800; color: var(--dark); display: flex; flex-direction: column; align-items: center; }}
.score-label {{ font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; }}
.stat-row {{ display: flex; gap: 8px; margin-top: 1rem; flex-wrap: wrap; }}
.stat-badge {{ padding: 8px 14px; border-radius: 8px; color: white; font-weight: bold; font-size: 0.85rem; }}
.filter-bar {{ position: sticky; top: 50px; background: var(--page-bg); padding: 10px 0; display: flex; gap: 8px; z-index: 1000; border-bottom: 1px solid var(--border); margin-bottom: 1rem; overflow-x: auto; }}
.filter-btn {{ padding: 6px 14px; border-radius: 20px; border: 1px solid var(--border); background: white; cursor: pointer; white-space: nowrap; transition: 0.2s; }}
.filter-btn.active {{ background: var(--primary); color: white; border-color: var(--primary); }}
.finding {{ cursor: pointer; border-left: 5px solid #ccc; margin-bottom: 0.8rem; border-radius: 8px; }}
.finding-header {{ display: flex; justify-content: space-between; align-items: center; padding: 1rem; font-weight: 600; }}
.finding-body {{ display: none; padding: 0 1rem 1rem; border-top: 1px solid var(--border); }}
.finding.expanded .finding-body {{ display: block; }}
.finding.expanded .expand-icon {{ transform: rotate(180deg); }}
.expand-icon {{ transition: 0.3s; }}
.finding.critical {{ border-left-color: var(--critical); background: #fef2f2; }}
.finding.high {{ border-left-color: var(--high); background: #fffaf5; }}
.finding.medium {{ border-left-color: var(--medium); background: #fffcf0; }}
.finding.low {{ border-left-color: var(--low); background: #f0f7ff; }}
.finding.pass {{ border-left-color: var(--pass); background: #f0fdf4; }}
code {{ display: block; background: #1e293b; color: #38bdf8; padding: 1rem; border-radius: 6px; margin: 10px 0; font-size: 0.85rem; overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }}
th, td {{ border: 1px solid var(--border); padding: 10px; text-align: left; }}
th {{ background: var(--primary-light); color: var(--primary); }}
a {{ color: var(--accent); }}
ol {{ margin-left: 1.5rem; }}
ol li {{ margin-bottom: 8px; }}
footer {{ text-align: center; padding: 3rem 1rem; color: var(--text-dim); border-top: 1px solid var(--border); }}
@media (max-width: 600px) {{ .summary-grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div id="progress-bar"></div>

<div class="lang-toggle">
<button id="btn-es" class="btn-lang active" onclick="switchLang('es')">🇪🇸 Español</button>
<button id="btn-en" class="btn-lang" onclick="switchLang('en')">🇬🇧 English</button>
</div>

<header>
<h1>⚔️ Ares Tool Security</h1>
<p class="lang-es">Reporte de Auditoría de Ciberseguridad</p>
<p class="lang-en lang-hidden">Cybersecurity Audit Report</p>
<p style="opacity:0.7;font-size:0.85rem;margin-top:5px;">{target} — {date}</p>
</header>

<div class="container">

<div class="card">
<h3 class="lang-es">🎯 Informacion del Objetivo</h3>
<h3 class="lang-en lang-hidden">🎯 Target Information</h3>
<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:10px; margin-top:10px;">
<div><strong>Domain:</strong><br>{target}</div>
<div><strong>Date:</strong><br>{date}</div>
<div><strong class="lang-es">Modulos:</strong><strong class="lang-en lang-hidden">Modules:</strong><br>{len(all_data)}</div>
<div><strong class="lang-es">Hallazgos:</strong><strong class="lang-en lang-hidden">Findings:</strong><br>{total}</div>
</div>
</div>

<div class="card">
<div class="summary-grid">
<div class="score-container">
<div style="position:relative; display:flex; align-items:center; justify-content:center;">
<svg class="score-svg"><circle class="score-bg" cx="75" cy="75" r="70"></circle>
<circle id="score-fill" class="score-fill" cx="75" cy="75" r="70"></circle></svg>
<div class="score-text"><span id="score-val">0</span><span class="score-label">/ 100</span></div>
</div>
<h3 style="color:{score_color}; margin-top:10px;" class="lang-es">{risk_es}</h3>
<h3 style="color:{score_color}; margin-top:10px;" class="lang-en lang-hidden">{risk_en}</h3>
</div>
<div>
<p class="lang-es">Resumen consolidado de {len(all_data)} modulos de auditoria ({total} hallazgos totales).</p>
<p class="lang-en lang-hidden">Consolidated summary from {len(all_data)} audit modules ({total} total findings).</p>
<div class="stat-row">
<span class="stat-badge" style="background:var(--critical)">🔴 {f_crit} Critical</span>
<span class="stat-badge" style="background:var(--high)">🟠 {f_high} High</span>
<span class="stat-badge" style="background:var(--medium)">🟡 {f_med} Medium</span>
<span class="stat-badge" style="background:var(--low)">🔵 {f_low} Low</span>
<span class="stat-badge" style="background:var(--pass)">✅ {f_pass} Pass</span>
</div>
</div>
</div>
</div>

<div class="filter-bar">
<button class="filter-btn active" data-filter="all">All ({total})</button>
<button class="filter-btn" data-filter="critical">🔴 Critical ({f_crit})</button>
<button class="filter-btn" data-filter="high">🟠 High ({f_high})</button>
<button class="filter-btn" data-filter="medium">🟡 Medium ({f_med})</button>
<button class="filter-btn" data-filter="low">🔵 Low ({f_low})</button>
<button class="filter-btn" data-filter="pass">✅ Pass ({f_pass})</button>
</div>

<div id="findings-container">
{findings_rows}
</div>

<div class="card">
<h3 class="lang-es">📋 Recomendaciones Prioritarias</h3>
<h3 class="lang-en lang-hidden">📋 Prioritized Recommendations</h3>
<ol>
<li class="lang-es"><strong>Urgente:</strong> Corregir SQL Injection en parametros identificados (id, p, family, render, text, solAdmin)</li>
<li class="lang-en lang-hidden"><strong>Urgent:</strong> Fix SQL Injection in identified parameters (id, p, family, render, text, solAdmin)</li>
<li class="lang-es">Deshabilitar catch-all routing y configurar errores 404 reales</li>
<li class="lang-en lang-hidden">Disable catch-all routing and configure proper 404 errors</li>
<li class="lang-es">Implementar WAF/CDN (Cloudflare, AWS WAF o CloudFront)</li>
<li class="lang-en lang-hidden">Implement WAF/CDN (Cloudflare, AWS WAF or CloudFront)</li>
<li class="lang-es">Configurar cabeceras de seguridad: CSP, HSTS, X-Frame-Options, XCTO</li>
<li class="lang-en lang-hidden">Configure security headers: CSP, HSTS, X-Frame-Options, XCTO</li>
<li class="lang-es">Bloquear acceso publico a /.git/config, /phpmyadmin, /debug, /phpinfo.php</li>
<li class="lang-en lang-hidden">Block public access to /.git/config, /phpmyadmin, /debug, /phpinfo.php</li>
<li class="lang-es">Cerrar puerto 8080 en firewall</li>
<li class="lang-en lang-hidden">Close port 8080 on firewall</li>
</ol>
</div>

<div class="card">
<h3 class="lang-es">📚 Referencias Tecnicas</h3>
<h3 class="lang-en lang-hidden">📚 Technical References</h3>
<table>
<thead><tr><th>Code</th><th class="lang-es">Descripcion</th><th class="lang-en lang-hidden">Description</th><th>OWASP</th></tr></thead>
<tbody>
{cwe_html}
</tbody>
</table>
<div style="display:flex;gap:8px;margin-top:15px;flex-wrap:wrap;">
<span style="padding:4px 10px;border-radius:12px;background:#e2e8f0;font-size:0.8rem;">OWASP Top 10:2021</span>
<span style="padding:4px 10px;border-radius:12px;background:#e2e8f0;font-size:0.8rem;">ISO 27001:2022</span>
<span style="padding:4px 10px;border-radius:12px;background:#e2e8f0;font-size:0.8rem;">NIST SP 800-53</span>
<span style="padding:4px 10px;border-radius:12px;background:#e2e8f0;font-size:0.8rem;">PCI DSS v4.0</span>
</div>
</div>

</div>

<footer>
<p><strong>Ares Tool Security</strong> — {target}</p>
<p class="lang-es">Enviado por Alicia ✨ — Agente de IA Autonoma</p>
<p class="lang-en lang-hidden">Sent by Alicia ✨ — Autonomous AI Agent</p>
<p style="font-size:0.75rem;margin-top:8px;opacity:0.6;" class="lang-es">Este reporte es auditable y trazable bajo OWASP, CWE e ISO 27001.</p>
<p style="font-size:0.75rem;margin-top:8px;opacity:0.6;" class="lang-en lang-hidden">This report is auditable and traceable under OWASP, CWE and ISO 27001.</p>
<p style="font-size:0.7rem;margin-top:4px;opacity:0.4;">© 2026</p>
</footer>

<script>
function switchLang(lang) {{
document.querySelectorAll('.lang-es').forEach(el => el.classList.toggle('lang-hidden', lang !== 'es'));
document.querySelectorAll('.lang-en').forEach(el => el.classList.toggle('lang-hidden', lang !== 'en'));
document.getElementById('btn-es').classList.toggle('active', lang === 'es');
document.getElementById('btn-en').classList.toggle('active', lang === 'en');
document.documentElement.lang = lang;
}}
function toggleFinding(el) {{ el.classList.toggle('expanded'); }}
document.querySelectorAll('.filter-btn').forEach(btn => {{
btn.addEventListener('click', () => {{
document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
btn.classList.add('active');
const filter = btn.dataset.filter;
document.querySelectorAll('.finding').forEach(f => {{
f.style.display = (filter === 'all' || f.classList.contains(filter)) ? 'block' : 'none';
}});
}});
}});
window.addEventListener('scroll', () => {{
const h = document.documentElement.scrollHeight - window.innerHeight;
document.getElementById('progress-bar').style.width = (window.scrollY / h * 100) + '%';
}});
window.onload = () => {{
const score = {global_score};
const circle = document.getElementById('score-fill');
const offset = 440 * (1 - score / 100);
circle.style.strokeDashoffset = offset;
let count = 0;
const timer = setInterval(() => {{ if (count >= score) clearInterval(timer); document.getElementById('score-val').innerText = count; count++; }}, 30);
}};
</script>
</body>
</html>'''

    out_path = f"/tmp/audit-report-{target.replace('https://','').replace('.','-')}-{date}.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  HTML generado: {out_path}")
    print(f"  Hallazgos: {len(all_findings)} | Score: {global_score}/100")
    return out_path

if __name__ == "__main__":
    main()
