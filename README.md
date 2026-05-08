# 🔐 Ares Tool Security

> Suite interactiva de auditoría de seguridad para sistemas y aplicaciones web.
> CLI bash + Python. Sin dependencias. Reportes en Markdown.

[![CI](https://github.com/uramos89/ares-tool-security/actions/workflows/ci.yml/badge.svg)](https://github.com/uramos89/ares-tool-security/actions/workflows/ci.yml)

---

## 🚀 Quick Start

```bash
git clone https://github.com/uramos89/ares-tool-security.git
cd ares-tool-security
chmod +x audit.sh
./audit.sh
```

## 📋 Módulos

| # | Módulo | Descripción |
|---|--------|-------------|
| 1 | 🌐 Web Audit | SSL, security headers, stack fingerprint, directory busting, forms, cookies, CORS |
| 2 | 🔨 Brute Force | Rate limiting, account lockout, DDoS resilience, 2FA detection |
| 3 | 🛡️ DDoS Audit | WAF/CDN detection, concurrent load test (10 parallel), timeout analysis |
| 4 | 🎯 Vuln Scan | CSRF in forms, cookie security (Secure/HttpOnly/SameSite), CORS misconfig, open redirect, info disclosure |
| 5 | 📋 Full Scan | Todos los módulos en secuencia |

## ⚡ Ejemplos

```bash
# Auditoría completa interactiva
./audit.sh

# Módulos individuales
python3 modules/web-audit.py https://ejemplo.com
python3 modules/brute-force.py https://ejemplo.com
python3 modules/ddos-audit.py https://ejemplo.com
python3 modules/vuln-scan.py https://ejemplo.com

# Full scan
./audit.sh  # Opción 5
```

## 🧠 Catch-All Detection

Ares detecta automáticamente servidores con **catch-all routing** (que devuelven 200 en lugar de 404). Cuando se detecta, las rutas sensibles se marcan como **falsos positivos** y se omiten de los resultados críticos.

## 📊 Reportes

### Formato Markdown (.md)

Todos los reportes se generan en `reports/` como `.md` con scoring, severidades y recomendaciones.

### Formato HTML Profesional (vía IA)

Usa el archivo [`docs/FORGE_REPORT.md`](docs/FORGE_REPORT.md) como prompt universal para CUALQUIER modelo de IA (ChatGPT, Claude, Gemini, Copilot) y obtén un reporte HTML profesional con:

- 🎨 **Tema oscuro** con diseño responsive (desktop, tablet, móvil)
- 🌐 **Toggle ESP 🇪🇸 / ENG 🇬🇧** funcional — cambia el idioma sin recargar
- ✨ **Animaciones CSS** — fadeInUp, score circle pulse, hover en cards
- 📊 **Score circle animado** con color según nivel de riesgo
- 🔍 **Cada hallazgo** con tags CWE, OWASP e ISO 27001 mapeados automáticamente
- 📋 **Recomendaciones priorizadas** (críticos y altos primero)
- 📚 **Tabla de referencias técnicas** con links a MITRE
- ⚖️ **Footer legal auditable** — trazable bajo OWASP, CWE e ISO 27001
- 📱 **100% responsive** — clamp en fonts, grid auto-fit, media queries

#### Cómo generar el HTML

```bash
# 1. Auditar el sitio
python3 modules/web-audit.py https://ejemplo.com
python3 modules/vuln-scan.py https://ejemplo.com

# 2. Abrir ChatGPT/Claude/Gemini y pegar:
#    - El contenido de docs/FORGE_REPORT.md
#    - El contenido de ambos .md de reports/
#    - Pedir: "Genera el reporte HTML profesional"
#    → La IA devuelve el .html listo para abrir en el navegador
```

O usa el **generador nativo** (si prefieres no depender de una IA externa):

```bash
python3 lib/report-html.py reports/web-audit-*.md -o reporte.html
```

## 📂 Estructura

```
ares-tool-security/
├── audit.sh            ← Entry point interactivo (menú)
├── modules/            ← Módulos de auditoría
│   ├── web-audit.py    ← SSL, headers, stack, dir busting, forms, cookies, CORS
│   ├── brute-force.py  ← Rate limiting, lockout, DDoS resilience, 2FA
│   ├── ddos-audit.py   ← WAF/CDN, concurrent load, timeout
│   └── vuln-scan.py    ← CSRF, XSS, SQLi, CORS, open redirect, info leak
├── lib/                ← Librerías
│   ├── reporter.py     ← Generador de reportes .md con scoring
│   ├── report-html.py  ← Conversor .md → .html profesional
│   ├── emailer.py      ← Envío de reportes por correo SMTP
│   └── colors.sh       ← Colores para terminal
├── tests/              ← Tests unitarios
├── reports/            ← Reportes generados (.md / .html)
├── scrum/              ← Metodología ágil
└── docs/
    └── FORGE_REPORT.md ← Prompt universal para generar HTML vía IA
```

## 🤝 Contribuir

```bash
git clone https://github.com/uramos89/ares-tool-security.git
cd ares-tool-security
./audit.sh
```

---

*Hecho con ❤️ por uramos89 y Alicia ✨*
