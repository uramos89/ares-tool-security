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

Todos los reportes se generan en `reports/` como `.md` con scoring y severidades.

## 📂 Estructura

```
ares-tool-security/
├── audit.sh            ← Entry point interactivo (menú)
├── modules/            ← Módulos de auditoría
│   ├── web-audit.py    ← SSL, headers, stack, dir busting, forms, cookies, CORS
│   ├── brute-force.py  ← Rate limiting, lockout, DDoS resilience, 2FA
│   ├── ddos-audit.py   ← WAF/CDN, concurrent load, timeout
│   └── vuln-scan.py    ← CSRF, XSS, SQLi, CORS, open redirect, info leak
├── lib/                ← Librerías (reporter, emailer, colors)
├── tests/              ← Tests unitarios
├── reports/            ← Reportes generados (.md)
├── scrum/              ← Metodología ágil
└── docs/               ← Documentación
```

## 🤝 Contribuir

```bash
git clone https://github.com/uramos89/ares-tool-security.git
cd ares-tool-security
./audit.sh
```

---

*Hecho con ❤️ por uramos89 y Alicia ✨*
