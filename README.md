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

| # | Módulo | Comando |
|---|--------|---------|
| 1 | 🌐 Web Audit | `python3 modules/web-audit.py <url>` |
| 2 | 🔨 Brute Force | `python3 modules/brute-force.py <url>` |

## 📊 Reportes

Todos los reportes se generan en `reports/` como `.md` con scoring y severidades.

## 📂 Estructura

```
ares-tool-security/
├── audit.sh            ← Entry point interactivo
├── modules/            ← Módulos de auditoría
├── lib/                ← Librerías (reporter, emailer, colors)
├── tests/              ← Tests unitarios
├── reports/            ← Reportes generados
├── scrum/              ← Metodología ágil
└── docs/               ← Documentación
```

---

*Hecho con ❤️ por uramos89 y Alicia ✨*
