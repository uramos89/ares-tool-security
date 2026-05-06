# 🔐 FullTestSec — Full Testing & Security Testing Suite

> Suite interactiva de auditoría de seguridad para sistemas y aplicaciones web.
> CLI bash + Python. Sin dependencias. Reportes en Markdown.

[![CI](https://github.com/uramos89/fulltestsec/actions/workflows/ci.yml/badge.svg)](https://github.com/uramos89/fulltestsec/actions/workflows/ci.yml)

---

## 🚀 Quick Start

```bash
# Clonar
git clone https://github.com/uramos89/fulltestsec.git
cd fulltestsec

# Dar permisos
chmod +x audit.sh

# Ejecutar (interactivo)
./audit.sh

# O modo directo:
./audit.sh --web https://tusitio.com
./audit.sh --brute https://tusitio.com/api/login
```

## 📋 Módulos

| # | Módulo | Comando | ¿Qué audita? |
|---|--------|---------|-------------|
| 1 | 🌐 Web Audit | `python3 modules/web-audit.py <url>` | SSL, security headers, stack fingerprint, puertos |
| 2 | 🔨 Brute Force | `python3 modules/brute-force.py <url>` | Rate limiting, lockout, 2FA |
| 3 | 🖥️ System | Próximamente | SSH, users, permisos |
| 4 | 🐳 Docker | Próximamente | Contenedores, imágenes |

## 📊 Reportes

Todos los reportes se generan en `reports/` como archivos `.md`:

```markdown
# 🔐 FullTestSec Audit Report

**Target:** `https://ejemplo.com`
**Score:** 72/100 ⚠️

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 7 |
```

## 📂 Estructura

```
fulltestsec/
├── audit.sh              ← Entry point interactivo
├── modules/              ← Módulos de auditoría (.py)
│   ├── web-audit.py      SSL, headers, stack, ports
│   └── brute-force.py    Rate limiting, lockout, 2FA
├── lib/                  ← Librerías compartidas
│   ├── colors.sh         UI con colores
│   └── reporter.py       Generador de reportes .md
├── tests/                ← Tests unitarios
├── reports/              ← Reportes generados
├── scrum/                ← Metodología ágil
│   ├── BACKLOG.md        Backlog de producto
│   ├── SPRINT_0.md       Sprint actual
│   └── ADR.md            Decisiones arquitectónicas
└── docs/                 ← Documentación
```

## 🧪 Tests

```bash
python3 tests/test_all.py
```

## 📝 Licencia

MIT — Ver [LICENSE](LICENSE)

---

*Hecho con ❤️ por uramos89 y Alicia ✨*
