# FullTestSec Architecture

## C4 Level 1 — Context
```mermaid
graph TD
    User[Security Auditor] -->|CLI| FTS[FullTestSec Suite]
    FTS -->|HTTPS| Target[Target Web/Sistema]
    FTS -->|File| Reports[Reportes .md]
```

## C4 Level 2 — Containers
```mermaid
graph TD
    subgraph "FullTestSec"
        CLI[audit.sh]
        Web[Web Audit<br/>web-audit.py]
        BF[Brute Force<br/>brute-force.py]
        Reporter[Reporter<br/>reporter.py]
    end
    CLI --> Web
    CLI --> BF
    Web --> Reporter
    BF --> Reporter
    Web -->|HTTPS| Target
    BF -->|HTTPS| Target
```

## Flujo de un Módulo
```
audit.sh → Menú interactivo
  ├── Usuario selecciona módulo
  ├── Usuario ingresa target
  ├── audit.sh ejecuta python3 modules/<module>.py <target>
  │     ├── Escanea/Prueba el target
  │     ├── Reporta findings en terminal
  │     └── Genera reporte .md en reports/
  └── Vuelve al menú principal
```
