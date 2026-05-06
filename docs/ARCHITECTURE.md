# Ares Tool Security Architecture

## C4 Level 1 — Context
```mermaid
graph TD
    User[Security Auditor] -->|CLI| Ares[Ares Tool Security Suite]
    Ares -->|HTTPS| Target[Target Web/Sistema]
    Ares -->|File| Reports[Reportes .md]
```

## C4 Level 2 — Containers
```mermaid
graph TD
    subgraph "Ares Tool Security"
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
