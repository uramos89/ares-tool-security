# Ares Tool Security Architecture

## C4 Level 1 — Context
```mermaid
graph TD
    User[Security Auditor] -->|CLI| Ares[Ares Tool Security Suite]
    Ares -->|HTTPS| Target[Target Web / System]
    Ares -->|File| Reports[Report .md Files]
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

## Module Execution Flow
```
audit.sh → Interactive menu
  ├── User selects module
  ├── User enters target
  ├── audit.sh runs python3 modules/<module>.py <target>
  │     ├── Scans/Tests the target
  │     ├── Reports findings in terminal
  │     └── Generates .md report in reports/
  └── Returns to main menu
```

## Report Generation Flow
```
Module (.py) → AuditReport class (lib/reporter.py) → .md file (reports/)
                                                           │
                    ┌──────────────────────────────────────┤
                    │                                      │
                    ▼                                      ▼
      lib/report-html.py (.md → .html)        docs/FORGE_REPORT.md
      (native converter)                       (AI prompt for HTML)
```
