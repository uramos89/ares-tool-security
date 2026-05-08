# ADR — Ares Tool Security

## ADR-001: Hybrid Bash + Python
**Status:** Accepted
**Decision:** Bash entry point (interactive UX), Python modules for auditing logic.
**Rationale:** Bash for lightweight menus and colors. Python for HTTP requests, SSL parsing, and complex logic.
**Consequence:** Bash calls `python3 modules/*.py` for heavy lifting.

## ADR-002: Markdown Reports
**Status:** Accepted
**Decision:** All reports generated as `.md` with structured format.
**Rationale:** Portable, git-versionable, renders on GitHub/GitLab, readable in terminal.
**Consequence:** Easy to share and track over time.

## ADR-003: Zero External Dependencies
**Status:** Accepted
**Decision:** Only `python3` + standard library. No `pip install` or external packages.
**Rationale:** Suite must run on any Linux without preparation.
**Exception:** `dnspython` for DNS checks (optional, graceful fallback).

## ADR-004: Non-Invasive Scanning
**Status:** Accepted
**Decision:** Ares Tool Security never modifies the target. It only reads, tests, and reports.
**Rationale:** Ethical auditing. The user decides whether to apply fixes.
