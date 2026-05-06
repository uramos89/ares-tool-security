# ADR — Ares Tool Security

## ADR-001: Bash + Python Híbrido
**Estado:** Aceptada
**Decisión:** Entry point en Bash (UX interactiva), módulos de auditoría en Python.
**Por qué:** Bash para menús livianos y colores. Python para HTTP requests, parsing, SSL, y lógica compleja.
**Consecuencia:** Bash llama `python3 modules/*.py` cuando toca trabajo pesado.

## ADR-002: Reportes en Markdown
**Estado:** Aceptada
**Decisión:** Todos los reportes se generan en `.md` con formato estructurado.
**Por qué:** Portable, versionable en Git, renderizable en GitHub/GitLab, legible en terminal.
**Consecuencia:** Fácil de compartir y trackear en el tiempo.

## ADR-003: Sin Dependencias Externas
**Estado:** Aceptada
**Decisión:** Solo `python3` + bibliotecas estándar. Sin `pip install` ni paquetes externos.
**Por qué:** La suite debe funcionar en cualquier Linux sin preparación.
**Excepción:** Si el usuario quiere SSL avanzado o HTML parsing, se sugiere pero no es obligatorio.

## ADR-004: Escaneo No Invasivo
**Estado:** Aceptada
**Decisión:** Ares Tool Security nunca modifica el objetivo. Solo lee, prueba y reporta.
**Por qué:** Auditoría ética. El usuario decide si aplicar los fixes.
