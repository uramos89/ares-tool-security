# 📋 Product Backlog — Ares Tool Security

> 🔐 Full Testing & Security Testing Suite
> PO: Ulises Ramos | Scrum Master: Alicia ✨
> Inicio: 2026-05-06

## Épicas

### EP-01: Fundación del Proyecto
| ID | Historia | Prioridad | Estimación |
|----|----------|-----------|------------|
| US-001 | Como usuario, quiero un CLI interactivo que me guíe en la auditoría de seguridad | 🔥 Crítica | 5 pts |
| US-002 | Como usuario, quiero reportes .md detallados con hallazgos y recomendaciones | 🔥 Crítica | 3 pts |
| US-003 | Como desarrollador, quiero estructura Scrum con backlog, sprints y ADRs | Alta | 3 pts |

### EP-02: Auditoría Web
| ID | Historia | Prioridad | Estimación |
|----|----------|-----------|------------|
| US-004 | Como usuario, quiero auditar URLs/IPs para validar identidad y seguridad | 🔥 Crítica | 8 pts |
| US-005 | Como usuario, quiero escanear security headers y SSL/TLS | 🔥 Crítica | 5 pts |
| US-006 | Como usuario, quiero fingerprinting del stack web (servidor, lenguaje, CMS) | Alta | 5 pts |

### EP-03: Pruebas de Fuerza Bruta (Éticas)
| ID | Historia | Prioridad | Estimación |
|----|----------|-----------|------------|
| US-007 | Como usuario, quiero probar rate limiting en endpoints de login y API | 🔥 Crítica | 8 pts |
| US-008 | Como usuario, quiero validar bloqueo de cuentas tras intentos fallidos | Alta | 5 pts |
| US-009 | Como usuario, quiero probar rate limiting en 2FA/MFA y password reset | Alta | 5 pts |

### EP-04: Auditoría de Sistema
| ID | Historia | Prioridad | Estimación |
|----|----------|-----------|------------|
| US-010 | Como usuario, quiero auditar configuración SSH, users, y permisos | Alta | 5 pts |
| US-011 | Como usuario, quiero escanear secrets y credenciales hardcodeadas | Alta | 5 pts |
| US-012 | Como usuario, quiero auditoría de Docker y contenedores | Media | 5 pts |

### EP-05: Infraestructura y SDLC
| ID | Historia | Prioridad | Estimación |
|----|----------|-----------|------------|
| US-013 | Como desarrollador, quiero CI/CD con tests automatizados | Alta | 3 pts |
| US-014 | Como desarrollador, quiero tests unitarios con cobertura ≥85% | Alta | 5 pts |
| US-015 | Como usuario, quiero documentación completa de uso y ejemplos | Alta | 3 pts |

## Sprints

| Sprint | Foco | Historias | Puntos |
|--------|------|-----------|--------|
| Sprint 0 | Setup + Scrum + Docs | US-001, US-003 | 8 pts |
| Sprint 1 | Web Audit Core | US-004, US-005 | 13 pts |
| Sprint 2 | Brute Force Testing | US-007, US-008, US-009 | 18 pts |
| Sprint 3 | System Audit | US-010, US-011, US-012 | 15 pts |
| Sprint 4 | CI/CD + Tests + Release | US-013, US-014, US-015 | 11 pts |

**Total:** 65 pts | **Velocidad estimada:** 15-20 pts/sprint | **Duración:** ~4 sprints (8 semanas)
