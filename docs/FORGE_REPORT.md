# ⚔️ Ares Forge Report — Universal Prompt for HTML Report Generation

> **Purpose:** This file contains instructions for any AI model (Claude, ChatGPT, Gemini, Copilot, etc.) to generate a **professional HTML report** from the `.md` files produced by **Ares Tool Security**.
>
> **Usage:** Provide the AI with the 2 audit `.md` files + this file's content as instructions.

---

## 🎯 Objective

Generate a `audit-report.html` file with:

- **Professional dark theme** (slate/dark blue: `#0f172a`, cards: `#1e293b`, borders: `#334155`)
- **Language toggle** ESP 🇪🇸 / ENG 🇬🇧 functional (switches all content without reload)
- **CSS animations** (fade in, slide up, score circle pulse, card hover)
- **Animated score circle** with circular fill effect (CSS radial-gradient or SVG circle with animated stroke-dashoffset)
- **Responsive design** (clamp fonts, auto-fit grid, mobile media queries)
- **Severity badges** with distinctive colors
- **CWE + OWASP + ISO 27001** references per finding
- **Technical references table** with MITRE links
- **Prioritized recommendations**
- **Auditable legal footer**

---

## 📥 Input

You will receive **2 Markdown files**:

1. `web-audit-<dominio>-<fecha>.md` — Auditoría web completa (20 checks)
2. `vuln-scan-<dominio>-<fecha>.md` — Escaneo de vulnerabilidades

Ambos siguen el formato estándar de Ares Tool Security (encabezados con `# `, hallazgos con `**N. Título**`, severidad con emojis 🔴🟠🟡🔵✅, y secciones `### 🔴 CRITICAL`, `### 🟠 HIGH`, etc.).

---

## 📋 Especificaciones Técnicas del HTML

### Estructura del Documento

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ares Tool Security — Audit Report / Reporte de Auditoría</title>
  <style>/* ... */</style>
</head>
<body>
  <!-- Language Toggle -->
  <!-- Header -->
  <!-- Target Info Card -->
  <!-- Summary Card (Score + Counts) -->
  <!-- Findings Cards -->
  <!-- Recommendations -->
  <!-- Technical References -->
  <!-- Footer -->
  <script>/* language toggle */</script>
</body>
</html>
```

### Estilos Requeridos

```css
/* Paleta */
body    { background: #0f172a; color: #e2e8f0; }
.card   { background: #1e293b; border: 1px solid #334155; }
.stat-box { background: #0f172a; }

/* Score Circle */
.score-circle {
  border: 6px solid;
  border-radius: 50%;
  width: clamp(80px, 15vw, 120px);
  height: clamp(80px, 15vw, 120px);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  font-size: clamp(1.8em, 5vw, 2.5em);
  font-weight: 700;
}
/* Color según score: <50: #dc2626, 50-79: #d97706, >=80: #16a34a */

/* Severidad colores */
.critical: #dc2626 | .high: #ea580c | .medium: #d97706
.low: #2563eb | .pass: #16a34a

/* Finding cards border-left + background con opacidad */
.finding-{severidad} {
  border-left: 4px solid <color>;
  background: rgba(<color_rgb>, 0.15);
}
```

### Animaciones CSS

```css
/* Fade in de cards */
@keyframes fadeInUp {
  from { opacity: 0; transform: translateY(20px); }
  to   { opacity: 1; transform: translateY(0); }
}
.card { animation: fadeInUp 0.5s ease-out; }
.card:nth-child(n) { animation-delay: 0.1s * n; }

/* Score circle pulse */
@keyframes pulse {
  0% { transform: scale(1); }
  50% { transform: scale(1.05); }
  100% { transform: scale(1); }
}

/* Hover en cards */
.card:hover { transform: translateY(-2px); box-shadow: 0 8px 12px rgba(0,0,0,0.4); }
```

### Language Toggle (JavaScript)

```javascript
function switchLang(lang) {
  document.querySelectorAll('.lang-es').forEach(el => el.classList.toggle('lang-hidden', lang !== 'es'));
  document.querySelectorAll('.lang-en').forEach(el => el.classList.toggle('lang-hidden', lang !== 'en'));
  document.getElementById('btn-es').classList.toggle('active', lang === 'es');
  document.getElementById('btn-en').classList.toggle('active', lang === 'en');
  document.documentElement.lang = lang;
}
```

### Score Circle con SVG Animado (Opcional)

Para un efecto más profesional, usa SVG circle con `stroke-dasharray` y `stroke-dashoffset` animado para mostrar visualmente el score.

---

## 📊 Mapeo de Hallazgos a CWE/OWASP/ISO

Usa esta tabla para asignar referencias a cada hallazgo:

| Tipo de Hallazgo | CWE | OWASP | ISO 27001 |
|-----------------|-----|-------|-----------|
| Missing CSP header | CWE-1021, CWE-79 | A5:2021 | A.8.25 |
| Missing HSTS header | CWE-319 | A5:2021 | A.8.20 |
| Missing X-Frame-Options | CWE-1021 | A4:2021 | A.8.20 |
| Missing X-Content-Type-Options | CWE-345 | A5:2021 | A.8.24 |
| Missing Referrer-Policy | CWE-200 | — | A.8.11 |
| Missing Permissions-Policy | CWE-200 | — | A.8.11 |
| CORS wildcard / mirroring | CWE-942 | A1:2021 | A.8.20 |
| Reflected XSS | CWE-79 | A3:2021 | A.8.25 |
| SQL Injection | CWE-89 | A3:2021 | A.8.25 |
| Open Redirect | CWE-601 | A1:2021 | A.8.11 |
| Missing CSRF token | CWE-352 | A1:2021 | A.8.5 |
| Cookie missing Secure | CWE-614 | A4:2021 | A.8.20 |
| Cookie missing HttpOnly | CWE-1004 | — | A.8.20 |
| No rate limiting / lockout | CWE-307 | A7:2021 | A.8.5 |
| Path exposed / Info leak | CWE-200 | A1:2021 | A.8.11 |
| No WAF/CDN | CWE-693 | — | A.8.21 |
| Mixed content | CWE-948 | — | A.8.20 |
| SPF/DMARC missing | CWE-345 | — | A.8.24 |
| Server version disclosed | CWE-200 | — | A.8.11 |
| SSL certificate expires soon | CWE-298 | — | A.8.20 |
| No SRI on resources | CWE-345 | — | A.8.24 |
| Cache-Control allows caching | CWE-525 | — | A.8.20 |
| security.txt not found | CWE-200 | — | A.8.11 |

---

## 📝 Estructura del Reporte

### 1. Target Info Card
- Dominio, tipo de auditoría, fecha, WAF/CDN detectado, estado SSL

### 2. Summary Card
- **Score numérico** (0-100) dentro de círculo con color según nivel
- **Score SVG animado** (opcional)
- **Etiqueta de riesgo**: 🔴 ALTO / 🟡 MEDIO / 🟢 BAJO
- **Grid con conteo** de hallazgos por severidad

### 3. Findings Cards
Cada hallazgo con:
- Icono de severidad
- Título en ESP y ENG
- Detalle del hallazgo
- **Tags CWE + OWASP + ISO** (con colores)
- Fix recomendado (en código `<code>`)

### 4. Sección de Recomendaciones Prioritarias
- Lista numerada con las correcciones más urgentes (críticas y altas primero)

### 5. Tabla de Referencias Técnicas
- Columnas: Código | Descripción ESP/ENG | Fuente (link a MITRE)
- Badges: OWASP Top 10, ISO 27001, NIST SP 800-53, PCI DSS v4.0

### 6. Footer
- Marca Ares Tool Security, dominio, fecha
- Firma de IA: "Enviado por Alicia ✨ — Agente de IA Autónoma"
- Disclaimer legal: "Este informe es auditable, verificable y trazable bajo OWASP, CWE e ISO 27001"
- © 2026

---

## 💡 Reglas de Parseo

El reporte `.md` de Ares tiene este formato:

```markdown
# 🔐 Ares Tool Security Audit Report

**Target:** `https://ejemplo.com`
**Type:** web-audit
**Date:** 2026-05-08
**Duration:** 10.3s

---

## 📊 Summary

**Security Score:** 45/100 🔴
...

### 🔴 CRITICAL
**1. Missing CSP header**
   - *Detail:* descripción
   - *Fix:* `add_header Content-Security-Policy "..."`
```

Reglas de parseo:
- **Score:** Extraer de `**Security Score:** (\d+)/100`
- **Target:** Extraer de `` **Target:** `(.+)` ``
- **Hallazgos críticos:** Buscar bajo `### 🔴 CRITICAL`
- **Hallazgos altos:** Buscar bajo `### 🟠 HIGH`
- **Hallazgos medios:** Buscar bajo `### 🟡 MEDIUM`
- **Hallazgos bajos:** Buscar bajo `### 🔵 LOW`
- **Aprobados:** Buscar bajo `### ✅ PASS`
- Cada hallazgo: `**N. Título**` + `Detail:` + `Fix:`

---

## ✅ Checklist de Validación

Antes de entregar el HTML, verifica:

- [ ] Language toggle ESP/ENG funcional
- [ ] Score circle animado con color correcto
- [ ] Todos los hallazgos parseados del .md
- [ ] Tags CWE/OWASP/ISO asignados correctamente
- [ ] Animaciones CSS funcionando (fadeInUp, pulse, hover)
- [ ] Responsive en 3 tamaños: desktop, tablet, móvil (320px)
- [ ] Sin errores JavaScript en consola
- [ ] Código HTML/CSS/JS auto-contenido (sin dependencias externas)
- [ ] Archivo nombrado como `reporte-auditoria-<dominio>.html`

---

## 🔗 Ejemplo Visual de Referencia

El reporte final debe verse similar a este diseño conceptual:

```
┌──────────────────────────────────────────┐
│  [🇪🇸 Español] [🇬🇧 English]              │  ← Sticky Toggle
├──────────────────────────────────────────┤
│         ⚔️ Ares Tool Security            │
│    Auditoría de Seguridad Web            │
│    [40/100] [Cloudflare] [SSL: ✅]       │
├──────────────────────────────────────────┤
│  🎯 Target Information                   │
│  ┌──────┬──────┬──────┬──────┐           │
│  │Dominio│ Tipo │Fecha │Report│           │
│  └──────┴──────┴──────┴──────┘           │
├──────────────────────────────────────────┤
│  📊 Security Summary                     │
│       ┌──────────┐                       │
│       │   40     │  ← Score animado      │
│       │  / 100   │                       │
│       └──────────┘                       │
│  🔴 ALTO — Acciones correctivas urgentes │
│  ┌───┬───┬───┬───┬───┐                  │
│  │🔴4│🟠1│🟡1│🔵0│✅2│                  │
│  └───┴───┴───┴───┴───┘                  │
├──────────────────────────────────────────┤
│  🔍 Detailed Findings                    │
│                                          │
│  ┌──────────────────────────────────┐    │
│  │🔴 Missing CSP Header             │    │  ← Animación fadeInUp
│  │ Detail: No se implementó...      │    │
│  │ [CWE-1021] [CWE-79] [OWASP A5]  │    │
│  │ Fix: add_header Content-Sec...   │    │
│  └──────────────────────────────────┘    │
│                                          │
│  ┌──────────────────────────────────┐    │
│  │🔴 Missing HSTS Header           │    │
│  │ ...                              │    │
│  └──────────────────────────────────┘    │
│  ...                                     │
├──────────────────────────────────────────┤
│  📋 Recommendations (ordered)            │
│  1. Implement security headers           │
│  2. Close port 8080                      │
│  3. Enable HSTS Preload                  │
├──────────────────────────────────────────┤
│  📚 Technical References                  │
│  ┌──────┬──────────────────┬──────┐      │
│  │CWE-79│ XSS              │MITRE │      │
│  │CWE-89│ SQL Injection    │MITRE │      │
│  │ ...   │                  │      │      │
│  └──────┴──────────────────┴──────┘      │
│  [OWASP] [ISO] [NIST] [PCI DSS]          │
├──────────────────────────────────────────┤
│  Footer legal auditable                   │
└──────────────────────────────────────────┘
```

---

## 🚀 Flujo de Trabajo

1. El usuario ejecuta Ares Tool Security y obtiene 2 archivos `.md` en `reports/`
2. El usuario te entrega a ti (modelo de IA):
   - Este archivo `FORGE_REPORT.md` como instrucción
   - El contenido de `web-audit-<dominio>.md`
   - El contenido de `vuln-scan-<dominio>.md`
3. Tú generas un único archivo `reporte-auditoria-<dominio>.html`
4. El usuario abre el `.html` en su navegador y tiene su reporte profesional listo

---

*Creado por Alicia ✨ — Ares Tool Security | Framework ContextP / OBPA*
