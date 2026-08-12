# mcp-securix

MCP Security Server — expone herramientas de reconocimiento y auditoría de seguridad de dominios para agentes de Claude, vía el Model Context Protocol.

## Qué hace

`mcp-securix` corre como un servidor MCP por stdio. Claude se conecta y gana acceso a herramientas que le permiten auditar dominios de forma autónoma: registros DNS, certificados SSL/TLS, autenticación de correo (SPF, DMARC, DKIM), headers de seguridad HTTP, configuración CORS y un score de seguridad compuesto.

Cada herramienta devuelve JSON estructurado. Los hallazgos incluyen severidad, impacto y remediación accionable (con el registro o header exacto para aplicar).

## Herramientas

| Tool | Qué evalúa | Estado |
|------|-----------|--------|
| `dns_lookup` | Registros A, AAAA, MX, TXT, NS, CNAME | ✅ |
| `spf_dmarc_check` | SPF y DMARC (anti-spoofing de correo) | ✅ |
| `dkim_check` | DKIM probando selectores comunes de grandes proveedores | ✅ |
| `email_extras_check` | MTA-STS, TLS-RPT y BIMI (email avanzado) | ✅ |
| `domain_info_check` | CAA, DNSSEC y registro/expiración del dominio (vía RDAP) | ✅ |
| `ssl_check` | Certificado: validez, expiración, emisor, protocolo TLS, SANs | ✅ |
| `headers_check` | 6 headers de seguridad (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy); sigue redirects | ✅ |
| `cors_check` | Misconfiguración CORS (reflejo de origen arbitrario con credenciales) | ✅ |
| `web_extras_check` | Redirect HTTP→HTTPS, flags de cookies (Secure/HttpOnly/SameSite), security.txt | ✅ |
| `security_score` | Auditoría completa: score 0-100, riesgo, desglose por categoría y hallazgos priorizados con remediación | ✅ |
| `security_report` | Reporte completo ya renderizado como HTML (score visual, gauge, barras) | ✅ |

### Prompt

| Prompt | Qué hace |
|--------|----------|
| `audit_report` | Audita un dominio con `security_score` y presenta un informe profesional en español, priorizado y accionable, con formato y tono consistentes. |

## Scoring

El `security_score` pondera cuatro pilares (suman 100):

| Categoría | Peso |
|-----------|------|
| SSL/TLS | 25 |
| SPF | 20 |
| DMARC | 25 |
| HTTP headers | 30 |

Los veredictos `weak` reciben crédito parcial (una config razonable como SPF `~all` penaliza poco). Un CORS peligroso aplica una penalización adicional de 15 puntos. Los hallazgos se ordenan por severidad (`critical` → `info`), y DKIM es informativo (no resta puntaje, porque no encontrar un selector común no confirma su ausencia).

Bandas de riesgo: `low` ≥ 80, `medium` ≥ 60, `high` ≥ 40, `critical` < 40.

## Setup

```bash
npm install
npm run build
npm start
```

## Desarrollo

```bash
npm run dev    # ts-node con ESM — sin paso de build
npm test       # compila y corre la suite (node:test)
```

> Nota: Claude ejecuta el `.js` compilado en `dist/`. Después de cambiar el código en `src/`, corré `npm run build` para regenerar `dist/`.

## Integración con Claude Desktop

Agregá a tu `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-securix": {
      "command": "node",
      "args": ["/ruta/a/mcp-securix/dist/index.js"]
    }
  }
}
```

Reiniciá Claude Desktop por completo (que no quede en la bandeja del sistema) para que tome la configuración.

## Arquitectura

```
src/
    index.ts                 → entry point del servidor MCP (stdio), registra tools y prompt
    tools/
        findings.ts          → tipos compartidos de hallazgos (Finding, Remediation, severidad)
        dns/
            lookup.ts        → dns_lookup
            spf-dmarc.ts     → spf_dmarc_check (+ parsers puros classifySpf/classifyDmarc)
            dkim.ts          → dkim_check
            email-extras.ts  → email_extras_check (MTA-STS, TLS-RPT, BIMI)
            domain-info.ts   → domain_info_check (CAA, DNSSEC, RDAP)
        ssl/
            check.ts         → ssl_check
        http/
            fetch.ts         → helper httpGet (sigue redirects, body opcional)
            header.ts        → headers_check
            cors.ts          → cors_check
            web-extras.ts    → web_extras_check (HTTP→HTTPS, cookies, security.txt)
        score/
            engine.ts        → security_score (orquesta todo y calcula el score)
        report/
            html.ts          → renderReport (HTML determinístico para security_report)
    tests/                   → suite con node:test (parsers, scoring, findings, report)
```

## Alcance

Esto es un análisis de configuración **externa**, no un pentest de la aplicación. No evalúa vulnerabilidades de la app, control de accesos ni el estado interno del servidor de correo.

## Licencia

ISC
