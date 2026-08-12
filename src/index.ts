import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { dnsLookup } from "./tools/dns/lookup.js";
import { spfDmarcCheck } from "./tools/dns/spf-dmarc.js";
import { dkimCheck } from "./tools/dns/dkim.js";
import { emailExtrasCheck } from "./tools/dns/email-extras.js";
import { domainInfoCheck } from "./tools/dns/domain-info.js";
import { sslCheck } from "./tools/ssl/check.js";
import { headersCheck } from "./tools/http/header.js";
import { corsCheck } from "./tools/http/cors.js";
import { webExtrasCheck } from "./tools/http/web-extras.js";
import { securityScore } from "./tools/score/engine.js";
import { renderReport } from "./tools/report/html.js";

const server = new McpServer({
  name: "mcp-securix",
  version: "1.0.0",
});

//DNS Lookup Tool
server.tool(
  "dns_lookup",
  "Resuelve los registros DNS (A, AAAA, MX, TXT, NS, CNAME) de un dominio. Útil para reconocimiento y auditoría de infraestructura.",
  {
    domain: z.string().describe("El dominio a consultar, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const result = await dnsLookup(domain);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

//SPF & DMARC Check Tool
server.tool(
  "spf_dmarc_check",
  "Verifica la configuración de SPF y DMARC de un dominio. Evalúa si el dominio está protegido contra email spoofing y phishing.",
  {
    domain: z.string().describe("El dominio a auditar, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const result = await spfDmarcCheck(domain);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

//SSL Certificate Check Tool
server.tool(
  "ssl_check",
  "Verifica el certificado SSL/TLS de un dominio: validez, fecha de expiración, emisor, protocolo y dominios cubiertos. Detecta certificados expirados, próximos a vencer, o con protocolos obsoletos.",
  {
    domain: z.string().describe("El dominio a verificar, sin https://, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const result = await sslCheck(domain);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

//Headers Check Tool
server.tool(
  "headers_check",
  "Analiza los headers de seguridad HTTP de un dominio: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy y Permissions-Policy. Detecta headers ausentes o mal configurados.",
  {
    domain: z.string().describe("El dominio a analizar, sin https://, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const result = await headersCheck(domain);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

// Domain Info Tool (CAA, DNSSEC, expiración vía RDAP)
server.tool(
  "domain_info_check",
  "Consulta gobernanza del dominio: registros CAA (qué CAs pueden emitir certificados), estado de DNSSEC y datos de registro (registrador y fecha de expiración) vía RDAP.",
  {
    domain: z.string().describe("El dominio a consultar, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const result = await domainInfoCheck(domain);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

// Email Extras Tool (MTA-STS, TLS-RPT, BIMI)
server.tool(
  "email_extras_check",
  "Verifica controles de email avanzados que complementan SPF/DMARC/DKIM: MTA-STS (fuerza TLS en la entrega SMTP), TLS-RPT (reportes de fallos TLS) y BIMI (logo verificado). Solo relevantes si el dominio tiene MX.",
  {
    domain: z.string().describe("El dominio a auditar, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const dns = await dnsLookup(domain);
    const hasMx = !!(dns.records.MX && dns.records.MX.length > 0);
    const result = await emailExtrasCheck(domain, hasMx);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

// DKIM Check Tool
server.tool(
  "dkim_check",
  "Busca registros DKIM probando los selectores más comunes de los grandes proveedores de correo. DKIM firma criptográficamente el email saliente. Nota: no encontrar nada NO confirma ausencia (el dominio puede usar un selector propio).",
  {
    domain: z.string().describe("El dominio a auditar, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const result = await dkimCheck(domain);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

// CORS Check Tool
server.tool(
  "cors_check",
  "Analiza la configuración CORS enviando un Origin de prueba ajeno. Detecta misconfiguraciones peligrosas (reflejar cualquier origen con credenciales) que permiten robo de datos autenticados cross-origin.",
  {
    domain: z.string().describe("El dominio a analizar, sin https://, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const result = await corsCheck(domain);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

// Web Extras Tool (redirect HTTPS, cookies, security.txt)
server.tool(
  "web_extras_check",
  "Analiza controles web adicionales: redirect HTTP→HTTPS, flags de seguridad de cookies (Secure, HttpOnly, SameSite) y presencia de security.txt (RFC 9116).",
  {
    domain: z.string().describe("El dominio a analizar, sin https://, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const result = await webExtrasCheck(domain);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

// Score engine Tool
server.tool(
  "security_score",
  "Realiza una auditoría de seguridad completa de un dominio: DNS, SSL, SPF, DMARC y HTTP headers. Devuelve un score 0-100, nivel de riesgo, desglose por categoría y hallazgos priorizados por severidad.",
  {
    domain: z.string().describe("El dominio a auditar, sin https://, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const result = await securityScore(domain);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

// Security Report Tool — devuelve el reporte YA renderizado como HTML.
// El diseño (score, gauge, barras) lo controla el server, así el visual es
// determinístico y no depende de que el modelo lo dibuje.
server.tool(
  "security_report",
  "Audita un dominio y devuelve un reporte de seguridad completo ya renderizado como HTML (score visual, desglose por categoría, estado de controles y hallazgos priorizados). El HTML debe mostrarse tal cual como artifact, sin modificarlo.",
  {
    domain: z.string().describe("El dominio a auditar, sin https://, por ejemplo 'example.com'"),
  },
  async ({ domain }) => {
    const result = await securityScore(domain);
    const html = renderReport(result);
    return {
      content: [
        {
          type: "text",
          text: html,
        },
      ],
    };
  }
);

// Prompt de reporte: da formato y tono consistentes al informe de auditoría,
// independientemente de cómo lo pida el usuario.
server.prompt(
  "audit_report",
  "Audita un dominio con security_score y presenta un informe de seguridad claro, priorizado y accionable en español.",
  {
    domain: z.string().describe("El dominio a auditar, sin https://, por ejemplo 'example.com'"),
  },
  ({ domain }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text: [
            `Generá el reporte de seguridad del dominio ${domain} llamando a la tool security_report.`,
            "",
            "Esa tool devuelve el reporte YA renderizado como HTML (con el score, el gauge y las barras hechos por el servidor). Mostrá ese HTML TAL CUAL como un artifact de tipo HTML, sin rediseñarlo, sin cambiar colores ni estructura, y sin regenerarlo por tu cuenta.",
            "",
            "Después del artifact, agregá 2-3 líneas de contexto en texto: cuál es el hallazgo más urgente y, si el score parece bajo por un solo problema grande (ej. DMARC ausente), aclaralo con honestidad. No repitas todo el contenido del reporte en texto.",
          ].join("\n"),
        },
      },
    ],
  })
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[mcp-securix] Server running on stdio");
}

main().catch((err) => {
  console.error("[mcp-securix] Fatal error:", err);
  process.exit(1);
});