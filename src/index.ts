import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { dnsLookup } from "./tools/dns/lookup.js";
import { spfDmarcCheck } from "./tools/dns/spf-dmarc.js";
import { dkimCheck } from "./tools/dns/dkim.js";
import { sslCheck } from "./tools/ssl/check.js";
import { headersCheck } from "./tools/http/header.js";
import { corsCheck } from "./tools/http/cors.js";
import { securityScore } from "./tools/score/engine.js";

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
            `Auditá la seguridad del dominio ${domain} usando la tool security_score y presentá el resultado como un informe profesional en español con esta estructura:`,
            "",
            "1. **Resumen ejecutivo**: score /100, nivel de riesgo y una frase honesta sobre qué tan grave es en la práctica (aclarando si el número exagera o no el problema real).",
            "2. **Lo que está bien**: bullets concisos con los controles correctamente configurados.",
            "3. **Lo que hay que corregir**: ordenado por severidad (critical → low). Para cada hallazgo: qué es, por qué importa (impacto) y el paso concreto para arreglarlo, incluyendo el registro/valor exacto a pegar cuando exista (campo remediation.example).",
            "4. **Prioridad**: qué hacer primero y el impacto esperado en el score.",
            "",
            "Reglas de tono:",
            "- Directo y técnico, sin relleno ni alarmismo. Si algo depende de un tercero (ej. la plataforma de hosting), decilo.",
            "- No inventes hallazgos que no estén en el JSON de la tool.",
            "- Cerrá aclarando que es un análisis de configuración externa, no un pentest de la aplicación.",
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