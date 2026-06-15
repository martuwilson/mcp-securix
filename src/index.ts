import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { dnsLookup } from "./tools/dns/lookup.js";
import { spfDmarcCheck } from "./tools/dns/spf-dmarc.js";
import { sslCheck } from "./tools/ssl/check.js";
import { headersCheck } from "./tools/http/header.js";

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

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[mcp-securix] Server running on stdio");
}

main().catch((err) => {
  console.error("[mcp-securix] Fatal error:", err);
  process.exit(1);
});