import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { dnsLookup } from "./tools/dns/index.js";

const server = new McpServer({
  name: "mcp-securix",
  version: "1.0.0",
});

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

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[mcp-securix] Server running on stdio");
}

main().catch((err) => {
  console.error("[mcp-securix] Fatal error:", err);
  process.exit(1);
});