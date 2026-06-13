import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({
  name: "mcp-securix",
  version: "1.0.0",
});

// Tools will be registered here as modules are implemented:
//   - dns/*    → DNS lookup, MX, SPF, DMARC, DKIM recon
//   - ssl/*    → Certificate validity, cipher suites, expiry, chain
//   - http/*   → Security headers audit, CORS, CSP, score

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[mcp-securix] Server running on stdio");
}

main().catch((err) => {
  console.error("[mcp-securix] Fatal error:", err);
  process.exit(1);
});
