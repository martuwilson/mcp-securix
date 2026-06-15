import { promises as dns } from "node:dns";

dns.setServers(["8.8.8.8", "1.1.1.1"]);

export interface DnsLookupResult {
  domain: string;
  records: {
    A?: string[];
    AAAA?: string[];
    MX?: { exchange: string; priority: number }[];
    TXT?: string[][];
    NS?: string[];
    CNAME?: string[];
  };
  errors?: string[];
}

export async function dnsLookup(domain: string): Promise<DnsLookupResult> {
  const result: DnsLookupResult = { domain, records: {} };
  const errors: string[] = [];

  const queries: [string, () => Promise<void>][] = [
    ["A", async () => { result.records.A = await dns.resolve4(domain); }],
    ["AAAA", async () => { result.records.AAAA = await dns.resolve6(domain); }],
    ["MX", async () => { result.records.MX = await dns.resolveMx(domain); }],
    ["TXT", async () => { result.records.TXT = await dns.resolveTxt(domain); }],
    ["NS", async () => { result.records.NS = await dns.resolveNs(domain); }],
    ["CNAME", async () => { result.records.CNAME = await dns.resolveCname(domain); }],
  ];

  for (const [type, query] of queries) {
    try {
      await query();
    } catch (err) {
      // ENODATA / ENOTFOUND son normales (el dominio no tiene ese tipo de registro)
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENODATA" && code !== "ENOTFOUND") {
        errors.push(`${type}: ${(err as Error).message}`);
      }
    }
  }

  if (errors.length > 0) result.errors = errors;
  return result;
}