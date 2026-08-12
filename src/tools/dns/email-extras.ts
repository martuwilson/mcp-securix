import { promises as dns } from "node:dns";
import type { Finding } from "../findings.js";

dns.setServers(["8.8.8.8", "1.1.1.1"]);

// Controles de email "modernos" que complementan SPF/DMARC/DKIM:
// - MTA-STS: fuerza TLS en la entrega SMTP (anti-downgrade / anti-MITM).
// - TLS-RPT: reportes de fallos de TLS en la entrega.
// - BIMI: logo verificado en la bandeja (requiere DMARC en enforcement).
// Todos son registros TXT baratos de consultar. Solo son relevantes si el
// dominio efectivamente envía/recibe correo (tiene MX).

export interface MtaStsResult {
  exists: boolean;
  record?: string;
  mode?: "enforce" | "testing" | "none";
  verdict: "strong" | "weak" | "missing";
  detail: string;
}

export interface TlsRptResult {
  exists: boolean;
  record?: string;
  verdict: "present" | "missing";
  detail: string;
}

export interface BimiResult {
  exists: boolean;
  record?: string;
  hasVmc: boolean;
  verdict: "present" | "missing";
  detail: string;
}

export interface EmailExtrasResult {
  domain: string;
  /** Si el dominio no tiene MX, estos controles no aplican realmente. */
  hasMx: boolean;
  mtaSts: MtaStsResult;
  tlsRpt: TlsRptResult;
  bimi: BimiResult;
  findings: Finding[];
}

async function findTxt(host: string, prefix: string): Promise<string | undefined> {
  try {
    const records = await dns.resolveTxt(host);
    return records.map((r) => r.join("")).find((r) => r.startsWith(prefix));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENODATA" || code === "ENOTFOUND") return undefined;
    return undefined;
  }
}

async function checkMtaSts(domain: string): Promise<MtaStsResult> {
  const record = await findTxt(`_mta-sts.${domain}`, "v=STSv1");
  if (!record) {
    return {
      exists: false,
      verdict: "missing",
      detail: "Sin MTA-STS. La entrega de correo puede sufrir downgrade a texto plano por un atacante en la red.",
    };
  }

  // El TXT solo anuncia que hay política; el modo real está en el archivo de
  // policy servido por HTTPS. Lo leemos para extraer el mode.
  const mode = await fetchMtaStsMode(domain);

  if (mode === "enforce") {
    return {
      exists: true,
      record,
      mode,
      verdict: "strong",
      detail: "MTA-STS en modo enforce: la entrega de correo exige TLS válido.",
    };
  }
  return {
    exists: true,
    record,
    mode,
    verdict: "weak",
    detail: `MTA-STS presente en modo ${mode ?? "desconocido"}. Recomendado: mode=enforce para proteger de verdad.`,
  };
}

async function fetchMtaStsMode(domain: string): Promise<MtaStsResult["mode"]> {
  return new Promise((resolve) => {
    import("node:https").then((https) => {
      const req = https.request(
        `https://mta-sts.${domain}/.well-known/mta-sts.txt`,
        { method: "GET", timeout: 6000 },
        (res) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (c) => (body += c));
          res.on("end", () => {
            const m = body.match(/mode\s*:\s*(enforce|testing|none)/i);
            resolve(m ? (m[1].toLowerCase() as MtaStsResult["mode"]) : undefined);
          });
        }
      );
      req.on("timeout", () => {
        req.destroy();
        resolve(undefined);
      });
      req.on("error", () => resolve(undefined));
      req.end();
    });
  });
}

async function checkTlsRpt(domain: string): Promise<TlsRptResult> {
  const record = await findTxt(`_smtp._tls.${domain}`, "v=TLSRPTv1");
  if (!record) {
    return {
      exists: false,
      verdict: "missing",
      detail: "Sin TLS-RPT. No recibís reportes cuando falla la entrega de correo por TLS.",
    };
  }
  return {
    exists: true,
    record,
    verdict: "present",
    detail: "TLS-RPT presente: recibís reportes de fallos de TLS en la entrega de correo.",
  };
}

async function checkBimi(domain: string): Promise<BimiResult> {
  const record = await findTxt(`default._bimi.${domain}`, "v=BIMI1");
  if (!record) {
    return {
      exists: false,
      hasVmc: false,
      verdict: "missing",
      detail: "Sin BIMI. Los clientes de correo no muestran tu logo verificado junto a los mensajes.",
    };
  }
  const hasVmc = /a=https?:\/\//i.test(record);
  return {
    exists: true,
    record,
    hasVmc,
    verdict: "present",
    detail: `BIMI presente${hasVmc ? " con VMC (logo verificado)" : " sin VMC"}. Requiere DMARC en enforcement para mostrarse.`,
  };
}

export async function emailExtrasCheck(
  domain: string,
  hasMx: boolean
): Promise<EmailExtrasResult> {
  const [mtaSts, tlsRpt, bimi] = await Promise.all([
    checkMtaSts(domain),
    checkTlsRpt(domain),
    checkBimi(domain),
  ]);

  const findings: Finding[] = [];

  // Si el dominio no recibe correo, estos controles son opcionales: los
  // marcamos como info en vez de generar ruido.
  const sev = hasMx ? "low" : "info";

  if (mtaSts.verdict === "missing") {
    findings.push({
      id: "mta-sts-missing",
      category: "dmarc",
      severity: sev,
      title: "Sin MTA-STS",
      impact: mtaSts.detail,
      remediation: {
        summary: "Publicá MTA-STS: un TXT en _mta-sts y una policy en mta-sts.<dominio>.",
        example: `_mta-sts.${domain}  TXT  "v=STSv1; id=$(date +%Y%m%d)01"`,
        reference: "https://www.rfc-editor.org/rfc/rfc8461",
      },
    });
  } else if (mtaSts.verdict === "weak") {
    findings.push({
      id: "mta-sts-testing",
      category: "dmarc",
      severity: "info",
      title: `MTA-STS en modo ${mtaSts.mode ?? "no-enforce"}`,
      impact: mtaSts.detail,
      remediation: { summary: "Cuando valides que todo funciona, cambiá la policy a mode=enforce." },
    });
  }

  if (tlsRpt.verdict === "missing") {
    findings.push({
      id: "tls-rpt-missing",
      category: "dmarc",
      severity: "info",
      title: "Sin TLS-RPT",
      impact: tlsRpt.detail,
      remediation: {
        summary: "Publicá un TXT TLS-RPT para recibir reportes de fallos de entrega TLS.",
        example: `_smtp._tls.${domain}  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@${domain}"`,
      },
    });
  }

  if (bimi.verdict === "missing") {
    findings.push({
      id: "bimi-missing",
      category: "dmarc",
      severity: "info",
      title: "Sin BIMI",
      impact: bimi.detail,
      remediation: {
        summary: "Opcional: publicá BIMI (requiere DMARC en quarantine/reject) para mostrar tu logo verificado.",
        reference: "https://bimigroup.org/",
      },
    });
  }

  return { domain, hasMx, mtaSts, tlsRpt, bimi, findings };
}
