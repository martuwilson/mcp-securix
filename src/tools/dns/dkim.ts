import { promises as dns } from "node:dns";
import type { Finding } from "../findings.js";

dns.setServers(["8.8.8.8", "1.1.1.1"]);

// DKIM no se puede enumerar: cada registro vive en
// `<selector>._domainkey.<domain>` y el selector lo elige quien envía.
// Lo mejor que se puede hacer sin credenciales es probar los selectores
// más usados por los grandes proveedores de correo. Por eso el veredicto
// nunca es "missing" a secas: si no encontramos nada es "unknown", no una
// afirmación de que DKIM no exista.
const COMMON_SELECTORS: { selector: string; provider: string }[] = [
  { selector: "google", provider: "Google Workspace" },
  { selector: "selector1", provider: "Microsoft 365 / Outlook" },
  { selector: "selector2", provider: "Microsoft 365 / Outlook" },
  { selector: "k1", provider: "Mailchimp / Mandrill" },
  { selector: "k2", provider: "Mailchimp / Mandrill" },
  { selector: "s1", provider: "SendGrid / genérico" },
  { selector: "s2", provider: "SendGrid / genérico" },
  { selector: "mail", provider: "genérico" },
  { selector: "dkim", provider: "genérico" },
  { selector: "default", provider: "genérico" },
  { selector: "smtp", provider: "genérico / Amazon SES" },
  { selector: "sig1", provider: "Zoho" },
  { selector: "scph", provider: "SparkPost" },
  { selector: "pm", provider: "Postmark" },
  { selector: "fm1", provider: "Fastmail" },
];

export interface DkimSelectorHit {
  selector: string;
  provider: string;
  record: string;
}

export interface DkimResult {
  domain: string;
  /** Selectores comunes que sí resolvieron a un registro DKIM. */
  found: DkimSelectorHit[];
  /** Cuántos selectores comunes probamos. */
  selectorsProbed: number;
  verdict: "found" | "unknown";
  detail: string;
  findings: Finding[];
}

export function isDkimRecord(txt: string): boolean {
  // Un registro DKIM válido declara v=DKIM1, o al menos una clave pública real
  // en p= (base64 largo). Exigir ≥20 chars de base64 evita falsos positivos con
  // otros TXT que casualmente tengan un p= corto (ej. 'p=none' de DMARC).
  if (/v=DKIM1/i.test(txt)) return true;
  return /(^|;)\s*p=[A-Za-z0-9+/]{20,}/.test(txt);
}

async function probeSelector(
  domain: string,
  selector: string
): Promise<string | null> {
  const host = `${selector}._domainkey.${domain}`;
  try {
    const records = await dns.resolveTxt(host);
    const flat = records.map((r) => r.join(""));
    const dkim = flat.find(isDkimRecord);
    return dkim ?? null;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENODATA" || code === "ENOTFOUND") return null;
    // Un error transitorio de DNS no debería voltear todo el check.
    return null;
  }
}

export async function dkimCheck(domain: string): Promise<DkimResult> {
  const hits = await Promise.all(
    COMMON_SELECTORS.map(async ({ selector, provider }) => {
      const record = await probeSelector(domain, selector);
      return record ? { selector, provider, record } : null;
    })
  );

  const found = hits.filter((h): h is DkimSelectorHit => h !== null);
  const findings: Finding[] = [];

  if (found.length > 0) {
    const selectorList = found.map((h) => h.selector).join(", ");
    return {
      domain,
      found,
      selectorsProbed: COMMON_SELECTORS.length,
      verdict: "found",
      detail: `DKIM detectado en ${found.length} selector(es) común(es): ${selectorList}. El dominio firma criptográficamente su correo saliente.`,
      findings,
    };
  }

  // No encontramos nada, pero no podemos afirmar que DKIM no exista:
  // el dominio podría usar un selector propio que no probamos.
  findings.push({
    id: "dkim-not-detected",
    category: "dkim",
    severity: "info",
    title: "No se detectó DKIM en selectores comunes",
    impact:
      "No encontramos DKIM probando los selectores más usados, pero esto NO confirma su ausencia: el dominio podría usar un selector propio. DKIM firma criptográficamente el correo y, junto con SPF y DMARC, es clave para que DMARC pueda alinear y autenticar.",
    remediation: {
      summary:
        "Verificá el selector real en tu proveedor de correo y confirmá que el registro DKIM esté publicado.",
      steps: [
        "Buscá el selector DKIM en el panel de tu proveedor de email (Google, Microsoft 365, SendGrid, etc.).",
        "Confirmá que exista el TXT en <selector>._domainkey.{domain}.",
        "Si aún no usás DKIM, activá la firma DKIM en tu proveedor.",
      ],
      reference: "https://www.rfc-editor.org/rfc/rfc6376",
    },
  });

  return {
    domain,
    found: [],
    selectorsProbed: COMMON_SELECTORS.length,
    verdict: "unknown",
    detail: `No se detectó DKIM probando ${COMMON_SELECTORS.length} selectores comunes. Esto no confirma su ausencia (el dominio podría usar un selector propio).`,
    findings,
  };
}
