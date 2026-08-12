import { promises as dns } from "node:dns";
import { httpGet } from "../http/fetch.js";
import type { Finding } from "../findings.js";

dns.setServers(["8.8.8.8", "1.1.1.1"]);

// Reúne información de "gobernanza" del dominio:
// - CAA: qué autoridades certificadoras pueden emitir certs (anti mis-issuance).
// - DNSSEC: si la zona está firmada (via RDAP secureDNS.delegationSigned).
// - Registro del dominio: registrar y fecha de expiración (via RDAP).
// RDAP es el reemplazo moderno de WHOIS: JSON sobre HTTPS.

export interface CaaResult {
  exists: boolean;
  issuers: string[];
  verdict: "present" | "missing";
  detail: string;
}

export interface RegistrationResult {
  available: boolean;
  registrar?: string;
  createdAt?: string;
  expiresAt?: string;
  daysUntilExpiry?: number;
  dnssec?: boolean;
  detail: string;
}

export interface DomainInfoResult {
  domain: string;
  caa: CaaResult;
  registration: RegistrationResult;
  findings: Finding[];
}

async function checkCaa(domain: string): Promise<CaaResult> {
  try {
    const records = await dns.resolveCaa(domain);
    const issuers = records
      .map((r) => r.issue ?? r.issuewild)
      .filter((v): v is string => !!v);

    if (records.length === 0) {
      return {
        exists: false,
        issuers: [],
        verdict: "missing",
        detail: "Sin registros CAA. Cualquier CA puede emitir certificados para el dominio.",
      };
    }
    return {
      exists: true,
      issuers,
      verdict: "present",
      detail: `CAA presente: solo ${issuers.join(", ") || "las CAs listadas"} pueden emitir certificados.`,
    };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENODATA" || code === "ENOTFOUND") {
      return {
        exists: false,
        issuers: [],
        verdict: "missing",
        detail: "Sin registros CAA. Cualquier CA puede emitir certificados para el dominio.",
      };
    }
    return {
      exists: false,
      issuers: [],
      verdict: "missing",
      detail: `No se pudo consultar CAA: ${(err as Error).message}`,
    };
  }
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}
interface RdapEntity {
  roles?: string[];
  vcardArray?: unknown;
}
interface RdapResponse {
  events?: RdapEvent[];
  secureDNS?: { delegationSigned?: boolean };
  entities?: RdapEntity[];
}

function extractRegistrar(entities: RdapEntity[] | undefined): string | undefined {
  const registrar = entities?.find((e) => e.roles?.includes("registrar"));
  if (!registrar?.vcardArray) return undefined;
  // vcardArray = ["vcard", [ ["fn", {}, "text", "NOMBRE"], ... ]]
  try {
    const props = (registrar.vcardArray as unknown[])[1] as unknown[];
    const fn = props.find((p) => Array.isArray(p) && p[0] === "fn") as
      | unknown[]
      | undefined;
    return fn ? String(fn[3]) : undefined;
  } catch {
    return undefined;
  }
}

async function checkRegistration(domain: string): Promise<RegistrationResult> {
  try {
    const res = await httpGet(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      timeoutMs: 8000,
      maxRedirects: 5,
      includeBody: true,
      headers: { Accept: "application/rdap+json" },
    });

    if (res.statusCode === 404) {
      return { available: true, detail: "El dominio no figura registrado (RDAP 404)." };
    }
    if (!res.body) {
      return { available: false, detail: "RDAP no devolvió datos." };
    }

    const data = JSON.parse(res.body) as RdapResponse;
    const events = data.events ?? [];
    const expiration = events.find((e) => e.eventAction === "expiration")?.eventDate;
    const created = events.find((e) => e.eventAction === "registration")?.eventDate;
    const dnssec = data.secureDNS?.delegationSigned;
    const registrar = extractRegistrar(data.entities);

    let daysUntilExpiry: number | undefined;
    if (expiration) {
      daysUntilExpiry = Math.floor(
        (new Date(expiration).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
      );
    }

    return {
      available: false,
      registrar,
      createdAt: created,
      expiresAt: expiration,
      daysUntilExpiry,
      dnssec,
      detail: `Registrado${registrar ? ` vía ${registrar}` : ""}${
        daysUntilExpiry != null ? `, expira en ${daysUntilExpiry} días` : ""
      }. DNSSEC: ${dnssec ? "activo" : "no activo"}.`,
    };
  } catch (err) {
    return {
      available: false,
      detail: `No se pudo consultar RDAP: ${(err as Error).message}`,
    };
  }
}

export async function domainInfoCheck(domain: string): Promise<DomainInfoResult> {
  const [caa, registration] = await Promise.all([
    checkCaa(domain),
    checkRegistration(domain),
  ]);

  const findings: Finding[] = [];

  if (caa.verdict === "missing") {
    findings.push({
      id: "caa-missing",
      category: "ssl",
      severity: "low",
      title: "Sin registros CAA",
      impact:
        "Sin CAA, cualquier autoridad certificadora puede emitir certificados para tu dominio, ampliando la superficie de mis-issuance.",
      remediation: {
        summary: "Publicá un registro CAA autorizando solo a tu(s) CA(s).",
        example: `${domain}  CAA  0 issue "letsencrypt.org"`,
        reference: "https://www.rfc-editor.org/rfc/rfc8659",
      },
    });
  }

  if (registration.dnssec === false) {
    findings.push({
      id: "dnssec-disabled",
      category: "dns",
      severity: "low",
      title: "DNSSEC no activado",
      impact:
        "Sin DNSSEC, las respuestas DNS de tu dominio pueden ser falsificadas (cache poisoning), redirigiendo usuarios a servidores maliciosos.",
      remediation: {
        summary: "Activá DNSSEC en tu proveedor de DNS y publicá el registro DS en el registrador.",
        reference: "https://www.rfc-editor.org/rfc/rfc4033",
      },
    });
  }

  if (registration.daysUntilExpiry != null) {
    if (registration.daysUntilExpiry <= 30) {
      findings.push({
        id: "domain-expiring",
        category: "dns",
        severity: "high",
        title: `Dominio próximo a expirar (${registration.daysUntilExpiry} días)`,
        impact:
          "Si el registro del dominio vence, el sitio y el correo dejan de funcionar por completo y el dominio puede ser tomado por un tercero.",
        remediation: {
          summary: "Renová el dominio ya y activá la renovación automática en el registrador.",
        },
      });
    } else if (registration.daysUntilExpiry <= 60) {
      findings.push({
        id: "domain-expiring-soon",
        category: "dns",
        severity: "low",
        title: `Dominio expira en ${registration.daysUntilExpiry} días`,
        impact: "Conviene renovar con margen para no arriesgar una caída total.",
        remediation: { summary: "Renová el dominio y activá renovación automática." },
      });
    }
  }

  return { domain, caa, registration, findings };
}
