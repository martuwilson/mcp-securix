import { dnsLookup, type DnsLookupResult } from "../dns/lookup.js";
import { spfDmarcCheck, type SpfDmarcResult } from "../dns/spf-dmarc.js";
import { dkimCheck, type DkimResult } from "../dns/dkim.js";
import { emailExtrasCheck, type EmailExtrasResult } from "../dns/email-extras.js";
import { domainInfoCheck, type DomainInfoResult } from "../dns/domain-info.js";
import { sslCheck, type SslResult } from "../ssl/check.js";
import { headersCheck, type HeadersResult } from "../http/header.js";
import { corsCheck, type CorsResult } from "../http/cors.js";
import { webExtrasCheck, type WebExtrasResult } from "../http/web-extras.js";
import { parseTarget } from "../target.js";
import {
  type Finding,
  type Severity,
  sortFindings,
  countBySeverity,
} from "../findings.js";

export type ScoreGroup = "tls" | "email" | "web" | "dns";

export interface CategoryScore {
  points: number;
  max: number;
  percentage: number;
  /** false cuando el grupo entero no aplica (ej. email sin MX). */
  applicable: boolean;
}

export interface ScoreBreakdown {
  tls: CategoryScore;
  email: CategoryScore;
  web: CategoryScore;
  dns: CategoryScore;
}

/** Un control individual y su aporte al score normalizado. */
export interface ScoreItem {
  key: string;
  label: string;
  group: ScoreGroup;
  earned: number;
  max: number;
  /** Si false, el control se excluye del cálculo (no aplica / indeterminado). */
  applicable: boolean;
}

export interface SecurityScoreResult {
  domain: string;
  score: number;
  maxScore: number;
  percentage: number;
  risk: "low" | "medium" | "high" | "critical";
  breakdown: ScoreBreakdown;
  /** Penalizaciones aplicadas fuera de las 4 categorías base (ej. CORS peligroso). */
  penalties: { cors: number };
  /** Detalle de cada control y su aporte al score normalizado. */
  scoreItems: ScoreItem[];
  /** Hallazgos estructurados con remediación, ordenados de más a menos grave. */
  findings: Finding[];
  /** Conteo de hallazgos por severidad. */
  summary: Record<Severity, number>;
  /** Resultados crudos de cada check, para render de reportes detallados. */
  details: {
    dns: DnsLookupResult;
    spfDmarc: SpfDmarcResult;
    dkim: DkimResult;
    emailExtras: EmailExtrasResult;
    domainInfo: DomainInfoResult;
    ssl: SslResult;
    headers: HeadersResult;
    cors: CorsResult;
    webExtras: WebExtrasResult;
  };
  generatedAt: string;
}

function calculateRisk(percentage: number): SecurityScoreResult["risk"] {
  if (percentage >= 80) return "low";
  if (percentage >= 60) return "medium";
  if (percentage >= 40) return "high";
  return "critical";
}

// --- SSL (25 pts) ---
export function scoreSsl(ssl: SslResult): { points: number; detail: string; findings: Finding[] } {
  const findings: Finding[] = [];

  if (ssl.verdict === "strong") {
    return {
      points: 25,
      detail: `Certificado válido, ${ssl.daysUntilExpiry} días hasta expiración, protocolo ${ssl.protocol}.`,
      findings,
    };
  }

  if (ssl.verdict === "expired") {
    findings.push({
      id: "ssl-expired",
      category: "ssl",
      severity: "critical",
      title: "Certificado SSL/TLS expirado",
      impact:
        "El certificado venció. Los navegadores muestran una pantalla de error de seguridad que bloquea el acceso y destruye la confianza del usuario.",
      remediation: {
        summary: "Renová el certificado de inmediato.",
        steps: [
          "Renová el certificado con tu CA o mediante Let's Encrypt.",
          "Configurá la renovación automática (certbot / ACME) para que no vuelva a pasar.",
        ],
      },
    });
    return { points: 0, detail: ssl.detail, findings };
  }

  if (ssl.verdict === "invalid" || ssl.verdict === "error") {
    findings.push({
      id: "ssl-invalid",
      category: "ssl",
      severity: "high",
      title: "Certificado SSL/TLS inválido o no confiable",
      impact:
        "El certificado no es de confianza (autofirmado, cadena rota o no coincide el dominio). Los navegadores advierten al usuario y muchos clientes rechazan la conexión.",
      remediation: {
        summary: "Instalá un certificado emitido por una CA confiable y con la cadena completa.",
        steps: [
          "Verificá que el CN/SAN coincida con el dominio.",
          "Incluí la cadena intermedia completa en la configuración del servidor.",
        ],
      },
    });
    return { points: 0, detail: ssl.detail, findings };
  }

  // weak: por expiración cercana o protocolo obsoleto.
  const oldProtocol = ssl.protocol === "TLSv1" || ssl.protocol === "TLSv1.1";
  if (oldProtocol) {
    findings.push({
      id: "ssl-weak-protocol",
      category: "ssl",
      severity: "medium",
      title: `Protocolo TLS obsoleto (${ssl.protocol})`,
      impact:
        "El servidor negocia una versión de TLS antigua y vulnerable. Debe usarse TLS 1.2 o 1.3.",
      remediation: {
        summary: "Deshabilitá TLS 1.0/1.1 y habilitá solo TLS 1.2 y 1.3.",
      },
    });
    return { points: 17, detail: ssl.detail, findings };
  }

  // Expiración cercana.
  const days = ssl.daysUntilExpiry ?? 0;
  findings.push({
    id: "ssl-expiring-soon",
    category: "ssl",
    severity: days <= 14 ? "high" : "low",
    title: `Certificado próximo a expirar (${days} días)`,
    impact:
      "Si el certificado vence sin renovarse, el sitio queda inaccesible con error de seguridad.",
    remediation: {
      summary: "Renová el certificado y activá renovación automática.",
    },
  });
  return { points: days <= 14 ? 15 : 20, detail: ssl.detail, findings };
}

// --- SPF (20 pts) ---
// hasMx escala la severidad: la falta de SPF pesa más si el dominio maneja correo.
export function scoreSpf(
  spf: SpfDmarcResult["spf"],
  hasMx = true
): { points: number; detail: string; findings: Finding[] } {
  const findings: Finding[] = [];

  if (spf.verdict === "strong") {
    return { points: 20, detail: "SPF con -all configurado correctamente.", findings };
  }

  if (spf.verdict === "dangerous") {
    findings.push({
      id: "spf-dangerous",
      category: "spf",
      severity: "critical",
      title: "SPF con +all (permite cualquier remitente)",
      impact:
        "Con +all cualquier servidor del mundo puede enviar correo en nombre de tu dominio y pasar SPF. Es peor que no tener SPF.",
      remediation: {
        summary: "Reemplazá +all por -all y listá solo tus emisores legítimos.",
        example: "v=spf1 include:_spf.tu-proveedor.com -all",
      },
    });
    return { points: 0, detail: spf.detail, findings };
  }

  if (spf.verdict === "missing") {
    findings.push({
      id: "spf-missing",
      category: "spf",
      severity: hasMx ? "high" : "medium",
      title: "Sin registro SPF",
      impact:
        "Sin SPF, los servidores receptores no pueden verificar qué IPs pueden enviar como tu dominio, facilitando el spoofing.",
      remediation: {
        summary: "Publicá un registro SPF con tus emisores autorizados terminando en -all.",
        example: "v=spf1 include:_spf.tu-proveedor.com -all",
        reference: "https://www.rfc-editor.org/rfc/rfc7208",
      },
    });
    return { points: 0, detail: spf.detail, findings };
  }

  // weak: ~all (soft fail) es una config legítima y muy común → penalización leve.
  if (spf.qualifier === "~all") {
    findings.push({
      id: "spf-softfail",
      category: "spf",
      severity: "low",
      title: "SPF en soft fail (~all)",
      impact:
        "Con ~all el correo no autorizado se marca pero igual puede entregarse. Es aceptable, pero -all es más estricto.",
      remediation: {
        summary:
          "Una vez confirmados todos tus emisores legítimos, endurecé ~all a -all.",
      },
    });
    return { points: 16, detail: spf.detail, findings };
  }

  // weak sin calificador claro.
  findings.push({
    id: "spf-unclear",
    category: "spf",
    severity: "medium",
    title: "SPF sin calificador final claro",
    impact:
      "El registro SPF existe pero no define un mecanismo 'all' claro, dejando ambiguo qué hacer con remitentes no listados.",
    remediation: {
      summary: "Agregá un calificador explícito al final del registro (idealmente -all).",
    },
  });
  return { points: 10, detail: spf.detail, findings };
}

// --- DMARC (25 pts) ---
// DMARC ausente es el mayor golpe al score (25 pts). Su severidad escala con
// hasMx para que el badge sea coherente con el peso: crítico si el dominio
// maneja correo, high si no.
export function scoreDmarc(
  dmarc: SpfDmarcResult["dmarc"],
  domain: string,
  hasMx = true
): { points: number; detail: string; findings: Finding[] } {
  const findings: Finding[] = [];

  if (dmarc.verdict === "strong") {
    return { points: 25, detail: "DMARC con p=reject configurado correctamente.", findings };
  }

  if (dmarc.verdict === "missing") {
    findings.push({
      id: "dmarc-missing",
      category: "dmarc",
      severity: hasMx ? "critical" : "high",
      title: "Sin registro DMARC",
      impact:
        "Sin DMARC, aunque falle SPF/DKIM los receptores no tienen instrucción sobre qué hacer, y no recibís reportes de quién envía como tu dominio. Es la puerta abierta al phishing con tu marca.",
      remediation: {
        summary:
          "Publicá un DMARC en modo observación y endurecelo progresivamente.",
        steps: [
          "Empezá con p=none para recibir reportes sin bloquear.",
          "Tras unas semanas revisando reportes, subí a p=quarantine.",
          "Finalmente endurecé a p=reject.",
        ],
        example: `_dmarc.${domain}  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@${domain}"`,
        reference: "https://www.rfc-editor.org/rfc/rfc7489",
      },
    });
    return { points: 0, detail: dmarc.detail, findings };
  }

  // weak: p=quarantine o p=none.
  if (dmarc.policy === "quarantine") {
    findings.push({
      id: "dmarc-quarantine",
      category: "dmarc",
      severity: "low",
      title: "DMARC en p=quarantine",
      impact:
        "El correo sospechoso va a spam en lugar de rechazarse. Buena postura intermedia; p=reject es el objetivo final.",
      remediation: {
        summary: "Cuando estés seguro de tus emisores, evolucioná a p=reject.",
      },
    });
    return { points: 18, detail: dmarc.detail, findings };
  }

  findings.push({
    id: "dmarc-none",
    category: "dmarc",
    severity: "medium",
    title: "DMARC en p=none (solo monitoreo)",
    impact:
      "Con p=none DMARC solo reporta, no bloquea. No protege contra spoofing activo; es apenas el primer escalón.",
    remediation: {
      summary: "Revisá los reportes rua y subí la política a quarantine y luego reject.",
    },
  });
  return { points: 12, detail: dmarc.detail, findings };
}

// --- HTTP Headers (30 pts) ---
interface HeaderMeta {
  weight: number;
  /** Severidad cuando el header falta por completo. */
  missingSeverity: Severity;
  label: string;
  example: string;
}

const HEADER_META: Record<string, HeaderMeta> = {
  "strict-transport-security": {
    weight: 10,
    missingSeverity: "high",
    label: "HSTS",
    example: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
  },
  "content-security-policy": {
    weight: 10,
    missingSeverity: "high",
    label: "Content-Security-Policy",
    example: "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'",
  },
  "x-content-type-options": {
    weight: 4,
    missingSeverity: "medium",
    label: "X-Content-Type-Options",
    example: "X-Content-Type-Options: nosniff",
  },
  "x-frame-options": {
    weight: 4,
    missingSeverity: "medium",
    label: "X-Frame-Options",
    example: "X-Frame-Options: SAMEORIGIN",
  },
  "referrer-policy": {
    weight: 1,
    missingSeverity: "low",
    label: "Referrer-Policy",
    example: "Referrer-Policy: strict-origin-when-cross-origin",
  },
  "permissions-policy": {
    weight: 1,
    missingSeverity: "low",
    label: "Permissions-Policy",
    example: "Permissions-Policy: geolocation=(), camera=(), microphone=()",
  },
};

function downgrade(sev: Severity): Severity {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const i = order.indexOf(sev);
  return order[Math.min(i + 1, order.length - 1)];
}

export function scoreHeaders(headers: HeadersResult): { points: number; detail: string; findings: Finding[] } {
  const findings: Finding[] = [];
  let points = 0;

  // ¿La CSP ya cubre clickjacking con frame-ancestors? Si es así, la ausencia
  // de X-Frame-Options es de bajo riesgo (solo afecta navegadores antiguos).
  const csp = headers.checks?.["content-security-policy"]?.value ?? "";
  const cspHasFrameAncestors = /frame-ancestors/i.test(csp);

  for (const [name, meta] of Object.entries(HEADER_META)) {
    const check = headers.checks?.[name];

    if (check?.verdict === "strong") {
      points += meta.weight;
      continue;
    }

    if (check?.verdict === "weak") {
      points += Math.floor(meta.weight / 2);
      findings.push({
        id: `header-weak-${name}`,
        category: "headers",
        severity: downgrade(meta.missingSeverity),
        title: `${meta.label} presente pero débil`,
        impact: check.detail,
        remediation: {
          summary: `Reforzá ${meta.label} con una configuración estricta.`,
          example: meta.example,
        },
      });
      continue;
    }

    // missing
    let severity = meta.missingSeverity;
    let impact = `${meta.label} no está configurado.`;
    if (name === "x-frame-options" && cspHasFrameAncestors) {
      severity = "low";
      impact =
        "X-Frame-Options ausente, pero la CSP ya define frame-ancestors (el reemplazo moderno). Solo afecta navegadores muy antiguos.";
    }
    findings.push({
      id: `header-missing-${name}`,
      category: "headers",
      severity,
      title: `Header ${meta.label} ausente`,
      impact,
      remediation: {
        summary: `Agregá el header ${meta.label} en las respuestas del servidor.`,
        example: meta.example,
      },
    });
  }

  const detail = `${headers.headers?.found?.length ?? 0}/6 headers presentes. Puntos: ${points}/30.`;
  return { points, detail, findings };
}

// --- Modelo de score normalizado ---
// Cada control aporta earned/max. Lo que no aplica (applicable=false) se excluye
// de ambos lados, así el score es justo y siempre queda en 0-100:
//   score = round( sum(earned aplicables) / sum(max aplicables) * 100 )
type ScoreDetails = SecurityScoreResult["details"];

export function buildScoreItems(d: ScoreDetails, hasMx: boolean, isLocal = false): ScoreItem[] {
  const items: ScoreItem[] = [];
  const add = (
    key: string,
    label: string,
    group: ScoreGroup,
    earned: number,
    max: number,
    applicable = true
  ) => items.push({ key, label, group, earned, max, applicable });

  // ---- TLS / Certificados ----
  const sslEarned =
    d.ssl.verdict === "strong"
      ? 18
      : d.ssl.verdict === "weak"
        ? d.ssl.protocol === "TLSv1" || d.ssl.protocol === "TLSv1.1"
          ? 10
          : 13
        : 0;
  // En local, un servidor http-only (verdict error) o un cert autofirmado
  // (verdict invalid) es lo esperado en desarrollo: no penaliza el score.
  const sslApplicable = !isLocal || d.ssl.verdict === "strong" || d.ssl.verdict === "weak";
  add("ssl", "Certificado SSL/TLS", "tls", sslEarned, 18, sslApplicable);

  const redirect = d.webExtras.httpsRedirect.verdict;
  // El redirect http→https no aplica a un dev server local.
  add("https-redirect", "Redirect HTTP→HTTPS", "tls", redirect === "strong" ? 5 : 0, 5, redirect !== "error" && !isLocal);

  // CAA es gobernanza de CAs públicas: no aplica a localhost.
  add("caa", "CAA", "tls", d.domainInfo.caa.verdict === "present" ? 3 : 0, 3, !isLocal);

  // ---- Email (todo el grupo se excluye si el dominio no tiene MX) ----
  const dmarcPts =
    d.spfDmarc.dmarc.verdict === "strong"
      ? 12
      : d.spfDmarc.dmarc.policy === "quarantine"
        ? 9
        : d.spfDmarc.dmarc.verdict === "weak"
          ? 5
          : 0;
  add("dmarc", "DMARC", "email", dmarcPts, 12, hasMx);

  const spfPts =
    d.spfDmarc.spf.verdict === "strong"
      ? 9
      : d.spfDmarc.spf.qualifier === "~all"
        ? 7
        : d.spfDmarc.spf.verdict === "weak"
          ? 4
          : 0;
  add("spf", "SPF", "email", spfPts, 9, hasMx);

  // DKIM: solo suma cuando lo detectamos. 'unknown' se excluye (no penaliza).
  add("dkim", "DKIM", "email", d.dkim.verdict === "found" ? 5 : 0, 5, hasMx && d.dkim.verdict === "found");

  const mtaPts =
    d.emailExtras.mtaSts.verdict === "strong" ? 2 : d.emailExtras.mtaSts.verdict === "weak" ? 1 : 0;
  add("mta-sts", "MTA-STS", "email", mtaPts, 2, hasMx);
  add("tls-rpt", "TLS-RPT", "email", d.emailExtras.tlsRpt.verdict === "present" ? 1 : 0, 1, hasMx);
  add("bimi", "BIMI", "email", d.emailExtras.bimi.verdict === "present" ? 1 : 0, 1, hasMx);

  // ---- Web / Headers ----
  const hv = (name: string) => d.headers.checks?.[name]?.verdict;
  const headerPts = (name: string, strong: number, weak: number) => {
    const v = hv(name);
    return v === "strong" ? strong : v === "weak" ? weak : 0;
  };
  add("hsts", "HSTS", "web", headerPts("strict-transport-security", 7, 3), 7);
  add("csp", "CSP", "web", headerPts("content-security-policy", 7, 3), 7);
  add("x-content-type", "X-Content-Type-Options", "web", headerPts("x-content-type-options", 3, 1), 3);

  // X-Frame-Options: si falta pero la CSP cubre con frame-ancestors, damos crédito completo.
  const cspVal = d.headers.checks?.["content-security-policy"]?.value ?? "";
  const cspFrameAncestors = /frame-ancestors/i.test(cspVal);
  const xfoV = hv("x-frame-options");
  const xfoPts = xfoV === "strong" ? 3 : xfoV === "weak" ? 1 : cspFrameAncestors ? 3 : 0;
  add("x-frame", "X-Frame-Options", "web", xfoPts, 3);

  add("referrer", "Referrer-Policy", "web", headerPts("referrer-policy", 1, 0), 1);
  add("permissions", "Permissions-Policy", "web", headerPts("permissions-policy", 1, 0), 1);

  // Cookies: si el sitio no setea ninguna, no aplica.
  const ck = d.webExtras.cookies.verdict;
  add("cookies", "Cookies seguras", "web", ck === "strong" ? 4 : ck === "weak" ? 2 : 0, 4, ck !== "none");

  const corsV = d.cors.verdict;
  const corsPts = corsV === "none" || corsV === "safe" ? 3 : corsV === "permissive" ? 2 : 0;
  add("cors", "CORS", "web", corsPts, 3, corsV !== "error");

  // security.txt es un canal público de reporte: no tiene sentido en localhost.
  add("security-txt", "security.txt", "web", d.webExtras.securityTxt.verdict === "present" ? 1 : 0, 1, !isLocal);

  // ---- DNS (todo el grupo depende de presencia pública: se excluye en local) ----
  const dnssec = d.domainInfo.registration.dnssec;
  add("dnssec", "DNSSEC", "dns", dnssec ? 6 : 0, 6, dnssec != null && !isLocal);

  const days = d.domainInfo.registration.daysUntilExpiry;
  const expiryPts = days == null ? 0 : days > 60 ? 3 : days > 30 ? 1 : 0;
  add("domain-expiry", "Expiración del dominio", "dns", expiryPts, 3, days != null && !isLocal);

  const hasIpv6 = !!(d.dns.records.AAAA && d.dns.records.AAAA.length > 0);
  add("ipv6", "IPv6", "dns", hasIpv6 ? 2 : 0, 2, !isLocal);

  return items;
}

function summarizeGroup(items: ScoreItem[], group: ScoreGroup): CategoryScore {
  const applicable = items.filter((i) => i.group === group && i.applicable);
  const max = applicable.reduce((s, i) => s + i.max, 0);
  const points = applicable.reduce((s, i) => s + i.earned, 0);
  return {
    points,
    max,
    percentage: max > 0 ? Math.round((points / max) * 100) : 0,
    applicable: applicable.length > 0,
  };
}

export async function securityScore(input: string): Promise<SecurityScoreResult> {
  const target = parseTarget(input);
  const domain = target.hostPort;
  const isLocal = target.isLocal;

  // Los controles basados en DNS/RDAP (SPF, DMARC, DKIM, email avanzado, CAA,
  // DNSSEC, expiración) no aplican a un target local: localhost / IP privada no
  // tienen presencia pública en DNS ni registro. Los omitimos por completo (sin
  // llamadas externas que filtren "localhost") y usamos resultados neutros.
  const NA = "No aplica en un target local.";
  let dns: DnsLookupResult = { domain, records: {} };
  let spfDmarc: SpfDmarcResult = {
    domain,
    spf: { exists: false, verdict: "missing", detail: NA },
    dmarc: { exists: false, verdict: "missing", detail: NA },
  };
  let dkim: DkimResult = {
    domain, found: [], selectorsProbed: 0, verdict: "unknown", detail: NA, findings: [],
  };
  let emailExtras: EmailExtrasResult = {
    domain, hasMx: false,
    mtaSts: { exists: false, verdict: "missing", detail: NA },
    tlsRpt: { exists: false, verdict: "missing", detail: NA },
    bimi: { exists: false, hasVmc: false, verdict: "missing", detail: NA },
    findings: [],
  };
  let domainInfo: DomainInfoResult = {
    domain,
    caa: { exists: false, issuers: [], verdict: "missing", detail: NA },
    registration: { available: false, detail: NA },
    findings: [],
  };

  if (!isLocal) {
    // Resolvemos DNS primero para saber si el dominio tiene MX (correo): eso
    // define si los controles de email avanzado aplican de verdad.
    dns = await dnsLookup(input);
  }
  const hasMx = !isLocal && !!(dns.records.MX && dns.records.MX.length > 0);

  // Los checks HTTP/SSL siempre corren contra el target (local o público).
  let ssl: SslResult;
  let headers: HeadersResult;
  let cors: CorsResult;
  let webExtras: WebExtrasResult;

  if (isLocal) {
    [ssl, headers, cors, webExtras] = await Promise.all([
      sslCheck(input),
      headersCheck(input),
      corsCheck(input),
      webExtrasCheck(input),
    ]);
  } else {
    [spfDmarc, dkim, emailExtras, domainInfo, ssl, headers, cors, webExtras] =
      await Promise.all([
        spfDmarcCheck(input),
        dkimCheck(input),
        emailExtrasCheck(input, hasMx),
        domainInfoCheck(input),
        sslCheck(input),
        headersCheck(input),
        corsCheck(input),
        webExtrasCheck(input),
      ]);
  }

  const findings: Finding[] = [];

  const sslScore = scoreSsl(ssl);
  const spfScore = scoreSpf(spfDmarc.spf, hasMx);
  const dmarcScore = scoreDmarc(spfDmarc.dmarc, domain, hasMx);
  const headersScore = scoreHeaders(headers);

  // En local no reportamos hallazgos de un cert "roto" (http-only/autofirmado):
  // es lo normal en desarrollo y no debe aparecer como problema.
  const includeSslFindings =
    !isLocal || (ssl.verdict !== "error" && ssl.verdict !== "invalid");

  findings.push(
    ...(includeSslFindings ? sslScore.findings : []),
    // SPF/DMARC solo aplican a dominios públicos con correo.
    ...(isLocal ? [] : spfScore.findings),
    ...(isLocal ? [] : dmarcScore.findings),
    ...headersScore.findings,
    // DKIM y CORS aportan sus propios findings (DKIM es informativo; CORS
    // solo genera hallazgos cuando hay misconfiguración). En local, dkim/email/
    // domainInfo son neutros y no aportan findings.
    ...dkim.findings,
    ...cors.findings,
    // Controles de email avanzado (MTA-STS, TLS-RPT, BIMI): low/info, no
    // afectan el puntaje numérico pero sí aparecen en el reporte.
    ...emailExtras.findings,
    // CAA, DNSSEC y expiración del dominio.
    ...domainInfo.findings,
    // Web extra: redirect HTTPS, flags de cookies, security.txt.
    ...webExtras.findings
  );

  // DNS: hallazgos informativos de baja severidad (solo para dominios públicos).
  if (!isLocal && (!dns.records.AAAA || dns.records.AAAA.length === 0)) {
    findings.push({
      id: "dns-no-ipv6",
      category: "dns",
      severity: "info",
      title: "Sin registro AAAA (IPv6)",
      impact: "El dominio no resuelve por IPv6. No es un problema de seguridad, sí de alcance.",
    });
  }
  if (dns.records.MX && dns.records.MX.length === 1) {
    findings.push({
      id: "dns-single-mx",
      category: "dns",
      severity: "low",
      title: "MX único sin failover",
      impact: "Hay un solo servidor MX. Si cae, no hay relay alternativo para recibir correo.",
      remediation: { summary: "Agregá un MX secundario con prioridad mayor para redundancia." },
    });
  }

  // Los scoreSsl/Spf/Dmarc/Headers de arriba solo se usan para generar findings.
  // El número del score sale del modelo normalizado por control.
  const details = { dns, spfDmarc, dkim, emailExtras, domainInfo, ssl, headers, cors, webExtras };
  const scoreItems = buildScoreItems(details, hasMx, isLocal);

  const applicable = scoreItems.filter((i) => i.applicable);
  const earnedTotal = applicable.reduce((s, i) => s + i.earned, 0);
  const maxTotal = applicable.reduce((s, i) => s + i.max, 0);
  let percentage = maxTotal > 0 ? Math.round((earnedTotal / maxTotal) * 100) : 0;

  // Penalización dura por CORS peligroso: es un riesgo crítico cuyo peso normal
  // (3 pts) subestima el impacto real, así que descuenta directo del score final.
  const corsPenalty = cors.verdict === "dangerous" ? 15 : 0;
  percentage = Math.max(0, percentage - corsPenalty);

  const maxScore = 100;

  return {
    domain,
    score: percentage,
    maxScore,
    percentage,
    risk: calculateRisk(percentage),
    breakdown: {
      tls: summarizeGroup(scoreItems, "tls"),
      email: summarizeGroup(scoreItems, "email"),
      web: summarizeGroup(scoreItems, "web"),
      dns: summarizeGroup(scoreItems, "dns"),
    },
    penalties: { cors: corsPenalty },
    scoreItems,
    findings: sortFindings(findings),
    summary: countBySeverity(findings),
    details,
    generatedAt: new Date().toISOString(),
  };
}
