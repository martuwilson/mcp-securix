import { dnsLookup, type DnsLookupResult } from "../dns/lookup.js";
import { spfDmarcCheck, type SpfDmarcResult } from "../dns/spf-dmarc.js";
import { dkimCheck, type DkimResult } from "../dns/dkim.js";
import { emailExtrasCheck, type EmailExtrasResult } from "../dns/email-extras.js";
import { sslCheck, type SslResult } from "../ssl/check.js";
import { headersCheck, type HeadersResult } from "../http/header.js";
import { corsCheck, type CorsResult } from "../http/cors.js";
import {
  type Finding,
  type Severity,
  sortFindings,
  countBySeverity,
} from "../findings.js";

export interface CategoryScore {
  points: number;
  max: number;
  detail: string;
}

export interface ScoreBreakdown {
  ssl: CategoryScore;
  spf: CategoryScore;
  dmarc: CategoryScore;
  headers: CategoryScore;
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
    ssl: SslResult;
    headers: HeadersResult;
    cors: CorsResult;
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
function scoreSsl(ssl: SslResult): { points: number; detail: string; findings: Finding[] } {
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
function scoreSpf(spf: SpfDmarcResult["spf"]): { points: number; detail: string; findings: Finding[] } {
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
      severity: "high",
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
function scoreDmarc(dmarc: SpfDmarcResult["dmarc"], domain: string): { points: number; detail: string; findings: Finding[] } {
  const findings: Finding[] = [];

  if (dmarc.verdict === "strong") {
    return { points: 25, detail: "DMARC con p=reject configurado correctamente.", findings };
  }

  if (dmarc.verdict === "missing") {
    findings.push({
      id: "dmarc-missing",
      category: "dmarc",
      severity: "high",
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

function scoreHeaders(headers: HeadersResult): { points: number; detail: string; findings: Finding[] } {
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

export async function securityScore(domain: string): Promise<SecurityScoreResult> {
  // Resolvemos DNS primero para saber si el dominio tiene MX (correo): eso
  // define si los controles de email avanzado aplican de verdad.
  const dns = await dnsLookup(domain);
  const hasMx = !!(dns.records.MX && dns.records.MX.length > 0);

  // El resto corre en paralelo.
  const [spfDmarc, dkim, emailExtras, ssl, headers, cors] = await Promise.all([
    spfDmarcCheck(domain),
    dkimCheck(domain),
    emailExtrasCheck(domain, hasMx),
    sslCheck(domain),
    headersCheck(domain),
    corsCheck(domain),
  ]);

  const findings: Finding[] = [];

  const sslScore = scoreSsl(ssl);
  const spfScore = scoreSpf(spfDmarc.spf);
  const dmarcScore = scoreDmarc(spfDmarc.dmarc, domain);
  const headersScore = scoreHeaders(headers);

  findings.push(
    ...sslScore.findings,
    ...spfScore.findings,
    ...dmarcScore.findings,
    ...headersScore.findings,
    // DKIM y CORS aportan sus propios findings (DKIM es informativo; CORS
    // solo genera hallazgos cuando hay misconfiguración).
    ...dkim.findings,
    ...cors.findings,
    // Controles de email avanzado (MTA-STS, TLS-RPT, BIMI): low/info, no
    // afectan el puntaje numérico pero sí aparecen en el reporte.
    ...emailExtras.findings
  );

  // DNS: hallazgos informativos de baja severidad.
  if (!dns.records.AAAA || dns.records.AAAA.length === 0) {
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

  // Puntaje base sobre las 4 categorías (suma 100).
  const baseScore =
    sslScore.points + spfScore.points + dmarcScore.points + headersScore.points;

  // Penalización por CORS peligroso: es un riesgo crítico que no encaja en las
  // 4 categorías base, así que resta directo (con piso en 0).
  const corsPenalty = cors.verdict === "dangerous" ? 15 : 0;
  const totalScore = Math.max(0, baseScore - corsPenalty);

  const maxScore = 100;
  const percentage = Math.round((totalScore / maxScore) * 100);

  return {
    domain,
    score: totalScore,
    maxScore,
    percentage,
    risk: calculateRisk(percentage),
    breakdown: {
      ssl: { points: sslScore.points, max: 25, detail: sslScore.detail },
      spf: { points: spfScore.points, max: 20, detail: spfScore.detail },
      dmarc: { points: dmarcScore.points, max: 25, detail: dmarcScore.detail },
      headers: { points: headersScore.points, max: 30, detail: headersScore.detail },
    },
    penalties: { cors: corsPenalty },
    findings: sortFindings(findings),
    summary: countBySeverity(findings),
    details: { dns, spfDmarc, dkim, emailExtras, ssl, headers, cors },
    generatedAt: new Date().toISOString(),
  };
}
