import { dnsLookup } from "../dns/lookup.js";
import { spfDmarcCheck } from "../dns/spf-dmarc.js";
import { sslCheck } from "../ssl/check.js";
import { headersCheck } from "../http/header.js";

export interface ScoreBreakdown {
  ssl: {
    points: number;
    max: number;
    detail: string;
  };
  spf: {
    points: number;
    max: number;
    detail: string;
  };
  dmarc: {
    points: number;
    max: number;
    detail: string;
  };
  headers: {
    points: number;
    max: number;
    detail: string;
  };
}

export interface SecurityScoreResult {
  domain: string;
  score: number;
  maxScore: number;
  percentage: number;
  risk: "low" | "medium" | "high" | "critical";
  breakdown: ScoreBreakdown;
  findings: {
    critical: string[];
    high: string[];
    medium: string[];
    low: string[];
  };
  generatedAt: string;
}

function calculateRisk(percentage: number): SecurityScoreResult["risk"] {
  if (percentage >= 80) return "low";
  if (percentage >= 60) return "medium";
  if (percentage >= 40) return "high";
  return "critical";
}

export async function securityScore(domain: string): Promise<SecurityScoreResult> {
  // Correr todas las tools en paralelo
  const [dns, spfDmarc, ssl, headers] = await Promise.all([
    dnsLookup(domain),
    spfDmarcCheck(domain),
    sslCheck(domain),
    headersCheck(domain),
  ]);

  const findings: SecurityScoreResult["findings"] = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };

  // --- SSL (25 puntos) ---
  let sslPoints = 0;
  let sslDetail = "";

  if (ssl.verdict === "strong") {
    sslPoints = 25;
    sslDetail = `Certificado válido, ${ssl.daysUntilExpiry} días hasta expiración, protocolo ${ssl.protocol}.`;
  } else if (ssl.verdict === "weak") {
    sslPoints = 12;
    sslDetail = ssl.detail;
    findings.medium.push(ssl.detail);
  } else if (ssl.verdict === "expired") {
    sslPoints = 0;
    sslDetail = ssl.detail;
    findings.critical.push(ssl.detail);
  } else {
    sslPoints = 0;
    sslDetail = ssl.detail;
    findings.high.push(ssl.detail);
  }

  // --- SPF (20 puntos) ---
  let spfPoints = 0;
  let spfDetail = "";

  if (spfDmarc.spf.verdict === "strong") {
    spfPoints = 20;
    spfDetail = "SPF con -all configurado correctamente.";
  } else if (spfDmarc.spf.verdict === "weak") {
    spfPoints = 10;
    spfDetail = spfDmarc.spf.detail;
    findings.medium.push(spfDmarc.spf.detail);
  } else if (spfDmarc.spf.verdict === "dangerous") {
    spfPoints = 0;
    spfDetail = spfDmarc.spf.detail;
    findings.critical.push(spfDmarc.spf.detail);
  } else {
    spfPoints = 0;
    spfDetail = spfDmarc.spf.detail;
    findings.high.push(spfDmarc.spf.detail);
  }

  // --- DMARC (25 puntos) ---
  let dmarcPoints = 0;
  let dmarcDetail = "";

  if (spfDmarc.dmarc.verdict === "strong") {
    dmarcPoints = 25;
    dmarcDetail = "DMARC con p=reject configurado correctamente.";
  } else if (spfDmarc.dmarc.verdict === "weak") {
    dmarcPoints = 10;
    dmarcDetail = spfDmarc.dmarc.detail;
    findings.high.push(spfDmarc.dmarc.detail);
  } else {
    dmarcPoints = 0;
    dmarcDetail = spfDmarc.dmarc.detail;
    findings.critical.push(spfDmarc.dmarc.detail);
  }

  // --- HTTP Headers (30 puntos) ---
  // HSTS + CSP = críticos = 10 pts cada uno
  // X-Content-Type-Options + X-Frame-Options = 4 pts cada uno
  // Referrer-Policy + Permissions-Policy = 1 pt cada uno
  let headersPoints = 0;
  let headersDetail = "";

  const headerWeights: Record<string, number> = {
    "strict-transport-security": 10,
    "content-security-policy": 10,
    "x-content-type-options": 4,
    "x-frame-options": 4,
    "referrer-policy": 1,
    "permissions-policy": 1,
  };

  for (const [header, weight] of Object.entries(headerWeights)) {
    const check = headers.checks[header];
    if (!check) continue;

    if (check.verdict === "strong") {
      headersPoints += weight;
    } else if (check.verdict === "weak") {
      headersPoints += Math.floor(weight / 2);
      findings.medium.push(`${header}: ${check.detail}`);
    } else {
      // missing
      if (weight >= 10) {
        findings.critical.push(`Header ${header} ausente.`);
      } else if (weight >= 4) {
        findings.high.push(`Header ${header} ausente.`);
      } else {
        findings.low.push(`Header ${header} ausente.`);
      }
    }
  }

  headersDetail = `${headers.headers.found.length}/6 headers presentes. Puntos: ${headersPoints}/30.`;

  // DNS findings adicionales
  if (!dns.records.AAAA || dns.records.AAAA.length === 0) {
    findings.low.push("Sin registro AAAA — dominio no soporta IPv6.");
  }
  if (dns.records.MX && dns.records.MX.length === 1) {
    findings.low.push("MX único sin failover — si el servidor de correo cae, no hay relay alternativo.");
  }

  const totalScore = sslPoints + spfPoints + dmarcPoints + headersPoints;
  const maxScore = 100;
  const percentage = Math.round((totalScore / maxScore) * 100);

  return {
    domain,
    score: totalScore,
    maxScore,
    percentage,
    risk: calculateRisk(percentage),
    breakdown: {
      ssl: { points: sslPoints, max: 25, detail: sslDetail },
      spf: { points: spfPoints, max: 20, detail: spfDetail },
      dmarc: { points: dmarcPoints, max: 25, detail: dmarcDetail },
      headers: { points: headersPoints, max: 30, detail: headersDetail },
    },
    findings,
    generatedAt: new Date().toISOString(),
  };
}