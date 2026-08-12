import type { SecurityScoreResult } from "../score/engine.js";
import type { Finding, Severity } from "../findings.js";

// Generador de reporte HTML autocontenido y determinístico. La ventaja frente
// a dejar que el modelo dibuje: el score, el gauge y las barras salen SIEMPRE
// igual, porque el markup lo controla el código.

const RISK_COLOR: Record<SecurityScoreResult["risk"], string> = {
  low: "#16a34a",
  medium: "#d97706",
  high: "#ea580c",
  critical: "#dc2626",
};

const RISK_LABEL: Record<SecurityScoreResult["risk"], string> = {
  low: "RIESGO BAJO",
  medium: "RIESGO MEDIO",
  high: "RIESGO ALTO",
  critical: "RIESGO CRÍTICO",
};

const SEVERITY_STYLE: Record<Severity, { bg: string; fg: string; label: string }> = {
  critical: { bg: "#fdecea", fg: "#a01b1b", label: "CRÍTICO" },
  high: { bg: "#fdeee4", fg: "#a8460f", label: "ALTO" },
  medium: { bg: "#fdf3e2", fg: "#8a5a06", label: "MEDIO" },
  low: { bg: "#eef2f6", fg: "#4b5563", label: "BAJO" },
  info: { bg: "#eef2f6", fg: "#4b5563", label: "INFO" },
};

function esc(s: unknown): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function code(s: unknown): string {
  return `<code style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:#f1f3f5;color:#374151;padding:1px 5px;border-radius:4px;">${esc(s)}</code>`;
}

/** Barra de progreso para el desglose por categoría. */
function bar(label: string, points: number, max: number): string {
  const ratio = max > 0 ? points / max : 0;
  const pct = Math.round(ratio * 100);
  const color = ratio >= 0.8 ? "#16a34a" : ratio >= 0.5 ? "#d97706" : "#dc2626";
  return `
    <div style="margin-bottom:12px;">
      <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px;">
        <span style="color:#374151;">${esc(label)}</span>
        <span style="font-weight:600;color:${color};">${points} / ${max}</span>
      </div>
      <div style="background:#e5e7eb;border-radius:6px;height:7px;overflow:hidden;">
        <div style="background:${color};width:${pct}%;height:7px;border-radius:6px;"></div>
      </div>
    </div>`;
}

/** Tarjeta de estado compacta para cada control. */
function statusCard(
  title: string,
  badge: string,
  badgeColor: string,
  lines: string[]
): string {
  return `
    <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:14px 16px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <span style="font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.03em;">${esc(title)}</span>
        <span style="margin-left:auto;font-size:10px;font-weight:600;background:${badgeColor}1a;color:${badgeColor};border-radius:5px;padding:2px 8px;">${esc(badge)}</span>
      </div>
      ${lines.map((l) => `<p style="font-size:13px;color:#4b5563;margin:0 0 3px;">${l}</p>`).join("")}
    </div>`;
}

/** Chip de control de email avanzado: verde=óptimo, amarillo=presente-mejorable, gris=ausente. */
function emailChip(label: string, optimal: boolean, present: boolean): string {
  const color = optimal ? "#16a34a" : present ? "#d97706" : "#9ca3af";
  const mark = present ? (optimal ? "✓" : "±") : "✕";
  return `<span style="display:inline-flex;align-items:center;gap:6px;font-size:13px;color:#4b5563;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:6px 12px;"><span style="color:${color};font-weight:700;">${mark}</span>${esc(label)}</span>`;
}

function findingRow(f: Finding): string {
  const s = SEVERITY_STYLE[f.severity];
  const rem = f.remediation;
  const example = rem?.example
    ? `<div style="margin-top:6px;background:#0f172a;color:#e2e8f0;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;padding:8px 10px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;">${esc(rem.example)}</div>`
    : "";
  const fix = rem?.summary
    ? `<p style="font-size:12px;color:#6b7280;margin:4px 0 0;"><strong style="color:#374151;">Cómo:</strong> ${esc(rem.summary)}</p>`
    : "";
  return `
    <div style="padding:12px 0;border-bottom:1px solid #eef2f6;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span style="font-size:10px;font-weight:700;background:${s.bg};color:${s.fg};border-radius:5px;padding:2px 8px;">${s.label}</span>
        <span style="font-size:14px;font-weight:600;color:#111827;">${esc(f.title)}</span>
      </div>
      <p style="font-size:13px;color:#4b5563;margin:0;">${esc(f.impact)}</p>
      ${fix}
      ${example}
    </div>`;
}

export function renderReport(r: SecurityScoreResult): string {
  const riskColor = RISK_COLOR[r.risk];
  const { ssl, spfDmarc, dkim, emailExtras, domainInfo, headers, cors, dns } = r.details;

  // Gauge circular del score.
  const radius = 54;
  const circ = 2 * Math.PI * radius;
  const offset = circ * (1 - r.percentage / 100);
  const gauge = `
    <div style="position:relative;width:132px;height:132px;flex-shrink:0;">
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle cx="66" cy="66" r="${radius}" fill="none" stroke="#e5e7eb" stroke-width="10"/>
        <circle cx="66" cy="66" r="${radius}" fill="none" stroke="${riskColor}" stroke-width="10"
          stroke-dasharray="${circ.toFixed(1)}" stroke-dashoffset="${offset.toFixed(1)}"
          stroke-linecap="round" transform="rotate(-90 66 66)"/>
      </svg>
      <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;">
        <span style="font-size:38px;font-weight:700;color:${riskColor};line-height:1;">${r.score}</span>
        <span style="font-size:13px;color:#9ca3af;">/ ${r.maxScore}</span>
      </div>
    </div>`;

  // Tarjetas de estado.
  const sslExpiry =
    ssl.daysUntilExpiry != null ? `Vence en ${ssl.daysUntilExpiry} días` : "—";
  const cards = [
    statusCard(
      "SSL / TLS",
      ssl.verdict,
      ssl.verdict === "strong" ? "#16a34a" : "#d97706",
      [
        `Emisor: ${esc(ssl.issuer?.organization ?? "—")}`,
        `Protocolo: ${esc(ssl.protocol ?? "—")}`,
        esc(sslExpiry),
      ]
    ),
    statusCard(
      "SPF",
      spfDmarc.spf.verdict,
      spfDmarc.spf.verdict === "strong" ? "#16a34a" : "#d97706",
      [
        `Presente: <strong>${spfDmarc.spf.exists ? "sí" : "no"}</strong>`,
        spfDmarc.spf.qualifier ? `Calificador: ${code(spfDmarc.spf.qualifier)}` : "Sin calificador",
      ]
    ),
    statusCard(
      "DMARC",
      spfDmarc.dmarc.verdict,
      spfDmarc.dmarc.verdict === "strong"
        ? "#16a34a"
        : spfDmarc.dmarc.verdict === "missing"
          ? "#dc2626"
          : "#d97706",
      [
        `Presente: <strong>${spfDmarc.dmarc.exists ? "sí" : "no"}</strong>`,
        spfDmarc.dmarc.policy ? `Política: ${code("p=" + spfDmarc.dmarc.policy)}` : "Sin política",
      ]
    ),
    statusCard(
      "DKIM",
      dkim.verdict === "found" ? "detectado" : "no detectado",
      dkim.verdict === "found" ? "#16a34a" : "#6b7280",
      [
        dkim.verdict === "found"
          ? `Selectores: ${esc(dkim.found.map((f) => f.selector).join(", "))}`
          : "Sin selectores comunes (puede usar uno propio)",
      ]
    ),
  ].join("");

  // Headers: chips de presentes/ausentes.
  const headerChips = Object.entries(headers.checks ?? {})
    .map(([name, c]) => {
      const color = c.verdict === "strong" ? "#16a34a" : c.verdict === "weak" ? "#d97706" : "#dc2626";
      const mark = c.verdict === "missing" ? "✕" : "✓";
      return `<span style="display:inline-flex;align-items:center;gap:5px;font-size:12px;color:#4b5563;background:#ffffff;border:1px solid #e5e7eb;border-radius:6px;padding:5px 9px;"><span style="color:${color};font-weight:700;">${mark}</span>${esc(name)}</span>`;
    })
    .join("");
  const headersNote = headers.finalUrl && headers.redirectChain
    ? `<p style="font-size:12px;color:#9ca3af;margin:10px 0 0;">Evaluado en ${code(headers.finalUrl)} tras seguir ${headers.redirectChain.length} redirect(s).</p>`
    : "";

  // DNS.
  const aRecords = (dns.records.A ?? []).map((ip) => code(ip)).join(" ") || "—";
  const nsRecords = (dns.records.NS ?? []).map((ns) => code(ns)).join(" ") || "—";
  const mxRecords =
    (dns.records.MX ?? []).map((mx) => `${code(mx.exchange)} <span style="color:#9ca3af;">(prio ${mx.priority})</span>`).join("<br>") || "—";
  const ipv6 = dns.records.AAAA && dns.records.AAAA.length > 0 ? "Configurado" : "No configurado";

  // Findings agrupados por severidad.
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const findingsHtml = order
    .filter((sev) => r.findings.some((f) => f.severity === sev))
    .map((sev) => r.findings.filter((f) => f.severity === sev).map(findingRow).join(""))
    .join("");

  const generated = new Date(r.generatedAt);
  const dateStr = generated.toLocaleString("es-AR", { dateStyle: "medium", timeStyle: "short" });

  const section = (title: string, body: string) => `
    <p style="font-size:12px;font-weight:700;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;margin:22px 0 10px;">${esc(title)}</p>
    ${body}`;

  return `
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:760px;margin:0 auto;background:#f8fafc;color:#111827;padding:22px;border-radius:16px;">

  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:18px;">
    <div>
      <p style="font-size:12px;color:#9ca3af;margin:0 0 2px;">Auditoría de seguridad</p>
      <h1 style="font-size:22px;font-weight:700;margin:0;color:#111827;">${esc(r.domain)}</h1>
    </div>
    <span style="font-size:11px;color:#9ca3af;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;padding:5px 10px;">${esc(dateStr)}</span>
  </div>

  <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:20px;display:flex;align-items:center;gap:24px;flex-wrap:wrap;margin-bottom:6px;">
    <div style="text-align:center;">
      ${gauge}
      <div style="margin-top:8px;"><span style="font-size:11px;font-weight:700;background:${riskColor}1a;color:${riskColor};border-radius:6px;padding:3px 10px;">${RISK_LABEL[r.risk]}</span></div>
    </div>
    <div style="flex:1;min-width:240px;">
      <p style="font-size:12px;color:#6b7280;font-weight:600;margin:0 0 12px;">Desglose por categoría</p>
      ${bar("SSL / TLS", r.breakdown.ssl.points, r.breakdown.ssl.max)}
      ${bar("SPF", r.breakdown.spf.points, r.breakdown.spf.max)}
      ${bar("DMARC", r.breakdown.dmarc.points, r.breakdown.dmarc.max)}
      ${bar("HTTP Headers", r.breakdown.headers.points, r.breakdown.headers.max)}
      ${r.penalties.cors > 0 ? `<p style="font-size:12px;color:#dc2626;margin:6px 0 0;">− ${r.penalties.cors} pts por CORS peligroso</p>` : ""}
    </div>
  </div>

  ${section("Estado de los controles", `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;">${cards}</div>`)}

  ${section("Headers HTTP de seguridad", `
    <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;">
      <div style="display:flex;flex-wrap:wrap;gap:8px;">${headerChips || '<span style="font-size:13px;color:#9ca3af;">No se pudieron evaluar los headers.</span>'}</div>
      ${headersNote}
    </div>`)}

  ${section("Infraestructura DNS", `
    <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;">
      <div><p style="font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;margin:0 0 6px;">Registros A</p><p style="margin:0;">${aRecords}</p></div>
      <div><p style="font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;margin:0 0 6px;">Name Servers</p><p style="margin:0;line-height:1.9;">${nsRecords}</p></div>
      <div><p style="font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;margin:0 0 6px;">Correo (MX)</p><p style="margin:0;">${mxRecords}</p></div>
      <div><p style="font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;margin:0 0 6px;">IPv6 (AAAA)</p><p style="margin:0;color:#4b5563;">${esc(ipv6)}</p></div>
    </div>`)}

  ${section("Registro y certificación del dominio", `
    <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;">
      <div><p style="font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;margin:0 0 6px;">Registrador</p><p style="margin:0;color:#4b5563;">${esc(domainInfo.registration.registrar ?? "—")}</p></div>
      <div><p style="font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;margin:0 0 6px;">Expira</p><p style="margin:0;color:#4b5563;">${domainInfo.registration.daysUntilExpiry != null ? esc(domainInfo.registration.daysUntilExpiry + " días") : "—"}</p></div>
      <div><p style="font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;margin:0 0 6px;">DNSSEC</p><p style="margin:0;color:${domainInfo.registration.dnssec ? "#16a34a" : "#d97706"};font-weight:600;">${domainInfo.registration.dnssec == null ? "—" : domainInfo.registration.dnssec ? "Activo" : "No activo"}</p></div>
      <div><p style="font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase;margin:0 0 6px;">CAA</p><p style="margin:0;color:${domainInfo.caa.verdict === "present" ? "#16a34a" : "#d97706"};font-weight:600;">${domainInfo.caa.verdict === "present" ? esc(domainInfo.caa.issuers.join(", ") || "Presente") : "Ausente"}</p></div>
    </div>`)}

  ${section("Email avanzado", `
    <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;display:flex;flex-wrap:wrap;gap:10px;">
      ${emailChip("MTA-STS", emailExtras.mtaSts.verdict === "strong", emailExtras.mtaSts.verdict !== "missing")}
      ${emailChip("TLS-RPT", emailExtras.tlsRpt.verdict === "present", emailExtras.tlsRpt.verdict === "present")}
      ${emailChip("BIMI", emailExtras.bimi.verdict === "present", emailExtras.bimi.verdict === "present")}
      ${!emailExtras.hasMx ? '<p style="margin:0;font-size:12px;color:#9ca3af;width:100%;">El dominio no tiene MX: estos controles son opcionales.</p>' : ""}
    </div>`)}

  ${section("CORS", `
    <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;">
      <p style="margin:0;font-size:13px;color:#4b5563;"><strong style="color:#111827;">${esc(cors.verdict)}</strong> — ${esc(cors.detail)}</p>
    </div>`)}

  ${section("Hallazgos priorizados", `
    <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:4px 16px 12px;">
      ${findingsHtml || '<p style="font-size:13px;color:#16a34a;padding:12px 0;">Sin hallazgos. Configuración sólida.</p>'}
    </div>`)}

  <p style="font-size:12px;color:#9ca3af;margin:18px 0 0;line-height:1.5;">Análisis de configuración externa, no un pentest de la aplicación. No evalúa vulnerabilidades de la app, control de accesos ni el estado interno del servidor de correo.</p>

</div>`.trim();
}
