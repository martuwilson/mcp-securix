import { test } from "node:test";
import assert from "node:assert/strict";
import { renderReport } from "../tools/report/html.js";
import type { SecurityScoreResult } from "../tools/score/engine.js";

// Resultado sintético mínimo pero completo para probar el render.
function fakeResult(): SecurityScoreResult {
  return {
    domain: "ejemplo.com",
    score: 65,
    maxScore: 100,
    percentage: 65,
    risk: "medium",
    breakdown: {
      ssl: { points: 25, max: 25, detail: "" },
      spf: { points: 16, max: 20, detail: "" },
      dmarc: { points: 0, max: 25, detail: "" },
      headers: { points: 24, max: 30, detail: "" },
    },
    penalties: { cors: 0 },
    findings: [
      {
        id: "dmarc-missing",
        category: "dmarc",
        severity: "high",
        title: "Sin registro DMARC",
        impact: "Vulnerable a spoofing.",
        remediation: { summary: "Publicá DMARC.", example: '_dmarc.ejemplo.com TXT "v=DMARC1; p=none"' },
      },
    ],
    summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    details: {
      dns: { domain: "ejemplo.com", records: { A: ["1.2.3.4"], NS: ["ns1.x.com"], MX: [{ exchange: "mail.x.com", priority: 10 }] } },
      spfDmarc: {
        domain: "ejemplo.com",
        spf: { exists: true, qualifier: "~all", verdict: "weak", detail: "" },
        dmarc: { exists: false, verdict: "missing", detail: "" },
      },
      dkim: { domain: "ejemplo.com", found: [], selectorsProbed: 15, verdict: "unknown", detail: "", findings: [] },
      emailExtras: {
        domain: "ejemplo.com",
        hasMx: true,
        mtaSts: { exists: false, verdict: "missing", detail: "" },
        tlsRpt: { exists: false, verdict: "missing", detail: "" },
        bimi: { exists: false, hasVmc: false, verdict: "missing", detail: "" },
        findings: [],
      },
      domainInfo: {
        domain: "ejemplo.com",
        caa: { exists: false, issuers: [], verdict: "missing", detail: "" },
        registration: { available: false, registrar: "Test Registrar", daysUntilExpiry: 300, dnssec: false, detail: "" },
        findings: [],
      },
      ssl: { domain: "ejemplo.com", valid: true, verdict: "strong", detail: "", issuer: { organization: "Let's Encrypt" }, protocol: "TLSv1.3", daysUntilExpiry: 60 },
      headers: {
        domain: "ejemplo.com",
        url: "https://ejemplo.com",
        headers: { found: ["strict-transport-security"], missing: [] },
        checks: { "strict-transport-security": { present: true, value: "max-age=31536000", verdict: "strong", detail: "" } },
        verdict: "strong",
        detail: "",
      },
      cors: { domain: "ejemplo.com", url: "https://ejemplo.com", probeOrigin: "x", verdict: "none", detail: "Sin CORS", findings: [] },
      webExtras: {
        domain: "ejemplo.com",
        httpsRedirect: { redirects: true, verdict: "strong", detail: "" },
        cookies: { count: 0, cookies: [], verdict: "none", detail: "" },
        securityTxt: { exists: false, verdict: "missing", detail: "" },
        findings: [],
      },
    },
    generatedAt: new Date().toISOString(),
  };
}

test("renderReport incluye el número del score", () => {
  const html = renderReport(fakeResult());
  assert.match(html, /<svg/);
  assert.match(html, />65</);
});

test("renderReport incluye el desglose y las secciones clave", () => {
  const html = renderReport(fakeResult());
  assert.match(html, /Desglose por categoría/);
  assert.match(html, /Hallazgos priorizados/);
  assert.match(html, /Email avanzado/);
  assert.match(html, /RIESGO MEDIO/);
});

test("renderReport muestra el finding y su remediation.example", () => {
  const html = renderReport(fakeResult());
  assert.match(html, /Sin registro DMARC/);
  assert.match(html, /v=DMARC1; p=none/);
});

test("renderReport escapa HTML del dominio (anti-inyección)", () => {
  const r = fakeResult();
  r.domain = "<script>alert(1)</script>";
  const html = renderReport(r);
  assert.ok(!html.includes("<script>alert(1)</script>"));
  assert.match(html, /&lt;script&gt;/);
});
