import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreSsl, scoreSpf, scoreDmarc, scoreHeaders, buildScoreItems } from "../tools/score/engine.js";
import type { SecurityScoreResult } from "../tools/score/engine.js";
import { sortFindings, countBySeverity, type Finding } from "../tools/findings.js";
import type { SslResult } from "../tools/ssl/check.js";
import type { SpfResult, DmarcResult } from "../tools/dns/spf-dmarc.js";
import type { HeadersResult } from "../tools/http/header.js";

function ssl(partial: Partial<SslResult>): SslResult {
  return { domain: "x.com", valid: true, verdict: "strong", detail: "", ...partial };
}

test("scoreSsl: strong da 25 puntos y sin findings", () => {
  const r = scoreSsl(ssl({ verdict: "strong", daysUntilExpiry: 200, protocol: "TLSv1.3" }));
  assert.equal(r.points, 25);
  assert.equal(r.findings.length, 0);
});

test("scoreSsl: expirado da 0 y finding critical", () => {
  const r = scoreSsl(ssl({ verdict: "expired", detail: "expirado" }));
  assert.equal(r.points, 0);
  assert.equal(r.findings[0]?.severity, "critical");
});

test("scoreSsl: TLS obsoleto es medium con puntaje parcial", () => {
  const r = scoreSsl(ssl({ verdict: "weak", protocol: "TLSv1.1", daysUntilExpiry: 100 }));
  assert.equal(r.points, 17);
  assert.equal(r.findings[0]?.severity, "medium");
});

test("scoreSpf: ~all (weak) penaliza poco -> 16/20 y finding low", () => {
  const spf: SpfResult = { exists: true, qualifier: "~all", verdict: "weak", detail: "" };
  const r = scoreSpf(spf);
  assert.equal(r.points, 16);
  assert.equal(r.findings[0]?.severity, "low");
});

test("scoreSpf: missing da 0 y finding high", () => {
  const spf: SpfResult = { exists: false, verdict: "missing", detail: "" };
  const r = scoreSpf(spf);
  assert.equal(r.points, 0);
  assert.equal(r.findings[0]?.severity, "high");
});

test("scoreDmarc: reject da 25 sin findings", () => {
  const dmarc: DmarcResult = { exists: true, policy: "reject", verdict: "strong", detail: "" };
  const r = scoreDmarc(dmarc, "x.com");
  assert.equal(r.points, 25);
  assert.equal(r.findings.length, 0);
});

test("scoreDmarc: missing da 0 y remediation con ejemplo del dominio", () => {
  const dmarc: DmarcResult = { exists: false, verdict: "missing", detail: "" };
  const r = scoreDmarc(dmarc, "midominio.com");
  assert.equal(r.points, 0);
  assert.ok(r.findings[0]?.remediation?.example?.includes("midominio.com"));
});

test("scoreDmarc: missing es critical si el dominio tiene MX", () => {
  const dmarc: DmarcResult = { exists: false, verdict: "missing", detail: "" };
  const r = scoreDmarc(dmarc, "x.com", true);
  assert.equal(r.findings[0]?.severity, "critical");
});

test("scoreDmarc: missing es high si el dominio NO tiene MX", () => {
  const dmarc: DmarcResult = { exists: false, verdict: "missing", detail: "" };
  const r = scoreDmarc(dmarc, "x.com", false);
  assert.equal(r.findings[0]?.severity, "high");
});

test("scoreSpf: missing baja a medium si el dominio NO tiene MX", () => {
  const spf: SpfResult = { exists: false, verdict: "missing", detail: "" };
  const r = scoreSpf(spf, false);
  assert.equal(r.findings[0]?.severity, "medium");
});

function headersWith(
  checks: HeadersResult["checks"],
  found: string[]
): HeadersResult {
  return {
    domain: "x.com",
    url: "https://x.com",
    headers: { found, missing: [] },
    checks,
    verdict: "strong",
    detail: "",
  };
}

test("scoreHeaders: X-Frame-Options ausente es low si la CSP tiene frame-ancestors", () => {
  const checks: HeadersResult["checks"] = {
    "content-security-policy": {
      present: true,
      value: "default-src 'self'; frame-ancestors 'self'",
      verdict: "strong",
      detail: "",
    },
  };
  const r = scoreHeaders(headersWith(checks, ["content-security-policy"]));
  const xfo = r.findings.find((f) => f.id === "header-missing-x-frame-options");
  assert.equal(xfo?.severity, "low");
});

test("scoreHeaders: X-Frame-Options ausente es medium sin CSP frame-ancestors", () => {
  const r = scoreHeaders(headersWith({}, []));
  const xfo = r.findings.find((f) => f.id === "header-missing-x-frame-options");
  assert.equal(xfo?.severity, "medium");
});

test("sortFindings ordena critical antes que low", () => {
  const findings: Finding[] = [
    { id: "a", category: "dns", severity: "low", title: "", impact: "" },
    { id: "b", category: "ssl", severity: "critical", title: "", impact: "" },
    { id: "c", category: "spf", severity: "medium", title: "", impact: "" },
  ];
  const sorted = sortFindings(findings);
  assert.deepEqual(sorted.map((f) => f.id), ["b", "c", "a"]);
});

function fakeDetails(): SecurityScoreResult["details"] {
  return {
    dns: { domain: "x.com", records: { A: ["1.2.3.4"], MX: [{ exchange: "m", priority: 10 }] } },
    spfDmarc: {
      domain: "x.com",
      spf: { exists: true, qualifier: "-all", verdict: "strong", detail: "" },
      dmarc: { exists: true, policy: "reject", verdict: "strong", detail: "" },
    },
    dkim: { domain: "x.com", found: [], selectorsProbed: 15, verdict: "unknown", detail: "", findings: [] },
    emailExtras: {
      domain: "x.com", hasMx: true,
      mtaSts: { exists: false, verdict: "missing", detail: "" },
      tlsRpt: { exists: false, verdict: "missing", detail: "" },
      bimi: { exists: false, hasVmc: false, verdict: "missing", detail: "" },
      findings: [],
    },
    domainInfo: {
      domain: "x.com",
      caa: { exists: true, issuers: ["letsencrypt.org"], verdict: "present", detail: "" },
      registration: { available: false, daysUntilExpiry: 300, dnssec: true, detail: "" },
      findings: [],
    },
    ssl: { domain: "x.com", valid: true, verdict: "strong", detail: "", protocol: "TLSv1.3", daysUntilExpiry: 90 },
    headers: { domain: "x.com", url: "https://x.com", headers: { found: [], missing: [] }, checks: {}, verdict: "strong", detail: "" },
    cors: { domain: "x.com", url: "https://x.com", probeOrigin: "x", verdict: "none", detail: "", findings: [] },
    webExtras: {
      domain: "x.com",
      httpsRedirect: { redirects: true, verdict: "strong", detail: "" },
      cookies: { count: 0, cookies: [], verdict: "none", detail: "" },
      securityTxt: { exists: true, verdict: "present", detail: "" },
      findings: [],
    },
  };
}

test("buildScoreItems: sin MX excluye todo el grupo email", () => {
  const items = buildScoreItems(fakeDetails(), false);
  const email = items.filter((i) => i.group === "email");
  assert.ok(email.length > 0);
  assert.ok(email.every((i) => !i.applicable));
});

test("buildScoreItems: con MX el email aplica", () => {
  const items = buildScoreItems(fakeDetails(), true);
  const dmarc = items.find((i) => i.key === "dmarc");
  assert.equal(dmarc?.applicable, true);
  assert.equal(dmarc?.earned, 12);
});

test("buildScoreItems: DKIM unknown se excluye (no penaliza)", () => {
  const items = buildScoreItems(fakeDetails(), true);
  const dkim = items.find((i) => i.key === "dkim");
  assert.equal(dkim?.applicable, false);
});

test("buildScoreItems: cookies 'none' se excluye del cálculo", () => {
  const items = buildScoreItems(fakeDetails(), true);
  const cookies = items.find((i) => i.key === "cookies");
  assert.equal(cookies?.applicable, false);
});

test("buildScoreItems: DNSSEC indeterminado (null) se excluye", () => {
  const d = fakeDetails();
  d.domainInfo.registration.dnssec = undefined;
  const items = buildScoreItems(d, true);
  const dnssec = items.find((i) => i.key === "dnssec");
  assert.equal(dnssec?.applicable, false);
});

test("countBySeverity cuenta bien", () => {
  const findings: Finding[] = [
    { id: "a", category: "dns", severity: "low", title: "", impact: "" },
    { id: "b", category: "ssl", severity: "low", title: "", impact: "" },
    { id: "c", category: "spf", severity: "high", title: "", impact: "" },
  ];
  const counts = countBySeverity(findings);
  assert.equal(counts.low, 2);
  assert.equal(counts.high, 1);
  assert.equal(counts.critical, 0);
});
