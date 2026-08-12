import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreSsl, scoreSpf, scoreDmarc, scoreHeaders } from "../tools/score/engine.js";
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
