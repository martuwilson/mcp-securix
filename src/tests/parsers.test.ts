import { test } from "node:test";
import assert from "node:assert/strict";
import { classifySpf, classifyDmarc } from "../tools/dns/spf-dmarc.js";
import { evaluateHeader } from "../tools/http/header.js";
import { evaluateCors } from "../tools/http/cors.js";
import { parseCookie } from "../tools/http/web-extras.js";

test("classifySpf: -all es strong", () => {
  const r = classifySpf("v=spf1 include:_spf.google.com -all");
  assert.equal(r.verdict, "strong");
  assert.equal(r.qualifier, "-all");
});

test("classifySpf: ~all es weak (soft fail)", () => {
  const r = classifySpf("v=spf1 include:amazonses.com ~all");
  assert.equal(r.verdict, "weak");
  assert.equal(r.qualifier, "~all");
});

test("classifySpf: +all es dangerous", () => {
  const r = classifySpf("v=spf1 +all");
  assert.equal(r.verdict, "dangerous");
  assert.equal(r.qualifier, "+all");
});

test("classifySpf: sin calificador all es weak sin qualifier", () => {
  const r = classifySpf("v=spf1 include:example.com");
  assert.equal(r.verdict, "weak");
  assert.equal(r.qualifier, undefined);
});

test("classifyDmarc: p=reject es strong", () => {
  const r = classifyDmarc("v=DMARC1; p=reject; rua=mailto:x@y.com");
  assert.equal(r.verdict, "strong");
  assert.equal(r.policy, "reject");
});

test("classifyDmarc: p=quarantine es weak", () => {
  const r = classifyDmarc("v=DMARC1; p=quarantine");
  assert.equal(r.verdict, "weak");
  assert.equal(r.policy, "quarantine");
});

test("classifyDmarc: p=none es weak", () => {
  const r = classifyDmarc("v=DMARC1; p=none");
  assert.equal(r.verdict, "weak");
  assert.equal(r.policy, "none");
});

test("evaluateHeader: HSTS con max-age largo es strong", () => {
  const r = evaluateHeader("strict-transport-security", "max-age=31536000; includeSubDomains");
  assert.equal(r.verdict, "strong");
});

test("evaluateHeader: HSTS con max-age bajo es weak", () => {
  const r = evaluateHeader("strict-transport-security", "max-age=3600");
  assert.equal(r.verdict, "weak");
});

test("evaluateHeader: CSP con unsafe-inline es weak", () => {
  const r = evaluateHeader("content-security-policy", "default-src 'self' 'unsafe-inline'");
  assert.equal(r.verdict, "weak");
});

test("evaluateHeader: header ausente es missing", () => {
  const r = evaluateHeader("content-security-policy", undefined);
  assert.equal(r.verdict, "missing");
});

test("evaluateCors: refleja origen arbitrario con credenciales es dangerous", () => {
  const r = evaluateCors("x.com", "https://evil.mcp-securix-probe.example", "true");
  assert.equal(r.verdict, "dangerous");
  assert.equal(r.findings[0]?.severity, "critical");
});

test("evaluateCors: sin headers CORS es none (default seguro)", () => {
  const r = evaluateCors("x.com", undefined, undefined);
  assert.equal(r.verdict, "none");
  assert.equal(r.findings.length, 0);
});

test("evaluateCors: wildcard sin credenciales es permissive (aceptable)", () => {
  const r = evaluateCors("x.com", "*", undefined);
  assert.equal(r.verdict, "permissive");
});

test("parseCookie: extrae flags Secure/HttpOnly/SameSite", () => {
  const c = parseCookie("sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax");
  assert.equal(c.name, "sid");
  assert.equal(c.secure, true);
  assert.equal(c.httpOnly, true);
  assert.equal(c.sameSite, "Lax");
});

test("parseCookie: cookie sin flags", () => {
  const c = parseCookie("tracking=xyz");
  assert.equal(c.secure, false);
  assert.equal(c.httpOnly, false);
  assert.equal(c.sameSite, undefined);
});
