import * as https from "node:https";
import * as http from "node:http";

export interface HeadersResult {
  domain: string;
  url: string;
  statusCode?: number;
  headers: {
    found: string[];
    missing: string[];
  };
  checks: {
    [header: string]: {
      present: boolean;
      value?: string;
      verdict: "strong" | "weak" | "missing";
      detail: string;
    };
  };
  verdict: "strong" | "weak" | "critical" | "error";
  detail: string;
}

// Headers de seguridad que deberían estar presentes
const SECURITY_HEADERS: Record<string, string> = {
  "strict-transport-security": "HSTS",
  "content-security-policy": "CSP",
  "x-content-type-options": "X-Content-Type-Options",
  "x-frame-options": "X-Frame-Options",
  "referrer-policy": "Referrer-Policy",
  "permissions-policy": "Permissions-Policy",
};

function evaluateHeader(name: string, value: string | undefined): {
  verdict: "strong" | "weak" | "missing";
  detail: string;
} {
  if (!value) {
    return {
      verdict: "missing",
      detail: `${SECURITY_HEADERS[name]} no está configurado.`,
    };
  }

  switch (name) {
    case "strict-transport-security": {
      const maxAge = value.match(/max-age=(\d+)/);
      const seconds = maxAge ? parseInt(maxAge[1]) : 0;
      const days = Math.floor(seconds / 86400);
      if (seconds >= 31536000) {
        return { verdict: "strong", detail: `HSTS activo por ${days} días${value.includes("includeSubDomains") ? ", incluye subdominios" : ""}.` };
      }
      return { verdict: "weak", detail: `HSTS presente pero max-age bajo (${days} días). Recomendado: mínimo 365 días.` };
    }

    case "content-security-policy": {
      if (value.includes("unsafe-inline") || value.includes("unsafe-eval")) {
        return { verdict: "weak", detail: "CSP presente pero usa 'unsafe-inline' o 'unsafe-eval', lo que debilita la protección contra XSS." };
      }
      return { verdict: "strong", detail: "CSP configurado sin directivas inseguras." };
    }

    case "x-content-type-options": {
      return value.toLowerCase() === "nosniff"
        ? { verdict: "strong", detail: "Protección contra MIME sniffing activa." }
        : { verdict: "weak", detail: `Valor incorrecto: '${value}'. Debe ser 'nosniff'.` };
    }

    case "x-frame-options": {
      const upper = value.toUpperCase();
      if (upper === "DENY" || upper === "SAMEORIGIN") {
        return { verdict: "strong", detail: `Protección contra clickjacking activa (${value}).` };
      }
      return { verdict: "weak", detail: `Valor no estándar: '${value}'. Usar DENY o SAMEORIGIN.` };
    }

    case "referrer-policy": {
      const strong = ["no-referrer", "strict-origin", "strict-origin-when-cross-origin"];
      const isStrong = strong.some(p => value.toLowerCase().includes(p));
      return isStrong
        ? { verdict: "strong", detail: `Referrer-Policy configurada correctamente (${value}).` }
        : { verdict: "weak", detail: `Referrer-Policy presente pero permisiva (${value}). Recomendado: strict-origin-when-cross-origin.` };
    }

    case "permissions-policy": {
      return { verdict: "strong", detail: "Permissions-Policy presente — controla acceso a APIs del browser." };
    }

    default:
      return { verdict: "weak", detail: "Header presente pero sin evaluación específica." };
  }
}

export async function headersCheck(domain: string): Promise<HeadersResult> {
  const url = `https://${domain}`;

  return new Promise((resolve) => {
    const req = https.request(
      url,
      {
        method: "GET",
        timeout: 8000,
        headers: { "User-Agent": "Mozilla/5.0 (compatible; mcp-securix/1.0)" },
      },
      (res) => {
        const responseHeaders = res.headers;
        const checks: HeadersResult["checks"] = {};
        const found: string[] = [];
        const missing: string[] = [];

        for (const [headerName] of Object.entries(SECURITY_HEADERS)) {
          const value = responseHeaders[headerName] as string | undefined;
          const evaluation = evaluateHeader(headerName, value);
          checks[headerName] = {
            present: !!value,
            value,
            ...evaluation,
          };
          if (value) {
            found.push(headerName);
          } else {
            missing.push(headerName);
          }
        }

        // Verdict general basado en ausencias y debilidades
        const missingCount = missing.length;
        const criticalMissing = ["strict-transport-security", "content-security-policy"];
        const hasCriticalMissing = criticalMissing.some(h => missing.includes(h));

        let verdict: HeadersResult["verdict"];
        let detail: string;

        if (missingCount >= 4 || hasCriticalMissing) {
          verdict = "critical";
          detail = `${missingCount} de ${Object.keys(SECURITY_HEADERS).length} headers de seguridad ausentes. Headers críticos faltantes: ${criticalMissing.filter(h => missing.includes(h)).join(", ")}.`;
        } else if (missingCount >= 2) {
          verdict = "weak";
          detail = `${missingCount} headers de seguridad ausentes. Configuración incompleta.`;
        } else {
          verdict = "strong";
          detail = `Headers de seguridad correctamente configurados. Solo ${missingCount} ausente(s).`;
        }

        resolve({
          domain,
          url,
          statusCode: res.statusCode,
          headers: { found, missing },
          checks,
          verdict,
          detail,
        });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      resolve({
        domain,
        url,
        headers: { found: [], missing: Object.keys(SECURITY_HEADERS) },
        checks: {},
        verdict: "error",
        detail: "Timeout al conectar al servidor.",
      });
    });

    req.on("error", (err) => {
      resolve({
        domain,
        url,
        headers: { found: [], missing: Object.keys(SECURITY_HEADERS) },
        checks: {},
        verdict: "error",
        detail: `Error de conexión: ${err.message}`,
      });
    });

    req.end();
  });
}