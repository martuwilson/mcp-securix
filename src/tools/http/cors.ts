import { httpGet } from "./fetch.js";
import type { Finding } from "../findings.js";

// Origen claramente ajeno que usamos como "sonda". Si el servidor lo refleja
// en Access-Control-Allow-Origin, está confiando en cualquier origen.
const PROBE_ORIGIN = "https://evil.mcp-securix-probe.example";

export interface CorsResult {
  domain: string;
  url: string;
  statusCode?: number;
  /** Origen que enviamos como sonda. */
  probeOrigin: string;
  accessControlAllowOrigin?: string;
  accessControlAllowCredentials?: string;
  /**
   * - none: no expone headers CORS (default seguro).
   * - safe: CORS presente pero acotado (no refleja nuestra sonda ni usa * con credenciales).
   * - permissive: abierto a cualquier origen sin credenciales (común en APIs/CDN públicos).
   * - dangerous: refleja origen arbitrario CON credenciales, o * con credenciales.
   */
  verdict: "none" | "safe" | "permissive" | "dangerous" | "error";
  detail: string;
  findings: Finding[];
}

function evaluate(
  domain: string,
  acao: string | undefined,
  acac: string | undefined
): { verdict: CorsResult["verdict"]; detail: string; findings: Finding[] } {
  const findings: Finding[] = [];
  const credentials = (acac ?? "").toLowerCase() === "true";
  const reflectsProbe = acao === PROBE_ORIGIN;
  const wildcard = acao === "*";

  if (!acao) {
    return {
      verdict: "none",
      detail:
        "El servidor no devuelve headers CORS para un origen externo. Default seguro: solo el mismo origen puede leer las respuestas.",
      findings,
    };
  }

  // Caso crítico: refleja cualquier origen Y permite credenciales.
  if ((reflectsProbe || wildcard) && credentials) {
    findings.push({
      id: "cors-reflect-credentials",
      category: "cors",
      severity: "critical",
      title: "CORS refleja origen arbitrario con credenciales",
      impact:
        "El servidor acepta cualquier origen (refleja el Origin recibido o usa '*') y además habilita Access-Control-Allow-Credentials. Cualquier sitio malicioso puede hacer peticiones autenticadas en nombre de un usuario logueado y leer la respuesta, exponiendo datos privados y sesiones.",
      remediation: {
        summary:
          "Nunca combines un origen dinámico/comodín con credenciales. Usá una allowlist explícita de orígenes de confianza.",
        steps: [
          "Reemplazá el reflejo del header Origin por una lista blanca de orígenes permitidos.",
          "Devolvé Access-Control-Allow-Origin solo para orígenes de esa lista.",
          "Habilitá Access-Control-Allow-Credentials únicamente para esos orígenes de confianza.",
        ],
        reference:
          "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#requests_with_credentials",
      },
    });
    return {
      verdict: "dangerous",
      detail:
        "CORS mal configurado: refleja un origen arbitrario o usa '*' junto con credenciales. Riesgo crítico de robo de datos autenticados.",
      findings,
    };
  }

  // Refleja nuestro origen sin credenciales: expone respuestas cross-origin,
  // menos grave pero digno de revisión si hay datos sensibles sin auth.
  if (reflectsProbe) {
    findings.push({
      id: "cors-reflect-origin",
      category: "cors",
      severity: "medium",
      title: "CORS refleja cualquier origen (sin credenciales)",
      impact:
        "El servidor devuelve Access-Control-Allow-Origin con el origen recibido, permitiendo que cualquier web lea respuestas cross-origin. Sin credenciales el riesgo es menor, pero cualquier dato servido sin autenticación queda expuesto a lectura desde sitios de terceros.",
      remediation: {
        summary:
          "Restringí Access-Control-Allow-Origin a una allowlist de orígenes en vez de reflejar el recibido.",
        reference:
          "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin",
      },
    });
    return {
      verdict: "permissive",
      detail:
        "El servidor refleja el origen recibido sin credenciales. Aceptable para contenido público, riesgoso si sirve datos sensibles sin auth.",
      findings,
    };
  }

  if (wildcard) {
    // '*' sin credenciales es el patrón estándar de APIs/CDN públicos.
    return {
      verdict: "permissive",
      detail:
        "Access-Control-Allow-Origin: * sin credenciales. Patrón habitual y aceptable para APIs o recursos públicos.",
      findings,
    };
  }

  // Devuelve un ACAO fijo distinto de nuestra sonda: allowlist real.
  return {
    verdict: "safe",
    detail: `CORS acotado a un origen específico (${acao}). Configuración correcta.`,
    findings,
  };
}

export async function corsCheck(domain: string): Promise<CorsResult> {
  const url = `https://${domain}`;

  let res;
  try {
    // Seguimos redirects mandando el Origin de prueba: la config CORS relevante
    // está en el destino final (ej. apex → www), no en el 301 intermedio.
    res = await httpGet(url, {
      timeoutMs: 8000,
      maxRedirects: 5,
      headers: { Origin: PROBE_ORIGIN },
    });
  } catch (err) {
    return {
      domain,
      url,
      probeOrigin: PROBE_ORIGIN,
      verdict: "error",
      detail: `Error de conexión: ${(err as Error).message}`,
      findings: [],
    };
  }

  const acao = res.headers["access-control-allow-origin"] as string | undefined;
  const acac = res.headers["access-control-allow-credentials"] as
    | string
    | undefined;

  const { verdict, detail, findings } = evaluate(domain, acao, acac);

  return {
    domain,
    url,
    statusCode: res.statusCode,
    probeOrigin: PROBE_ORIGIN,
    accessControlAllowOrigin: acao,
    accessControlAllowCredentials: acac,
    verdict,
    detail,
    findings,
  };
}
