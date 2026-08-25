import { URL } from "node:url";

// Normaliza el "target" que pide el usuario. La idea central:
//   - Un dominio pelado ("example.com") se comporta EXACTAMENTE como antes:
//     esquema https por defecto y puerto 443 para el handshake TLS.
//   - Además ahora se acepta un target local ("localhost:3000",
//     "http://127.0.0.1:8080", "https://mi-app.local"): se respeta el esquema
//     y el puerto que da el usuario, y se marca isLocal para que los checks
//     que dependen de DNS/registro público (SPF, DMARC, RDAP, CAA...) sepan
//     que no aplican.

export type Scheme = "http" | "https";

export interface Target {
  /** Input original, tal cual lo pasó el usuario. */
  raw: string;
  /** Hostname sin esquema, puerto ni corchetes (ej. "example.com", "localhost", "::1"). */
  host: string;
  /** Puerto explícito si el usuario lo dio; undefined si no. */
  port?: number;
  /** Esquema explícito ("http"|"https") si el input lo traía; undefined si no. */
  scheme?: Scheme;
  /** true si el host es loopback / IP privada / .local: sin presencia pública en DNS/RDAP. */
  isLocal: boolean;
  /** "host[:port]" (con corchetes si es IPv6). Se usa como identificador legible del target. */
  hostPort: string;
  /** Esquema efectivo para las peticiones web principales: el explícito, o https público / http local. */
  primaryScheme: Scheme;
  /** Host para el handshake TLS. */
  tlsHost: string;
  /** Puerto para el handshake TLS: el explícito, o 443. */
  tlsPort: number;
  /** URL principal: <primaryScheme>://host[:port]<path>. */
  primaryUrl(path?: string): string;
  /** URL en texto plano: http://host[:port]<path> (para el test de redirect http→https). */
  insecureUrl(path?: string): string;
}

// Rangos que consideramos "locales": loopback, link-local y RFC 1918.
const PRIVATE_IPV4 =
  /^(127\.|10\.|0\.0\.0\.0|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;

function detectLocal(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h === "::1" || h === "0.0.0.0") return true;
  if (h.endsWith(".localhost") || h.endsWith(".local")) return true;
  if (PRIVATE_IPV4.test(h)) return true;
  // IPv6 loopback/link-local por si viene con otra forma.
  if (h.startsWith("fe80:") || h === "0:0:0:0:0:0:0:1") return true;
  return false;
}

function bracketIfV6(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function makeTarget(
  raw: string,
  hostInput: string,
  port: number | undefined,
  scheme: Scheme | undefined,
  isLocal: boolean
): Target {
  const host = hostInput.replace(/^\[|\]$/g, ""); // normalizamos IPv6 sin corchetes
  const authority = bracketIfV6(host);
  const hostPort = port != null ? `${authority}:${port}` : authority;
  const primaryScheme: Scheme = scheme ?? (isLocal ? "http" : "https");

  return {
    raw,
    host,
    port,
    scheme,
    isLocal,
    hostPort,
    primaryScheme,
    tlsHost: host,
    tlsPort: port ?? 443,
    primaryUrl: (path = "") => `${primaryScheme}://${hostPort}${path}`,
    insecureUrl: (path = "") => `http://${hostPort}${path}`,
  };
}

export function parseTarget(input: string): Target {
  const raw = input.trim();
  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);

  let parsed: URL;
  try {
    // Si no viene esquema, anteponemos uno temporal SOLO para parsear host/puerto
    // de forma robusta; el esquema real queda como undefined.
    parsed = new URL(hasScheme ? raw : `http://${raw}`);
  } catch {
    // Fallback defensivo: tratamos todo el input como host.
    const host = raw.replace(/^\[|\]$/g, "");
    return makeTarget(raw, host, undefined, undefined, detectLocal(host));
  }

  let scheme: Scheme | undefined;
  if (hasScheme) {
    const p = parsed.protocol.replace(":", "").toLowerCase();
    // http se respeta; cualquier otro esquema (https u otro) lo tratamos como https.
    scheme = p === "http" ? "http" : "https";
  }

  const host = parsed.hostname; // puede venir con corchetes si es IPv6
  const port = parsed.port ? Number(parsed.port) : undefined;
  const bareHost = host.replace(/^\[|\]$/g, "");

  return makeTarget(raw, bareHost, port, scheme, detectLocal(bareHost));
}
