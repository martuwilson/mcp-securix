import { httpGet } from "./fetch.js";
import type { Finding } from "../findings.js";

// Controles web que aprovechan que ya bajamos la página:
// - Redirect HTTP→HTTPS: ¿el sitio fuerza HTTPS?
// - Flags de cookies: Secure / HttpOnly / SameSite.
// - security.txt (RFC 9116): canal declarado para reportar vulnerabilidades.

export interface HttpsRedirectResult {
  redirects: boolean;
  location?: string;
  statusCode?: number;
  verdict: "strong" | "weak" | "error";
  detail: string;
}

export interface CookieInfo {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
}

export interface CookiesResult {
  count: number;
  cookies: CookieInfo[];
  verdict: "strong" | "weak" | "none";
  detail: string;
}

export interface SecurityTxtResult {
  exists: boolean;
  url?: string;
  verdict: "present" | "missing";
  detail: string;
}

export interface WebExtrasResult {
  domain: string;
  httpsRedirect: HttpsRedirectResult;
  cookies: CookiesResult;
  securityTxt: SecurityTxtResult;
  findings: Finding[];
}

async function checkHttpsRedirect(domain: string): Promise<HttpsRedirectResult> {
  try {
    // maxRedirects 0: queremos ver el primer salto sin seguirlo.
    const res = await httpGet(`http://${domain}`, { timeoutMs: 8000, maxRedirects: 0 });
    const status = res.statusCode ?? 0;
    const location = res.headers.location;

    if (status >= 300 && status < 400 && location) {
      const toHttps = location.startsWith("https://");
      return {
        redirects: true,
        location,
        statusCode: status,
        verdict: toHttps ? "strong" : "weak",
        detail: toHttps
          ? "El acceso por HTTP redirige a HTTPS."
          : `HTTP redirige, pero no a HTTPS (${location}).`,
      };
    }

    return {
      redirects: false,
      statusCode: status,
      verdict: "weak",
      detail: "El sitio responde por HTTP sin forzar redirect a HTTPS. El tráfico inicial puede viajar en texto plano.",
    };
  } catch (err) {
    return {
      redirects: false,
      verdict: "error",
      detail: `No se pudo evaluar el redirect HTTP: ${(err as Error).message}`,
    };
  }
}

function parseCookie(raw: string): CookieInfo {
  const parts = raw.split(";").map((p) => p.trim());
  const name = parts[0]?.split("=")[0] ?? "(sin nombre)";
  const lower = parts.map((p) => p.toLowerCase());
  const sameSitePart = parts.find((p) => p.toLowerCase().startsWith("samesite="));
  return {
    name,
    secure: lower.includes("secure"),
    httpOnly: lower.includes("httponly"),
    sameSite: sameSitePart ? sameSitePart.split("=")[1] : undefined,
  };
}

async function checkCookies(domain: string): Promise<CookiesResult> {
  try {
    const res = await httpGet(`https://${domain}`, { timeoutMs: 8000, maxRedirects: 5 });
    const setCookie = res.headers["set-cookie"] ?? [];
    if (setCookie.length === 0) {
      return { count: 0, cookies: [], verdict: "none", detail: "El servidor no setea cookies en la respuesta inicial." };
    }
    const cookies = setCookie.map(parseCookie);
    const allSecure = cookies.every((c) => c.secure);
    const allHttpOnly = cookies.every((c) => c.httpOnly);
    return {
      count: cookies.length,
      cookies,
      verdict: allSecure && allHttpOnly ? "strong" : "weak",
      detail:
        allSecure && allHttpOnly
          ? `${cookies.length} cookie(s), todas con Secure y HttpOnly.`
          : `${cookies.length} cookie(s); faltan flags de seguridad en alguna.`,
    };
  } catch (err) {
    return { count: 0, cookies: [], verdict: "none", detail: `No se pudieron leer las cookies: ${(err as Error).message}` };
  }
}

async function checkSecurityTxt(domain: string): Promise<SecurityTxtResult> {
  const candidates = [
    `https://${domain}/.well-known/security.txt`,
    `https://${domain}/security.txt`,
  ];
  for (const url of candidates) {
    try {
      const res = await httpGet(url, { timeoutMs: 6000, maxRedirects: 3, includeBody: true });
      if (res.statusCode === 200 && res.body && /contact\s*:/i.test(res.body)) {
        return { exists: true, url, verdict: "present", detail: `security.txt presente en ${url}.` };
      }
    } catch {
      /* probamos el siguiente candidato */
    }
  }
  return {
    exists: false,
    verdict: "missing",
    detail: "Sin security.txt. No hay un canal declarado para reportar vulnerabilidades.",
  };
}

export async function webExtrasCheck(domain: string): Promise<WebExtrasResult> {
  const [httpsRedirect, cookies, securityTxt] = await Promise.all([
    checkHttpsRedirect(domain),
    checkCookies(domain),
    checkSecurityTxt(domain),
  ]);

  const findings: Finding[] = [];

  if (httpsRedirect.verdict === "weak") {
    findings.push({
      id: "no-https-redirect",
      category: "headers",
      severity: "medium",
      title: "No fuerza HTTPS",
      impact: httpsRedirect.detail,
      remediation: {
        summary: "Configurá un redirect 301 de todo el tráfico HTTP a HTTPS.",
      },
    });
  }

  if (cookies.verdict === "weak") {
    const insecure = cookies.cookies.filter((c) => !c.secure);
    const noHttpOnly = cookies.cookies.filter((c) => !c.httpOnly);
    const noSameSite = cookies.cookies.filter((c) => !c.sameSite);
    if (insecure.length > 0) {
      findings.push({
        id: "cookies-no-secure",
        category: "headers",
        severity: "medium",
        title: "Cookies sin flag Secure",
        impact: `Cookie(s) sin Secure (${insecure.map((c) => c.name).join(", ")}): pueden viajar por HTTP en texto plano y ser interceptadas.`,
        remediation: { summary: "Agregá el atributo Secure a todas las cookies." },
      });
    }
    if (noHttpOnly.length > 0) {
      findings.push({
        id: "cookies-no-httponly",
        category: "headers",
        severity: "low",
        title: "Cookies sin flag HttpOnly",
        impact: `Cookie(s) sin HttpOnly (${noHttpOnly.map((c) => c.name).join(", ")}): accesibles vía JavaScript, exponibles a robo por XSS.`,
        remediation: { summary: "Agregá HttpOnly a las cookies que no requieran acceso desde JS." },
      });
    }
    if (noSameSite.length > 0) {
      findings.push({
        id: "cookies-no-samesite",
        category: "headers",
        severity: "low",
        title: "Cookies sin atributo SameSite",
        impact: `Cookie(s) sin SameSite (${noSameSite.map((c) => c.name).join(", ")}): mayor exposición a CSRF.`,
        remediation: { summary: "Definí SameSite=Lax o Strict según el caso de uso." },
      });
    }
  }

  if (securityTxt.verdict === "missing") {
    findings.push({
      id: "security-txt-missing",
      category: "headers",
      severity: "info",
      title: "Sin security.txt",
      impact: securityTxt.detail,
      remediation: {
        summary: "Publicá /.well-known/security.txt con un contacto para reportes de seguridad.",
        example: "Contact: mailto:security@" + domain + "\nExpires: 2027-01-01T00:00:00Z",
        reference: "https://www.rfc-editor.org/rfc/rfc9116",
      },
    });
  }

  return { domain, httpsRedirect, cookies, securityTxt, findings };
}
