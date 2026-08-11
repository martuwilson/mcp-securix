import * as https from "node:https";
import * as http from "node:http";
import { URL } from "node:url";

export interface HttpGetResult {
  statusCode?: number;
  headers: http.IncomingHttpHeaders;
  /** URL final tras seguir los redirects. */
  finalUrl: string;
  /** Cadena de redirects seguidos (URLs intermedias), vacía si no hubo. */
  redirectChain: string[];
}

export interface HttpGetOptions {
  headers?: Record<string, string>;
  timeoutMs?: number;
  maxRedirects?: number;
}

const DEFAULT_UA = "Mozilla/5.0 (compatible; mcp-securix/1.0)";

/**
 * GET que sigue redirects (301/302/303/307/308) hasta la respuesta final.
 * Necesario porque muchos dominios redirigen apex→www o http→https, y los
 * headers de seguridad / CORS viven en el destino final, no en el 3xx.
 */
export function httpGet(
  startUrl: string,
  opts: HttpGetOptions = {}
): Promise<HttpGetResult> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  const maxRedirects = opts.maxRedirects ?? 5;
  const baseHeaders = { "User-Agent": DEFAULT_UA, ...(opts.headers ?? {}) };

  return new Promise((resolve, reject) => {
    const redirectChain: string[] = [];

    const request = (currentUrl: string, redirectsLeft: number): void => {
      let parsed: URL;
      try {
        parsed = new URL(currentUrl);
      } catch {
        reject(new Error(`URL inválida: ${currentUrl}`));
        return;
      }

      const transport = parsed.protocol === "http:" ? http : https;

      const req = transport.request(
        currentUrl,
        { method: "GET", timeout: timeoutMs, headers: baseHeaders },
        (res) => {
          const status = res.statusCode ?? 0;
          const location = res.headers.location;

          // ¿Es un redirect que podemos seguir?
          if (
            status >= 300 &&
            status < 400 &&
            location &&
            redirectsLeft > 0
          ) {
            res.resume(); // descartamos el body del 3xx
            // Location puede ser relativo; lo resolvemos contra la URL actual.
            const nextUrl = new URL(location, currentUrl).toString();
            redirectChain.push(currentUrl);
            request(nextUrl, redirectsLeft - 1);
            return;
          }

          // Respuesta final (o se agotaron los redirects).
          res.resume();
          resolve({
            statusCode: status,
            headers: res.headers,
            finalUrl: currentUrl,
            redirectChain,
          });
        }
      );

      req.on("timeout", () => {
        req.destroy();
        reject(new Error("Timeout al conectar al servidor."));
      });

      req.on("error", (err) => reject(err));
      req.end();
    };

    request(startUrl, maxRedirects);
  });
}
