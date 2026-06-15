import * as tls from "node:tls";

export interface SslResult {
  domain: string;
  valid: boolean;
  issuer?: {
    organization?: string;
    country?: string;
  };
  subject?: {
    commonName?: string;
    altNames?: string[];
  };
  validFrom?: string;
  validTo?: string;
  daysUntilExpiry?: number;
  protocol?: string;
  verdict: "strong" | "weak" | "expired" | "invalid" | "error";
  detail: string;
}

const asString = (v: string | string[] | undefined): string | undefined =>
  Array.isArray(v) ? v[0] : v;

export async function sslCheck(domain: string): Promise<SslResult> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false, // queremos inspeccionar aunque sea inválido
        timeout: 8000,
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        const authorized = socket.authorized;
        const protocol = socket.getProtocol() ?? undefined;

        socket.destroy();

        if (!cert || !cert.subject) {
          resolve({
            domain,
            valid: false,
            verdict: "invalid",
            detail: "No se pudo obtener el certificado del servidor.",
          });
          return;
        }

        // Calcular días hasta expiración
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysUntilExpiry = Math.floor(
          (validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
        );

        // Extraer SANs (Subject Alternative Names)
        const altNames = cert.subjectaltname
          ? cert.subjectaltname
              .split(", ")
              .filter((s) => s.startsWith("DNS:"))
              .map((s) => s.replace("DNS:", ""))
          : [];

        // Determinar verdict
        let verdict: SslResult["verdict"];
        let detail: string;

        if (daysUntilExpiry < 0) {
          verdict = "expired";
          detail = `Certificado expirado hace ${Math.abs(daysUntilExpiry)} días. Conexiones van a mostrar error de seguridad.`;
        } else if (!authorized) {
          verdict = "invalid";
          detail = `Certificado no confiable: ${socket.authorizationError}. Posible certificado autofirmado o cadena rota.`;
        } else if (daysUntilExpiry <= 14) {
          verdict = "weak";
          detail = `Certificado válido pero expira en ${daysUntilExpiry} días. Renovación urgente.`;
        } else if (daysUntilExpiry <= 30) {
          verdict = "weak";
          detail = `Certificado válido pero expira en ${daysUntilExpiry} días. Planificar renovación.`;
        } else if (protocol === "TLSv1" || protocol === "TLSv1.1") {
          verdict = "weak";
          detail = `Certificado válido pero el servidor usa ${protocol}, protocolo obsoleto y vulnerable. Recomendado: TLSv1.2 o TLSv1.3.`;
        } else {
          verdict = "strong";
          detail = `Certificado válido. Expira en ${daysUntilExpiry} días. Protocolo: ${protocol}.`;
        }

        resolve({
          domain,
          valid: authorized,
          issuer: {
            organization: asString(cert.issuer?.O),
            country: asString(cert.issuer?.C),
          },
          subject: {
            commonName: asString(cert.subject?.CN),
            altNames,
          },
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysUntilExpiry,
          protocol,
          verdict,
          detail,
        });
      }
    );

    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        domain,
        valid: false,
        verdict: "error",
        detail: "Timeout al conectar al servidor. Puerto 443 puede estar cerrado o filtrado.",
      });
    });

    socket.on("error", (err) => {
      resolve({
        domain,
        valid: false,
        verdict: "error",
        detail: `Error de conexión: ${err.message}`,
      });
    });
  });
}