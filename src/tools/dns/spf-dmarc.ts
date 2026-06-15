import { promises as dns } from "node:dns";

dns.setServers(["8.8.8.8", "1.1.1.1"]);

export interface SpfResult {
  exists: boolean;
  record?: string;
  qualifier?: "-all" | "~all" | "+all" | "?all";
  verdict: "strong" | "weak" | "dangerous" | "missing";
  detail: string;
}

export interface DmarcResult {
  exists: boolean;
  record?: string;
  policy?: "none" | "quarantine" | "reject";
  verdict: "strong" | "weak" | "missing";
  detail: string;
}

export interface SpfDmarcResult {
  domain: string;
  spf: SpfResult;
  dmarc: DmarcResult;
}

async function checkSpf(domain: string): Promise<SpfResult> {
  try {
    const records = await dns.resolveTxt(domain);
    const flat = records.map(r => r.join(""));
    const spfRecord = flat.find(r => r.startsWith("v=spf1"));

    if (!spfRecord) {
      return {
        exists: false,
        verdict: "missing",
        detail: "No se encontró registro SPF. Cualquiera puede enviar emails suplantando este dominio.",
      };
    }

    // Extraer el calificador final (-all, ~all, +all, ?all)
    const match = spfRecord.match(/([+~\-?])all/);
    const qualifier = match ? match[1] : null;

    if (qualifier === "-") {
      return {
        exists: true,
        record: spfRecord,
        qualifier: "-all",
        verdict: "strong",
        detail: "SPF configurado correctamente. Emails no autorizados son rechazados.",
      };
    } else if (qualifier === "~") {
      return {
        exists: true,
        record: spfRecord,
        qualifier: "~all",
        verdict: "weak",
        detail: "SPF en soft fail (~all). Emails no autorizados son marcados pero no rechazados. Recomendado: cambiar a -all.",
      };
    } else if (qualifier === "+") {
      return {
        exists: true,
        record: spfRecord,
        qualifier: "+all",
        verdict: "dangerous",
        detail: "SPF con +all: cualquier servidor puede enviar emails como este dominio. Configuración peligrosa.",
      };
    } else {
      return {
        exists: true,
        record: spfRecord,
        verdict: "weak",
        detail: "SPF encontrado pero sin calificador claro. Revisión manual recomendada.",
      };
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENODATA" || code === "ENOTFOUND") {
      return {
        exists: false,
        verdict: "missing",
        detail: "No se encontró registro SPF.",
      };
    }
    throw err;
  }
}

async function checkDmarc(domain: string): Promise<DmarcResult> {
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    const flat = records.map(r => r.join(""));
    const dmarcRecord = flat.find(r => r.startsWith("v=DMARC1"));

    if (!dmarcRecord) {
      return {
        exists: false,
        verdict: "missing",
        detail: "No se encontró registro DMARC.",
      };
    }

    // Extraer la policy (p=none, p=quarantine, p=reject)
    const match = dmarcRecord.match(/p=(none|quarantine|reject)/);
    const policy = match ? match[1] as "none" | "quarantine" | "reject" : undefined;

    if (policy === "reject") {
      return {
        exists: true,
        record: dmarcRecord,
        policy,
        verdict: "strong",
        detail: "DMARC con p=reject. Emails no autorizados son rechazados directamente.",
      };
    } else if (policy === "quarantine") {
      return {
        exists: true,
        record: dmarcRecord,
        policy,
        verdict: "weak",
        detail: "DMARC con p=quarantine. Emails sospechosos van a spam. Recomendado: evolucionar a p=reject.",
      };
    } else {
      return {
        exists: true,
        record: dmarcRecord,
        policy,
        verdict: "weak",
        detail: "DMARC con p=none. Solo monitoreo, sin acción. No protege contra spoofing activo.",
      };
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENODATA" || code === "ENOTFOUND") {
      return {
        exists: false,
        verdict: "missing",
        detail: "No se encontró registro DMARC. El dominio no tiene política anti-spoofing definida.",
      };
    }
    throw err;
  }
}

export async function spfDmarcCheck(domain: string): Promise<SpfDmarcResult> {
  const [spf, dmarc] = await Promise.all([
    checkSpf(domain),
    checkDmarc(domain),
  ]);

  return { domain, spf, dmarc };
}