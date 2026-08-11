// Tipos compartidos para hallazgos estructurados.
// La idea: cada tool devuelve Findings con remediación accionable en vez de
// strings sueltos, para que el reporte final sea consistente y útil sin
// depender de cómo el modelo redacte.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category =
  | "ssl"
  | "spf"
  | "dmarc"
  | "dkim"
  | "headers"
  | "cors"
  | "dns";

export interface Remediation {
  /** Qué hacer, en una línea. */
  summary: string;
  /** Pasos concretos a seguir, opcional. */
  steps?: string[];
  /** Valor/registro exacto para copiar y pegar (ej. un TXT de DNS). */
  example?: string;
  /** Link de referencia para profundizar. */
  reference?: string;
}

export interface Finding {
  /** Slug estable e identificable, ej. "dmarc-missing". */
  id: string;
  category: Category;
  severity: Severity;
  /** Título corto y claro del hallazgo. */
  title: string;
  /** Por qué importa / cuál es el impacto real. */
  impact: string;
  /** Cómo arreglarlo. Ausente cuando es un hallazgo puramente informativo. */
  remediation?: Remediation;
}

// Orden de severidad para poder ordenar findings de más a menos grave.
const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Ordena findings de mayor a menor severidad (estable). */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
}

/** Cuenta findings por severidad, útil para resúmenes rápidos. */
export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) counts[f.severity]++;
  return counts;
}
