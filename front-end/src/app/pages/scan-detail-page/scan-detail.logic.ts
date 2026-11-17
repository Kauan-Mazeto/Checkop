import { ComplianceNote, Finding, FindingLocation, FindingSeverity } from '../../core/services/scan.service';
import { SEVERITY_ORDER } from '../../shared/ui/labels';

// Lógica pura da tela de detalhe (testável sem renderizar o componente).

export const sortBySeverity = (findings: Finding[]): Finding[] =>
  [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      (b.cvssScore ?? 0) - (a.cvssScore ?? 0) ||
      a.title.localeCompare(b.title)
  );

export const filterBySeverity = (findings: Finding[], severity: FindingSeverity | 'ALL'): Finding[] =>
  severity === 'ALL' ? findings : findings.filter((f) => f.severity === severity);

const locationHasEvidence = (l: { rawRequest?: string | null; rawResponse?: string | null }): boolean =>
  Boolean(l.rawRequest || l.rawResponse);

/** Locais da falha; achado sem agrupamento (comparação) vale como um local só. */
export const locationsOf = (finding: Finding): FindingLocation[] =>
  finding.locations?.length
    ? finding.locations
    : [{ id: finding.id, affectedUrl: finding.affectedUrl, parameter: finding.parameter, severity: finding.severity,
         rawRequest: finding.rawRequest, rawResponse: finding.rawResponse }];

export const hasEvidence = (finding: Finding): boolean => locationsOf(finding).some(locationHasEvidence);

/** Aba Evidências: um cartão por local que tem requisição/resposta. */
export interface EvidenceItem {
  id: string;
  title: string;
  severity: FindingSeverity;
  affectedUrl: string | null;
  parameter?: string | null;
  rawRequest?: string | null;
  rawResponse?: string | null;
}

/** Tamanho máximo exibido de cada requisição/resposta (o JSON exportado leva tudo). */
export const EVIDENCE_MAX_CHARS = 20000;

export const clipEvidence = (text: string | null | undefined): string | null | undefined =>
  text && text.length > EVIDENCE_MAX_CHARS
    ? `${text.slice(0, EVIDENCE_MAX_CHARS)}

[... ${text.length - EVIDENCE_MAX_CHARS} caracteres omitidos; o JSON exportado traz o conteúdo completo]`
    : text;

export const evidenceItems = (findings: Finding[]): EvidenceItem[] =>
  findings.flatMap((f) =>
    locationsOf(f)
      .filter(locationHasEvidence)
      .map((l) => ({ id: l.id, title: f.title, severity: l.severity, affectedUrl: l.affectedUrl, parameter: l.parameter,
                     rawRequest: clipEvidence(l.rawRequest), rawResponse: clipEvidence(l.rawResponse) })),
  );

export interface ComplianceGroup {
  law: string;
  reference: string;
  message: string;
  findings: Finding[];
}

/**
 * espec.txt 3.3: painel de conformidade. Agrupa as notas LGPD/PCI-DSS de todos
 * os achados por lei + artigo, mostrando quais falhas disparam cada uma.
 */
export const groupCompliance = (findings: Finding[]): ComplianceGroup[] => {
  const groups = new Map<string, ComplianceGroup>();
  for (const finding of findings) {
    for (const note of finding.compliance ?? []) {
      const key = `${note.law}|${note.reference}`;
      const group = groups.get(key) ?? { ...pickNote(note), findings: [] };
      if (!group.findings.includes(finding)) group.findings.push(finding);
      groups.set(key, group);
    }
  }
  return [...groups.values()].sort((a, b) => a.law.localeCompare(b.law) || b.findings.length - a.findings.length);
};

const pickNote = ({ law, reference, message }: ComplianceNote) => ({ law, reference, message });

export const countBy = <T>(items: T[], key: (item: T) => string | null | undefined): Record<string, number> =>
  items.reduce<Record<string, number>>((acc, item) => {
    const k = key(item) ?? 'UNKNOWN';
    acc[k] = (acc[k] ?? 0) + 1;
    return acc;
  }, {});

/** Nome do arquivo exportado: checkop-<host>-<aaaa-mm-dd>.json */
export const exportFileName = (targetUrl: string, date = new Date()): string => {
  let host = 'alvo';
  try {
    host = new URL(targetUrl).hostname.replace(/[^a-z0-9.-]/gi, '_');
  } catch {
    /* mantém "alvo" */
  }
  return `checkop-${host}-${date.toISOString().slice(0, 10)}.json`;
};

/** "mm:ss" desde o início da varredura. */
export const elapsed = (startedAt: string | null, now = Date.now()): string => {
  if (!startedAt) return '00:00';
  const seconds = Math.max(0, Math.floor((now - new Date(startedAt).getTime()) / 1000));
  return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
};
