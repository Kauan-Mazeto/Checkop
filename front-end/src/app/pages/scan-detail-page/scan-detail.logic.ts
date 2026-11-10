import { ComplianceNote, Finding, FindingSeverity } from '../../core/services/scan.service';
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

export const hasEvidence = (finding: Finding): boolean => Boolean(finding.rawRequest || finding.rawResponse);

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
