import { ComplianceNote, Finding, FindingLocation, FindingSeverity, FindingStatus } from '../../core/services/scan.service';
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
    : [{ id: finding.id, affectedUrl: finding.affectedUrl, parameter: finding.parameter, severity: finding.severity, status: finding.status,
         attack: finding.attack, reproduction: finding.reproduction,
         rawRequest: finding.rawRequest, rawResponse: finding.rawResponse }];

export const hasEvidence = (finding: Finding): boolean => locationsOf(finding).some(locationHasEvidence);

/** Aba Evidências: um cartão por local que tem requisição/resposta. */
export interface EvidenceItem {
  id: string;
  title: string;
  severity: FindingSeverity;
  affectedUrl: string | null;
  parameter?: string | null;
  attack?: string | null;
  reproduction?: string | null;
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
                     attack: l.attack, reproduction: l.reproduction,
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

/** Aba Evidências: a mesma falha em vários locais vira um bloco só, com as ocorrências dentro. */
export interface EvidenceGroup {
  id: string;
  title: string;
  severity: FindingSeverity;
  items: EvidenceItem[];
}

export const evidenceGroups = (findings: Finding[]): EvidenceGroup[] =>
  findings
    .map((f) => ({ id: f.id, title: f.title, severity: f.severity, items: evidenceItems([f]) }))
    .filter((group) => group.items.length > 0);

// ---------- painel de achados (lista | detalhe | metadados) ----------

/**
 * Status de um achado agrupado: o dos seus locais. Se ainda houver algum local aberto,
 * o achado está aberto (só sai da fila quando todos foram tratados).
 */
export const findingStatusOf = (finding: Finding): FindingStatus => {
  const statuses = locationsOf(finding).map((l) => l.status ?? finding.status ?? 'OPEN');
  if (statuses.includes('OPEN')) return 'OPEN';
  return statuses.every((s) => s === statuses[0]) ? statuses[0] : 'OPEN';
};

/** Filtro da lista por triagem: 'ALL' mostra todos. */
export const filterByStatus = (findings: Finding[], status: FindingStatus | 'ALL'): Finding[] =>
  status === 'ALL' ? findings : findings.filter((f) => findingStatusOf(f) === status);

/** Aplica o status a um achado e a todos os seus locais (atualização local, sem recarregar). */
export const withStatus = (finding: Finding, status: FindingStatus): Finding => ({
  ...finding,
  status,
  locations: finding.locations?.map((l) => ({ ...l, status })),
});

const normalize = (text: string | null | undefined): string =>
  (text ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();

/** Busca da lista de achados: título, URL, parâmetro, OWASP, CVE ou regra (sem acento e sem caixa). */
export const filterFindings = (findings: Finding[], query: string): Finding[] => {
  const terms = normalize(query).split(/\s+/).filter(Boolean);
  if (terms.length === 0) return findings;
  return findings.filter((f) => {
    const haystack = normalize(
      [f.title, f.owaspUrl, f.cveId, f.ruleId, ...locationsOf(f).flatMap((l) => [l.affectedUrl, l.parameter])].join(' '),
    );
    return terms.every((term) => haystack.includes(term));
  });
};

/** Caminho curto da URL para a lista ("http://site/busca?q=1" → "/busca?q=1"). */
export const pathOf = (url: string | null | undefined): string => {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    return `${parsed.pathname}${parsed.search}` || '/';
  } catch {
    return url;
  }
};

/** Pedaço de uma linha do visor; `mark` = é o trecho exato que prova a falha. */
export interface ViewerSegment {
  text: string;
  mark: boolean;
}

/** Linha do visor de requisição/resposta; `hit` = a linha que prova a falha. */
export interface ViewerLine {
  number: number;
  segments: ViewerSegment[];
  hit: boolean;
}

/** Acima disso o visor mostra só o começo (o JSON exportado leva tudo). */
export const VIEWER_MAX_LINES = 400;

// o motor marca a evidência como ">>> trecho <<<" (backend: security_engine/app/evidence.py)
const MARK_OPEN = '>>> ';
const MARK_CLOSE = ' <<<';

/** Texto sem os marcadores de evidência (para copiar). */
export const stripEvidenceMarks = (text: string): string => text.replace(/>>> ([\s\S]*?) <<</g, '$1');

/** Separa a linha em pedaços normais e marcados; `inside` = a marcação veio aberta da linha anterior. */
const splitMarks = (line: string, inside: boolean): { segments: ViewerSegment[]; inside: boolean } => {
  const segments: ViewerSegment[] = [];
  let cursor = 0;
  while (cursor <= line.length) {
    const token = inside ? MARK_CLOSE : MARK_OPEN;
    const at = line.indexOf(token, cursor);
    const piece = line.slice(cursor, at < 0 ? undefined : at);
    if (piece) segments.push({ text: piece, mark: inside });
    if (at < 0) break;
    inside = !inside;
    cursor = at + token.length;
  }
  return { segments, inside };
};

/**
 * Numera o texto e marca o que prova a falha:
 *  1. o trecho que o motor marcou (>>> <<<), destacado na própria linha, sem os marcadores;
 *  2. sem marcação (varreduras antigas): as linhas com o payload do ataque ou com o
 *     cabeçalho citado entre aspas no título (“X-Powered-By” → "X-Powered-By: Express").
 */
export const highlightedLines = (text: string, title: string, attack: string | null | undefined): ViewerLine[] => {
  if (!text) return [];
  const lines = text.split('\n').slice(0, VIEWER_MAX_LINES);

  if (text.includes(MARK_OPEN) && text.includes(MARK_CLOSE)) {
    let inside = false;
    return lines.map((line, index) => {
      const split = splitMarks(line, inside);
      inside = split.inside;
      return { number: index + 1, segments: split.segments, hit: split.segments.some((s) => s.mark) };
    });
  }

  const headers = [...title.matchAll(/[“"'‘]([A-Za-z][\w-]{2,})[”"'’]/g)].map((m) => m[1].toLowerCase());
  const payload = attack && attack.trim().length >= 3 ? attack.trim() : null;
  return lines.map((line, index) => {
    const lower = line.toLowerCase();
    const hit = headers.some((h) => lower.startsWith(`${h}:`)) || Boolean(payload && line.includes(payload));
    return { number: index + 1, segments: [{ text: line, mark: false }], hit };
  });
};
