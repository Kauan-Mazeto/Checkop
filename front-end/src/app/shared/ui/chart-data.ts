import { ChartData, ChartOptions } from 'chart.js';
import { Finding, FindingSeverity, FindingStatus, Scan } from '../../core/services/scan.service';
import { CONFIDENCE_LABEL, FINDING_STATUS_LABEL, SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_ORDER, TOOL_LABEL, shortOwasp } from './labels';

const PRIMARY = '#d84a56';
const INFO = '#8299ad';

/** Rosca de achados por severidade, sempre na ordem crítico → informativo. */
export const severityDoughnut = (counts: Partial<Record<string, number>>): ChartData<'doughnut'> => ({
  labels: SEVERITY_ORDER.map((s) => SEVERITY_LABEL[s]),
  datasets: [
    {
      data: SEVERITY_ORDER.map((s) => counts[s] ?? 0),
      backgroundColor: SEVERITY_ORDER.map((s) => SEVERITY_COLOR[s]),
      borderColor: '#191a1c',
      borderWidth: 2,
    },
  ],
});

/**
 * Linha dos últimos N dias. O backend só manda os dias com achados; os dias
 * vazios entram como zero para o eixo do tempo não "pular".
 */
export const timelineLine = (
  timeline: Record<string, number>,
  days = 30,
  today = new Date()
): ChartData<'line'> => {
  const labels: string[] = [];
  const values: number[] = [];
  for (let offset = days - 1; offset >= 0; offset--) {
    const day = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - offset));
    const key = day.toISOString().slice(0, 10);
    labels.push(`${key.slice(8, 10)}/${key.slice(5, 7)}`);
    values.push(timeline[key] ?? 0);
  }
  return {
    labels,
    datasets: [
      {
        label: 'Achados',
        data: values,
        borderColor: PRIMARY,
        backgroundColor: 'rgba(216, 74, 86, 0.10)',
        fill: true,
        tension: 0.3,
        pointRadius: 2,
      },
    ],
  };
};

/** Barras por categoria OWASP Top 10, da mais frequente para a menos. */
export const owaspBar = (byCategory: Record<string, number>): ChartData<'bar'> => {
  const entries = Object.entries(byCategory).sort(([a, x], [b, y]) => y - x || a.localeCompare(b));
  return {
    labels: entries.map(([category]) => shortOwasp(category)),
    datasets: [{ label: 'Achados', data: entries.map(([, n]) => n), backgroundColor: PRIMARY, borderRadius: 4, maxBarThickness: 22 }],
  };
};

/** Barras simples a partir de um mapa { chave: quantidade }. */
export const countBar = (
  counts: Record<string, number>,
  labelOf: (key: string) => string = (key) => TOOL_LABEL[key] ?? key,
  color = INFO
): ChartData<'bar'> => {
  const entries = Object.entries(counts).sort(([, x], [, y]) => y - x);
  return {
    labels: entries.map(([key]) => labelOf(key)),
    datasets: [{ label: 'Quantidade', data: entries.map(([, n]) => n), backgroundColor: color, borderRadius: 4, maxBarThickness: 22 }],
  };
};

export const severityCountsFrom = (findings: { severity: FindingSeverity }[]): Record<FindingSeverity, number> => {
  const counts: Record<FindingSeverity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
};

// ---------- QA ----------

const TRIAGE_ORDER: FindingStatus[] = ['OPEN', 'FIXED', 'FALSE_POSITIVE', 'IGNORED'];
const TRIAGE_COLOR: Record<FindingStatus, string> = { OPEN: '#d84a56', FIXED: '#4fb276', FALSE_POSITIVE: '#8299ad', IGNORED: '#5b5c61' };

/** Rosca da triagem: quanto já foi corrigido, marcado como falso positivo ou ignorado. */
export const triageDoughnut = (byStatus: Partial<Record<string, number>>): ChartData<'doughnut'> => ({
  labels: TRIAGE_ORDER.map((s) => FINDING_STATUS_LABEL[s]),
  datasets: [
    {
      data: TRIAGE_ORDER.map((s) => byStatus[s] ?? 0),
      backgroundColor: TRIAGE_ORDER.map((s) => TRIAGE_COLOR[s]),
      borderColor: '#191a1c',
      borderWidth: 2,
    },
  ],
});

const TREND_COLORS = ['#d84a56', '#8299ad', '#c5a66c', '#4fb276'];

/**
 * Regressão: total de achados em cada execução do MESMO tipo de teste no MESMO site
 * (comparar "Varredura completa" com "só SQL Injection" não diz se melhorou). Só
 * concluídas (uma cancelada para no meio e daria uma queda falsa). Até 4 linhas, as
 * com mais execuções, e as 10 últimas execuções de cada, na ordem do tempo.
 */
export const targetTrendLine = (scans: Scan[], maxSeries = 4, lastRuns = 10): ChartData<'line'> => {
  const done = scans
    .filter((s) => s.status === 'COMPLETED')
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  const bySeries = new Map<string, Scan[]>();
  for (const scan of done) {
    const key = `${scan.targetUrl}\u0000${scan.objective}`;
    bySeries.set(key, [...(bySeries.get(key) ?? []), scan]);
  }
  const repeated = [...bySeries.values()]
    .filter((runs) => runs.length > 1)
    .sort((a, b) => b.length - a.length)
    .slice(0, maxSeries)
    .map((runs) => runs.slice(-lastRuns));
  const longest = Math.max(0, ...repeated.map((runs) => runs.length));
  return {
    labels: Array.from({ length: longest }, (_, i) => `${i + 1}ª`),
    datasets: repeated.map((runs, i) => ({
      label: `${runs[0].targetUrl.replace(/^https?:\/\//, '')} · ${runs[0].objectiveLabel}`,
      data: runs.map((r) => r.findingsCount),
      borderColor: TREND_COLORS[i % TREND_COLORS.length],
      backgroundColor: TREND_COLORS[i % TREND_COLORS.length],
      tension: 0.25,
      pointRadius: 3,
    })),
  };
};

// ---------- Pentester ----------

const CVSS_BUCKETS: { label: string; min: number; max: number; color: string }[] = [
  { label: 'Baixa (0,1–3,9)', min: 0.1, max: 3.9, color: SEVERITY_COLOR.LOW },
  { label: 'Média (4–6,9)', min: 4, max: 6.9, color: SEVERITY_COLOR.MEDIUM },
  { label: 'Alta (7–8,9)', min: 7, max: 8.9, color: SEVERITY_COLOR.HIGH },
  { label: 'Crítica (9–10)', min: 9, max: 10, color: SEVERITY_COLOR.CRITICAL },
];

/** Quantos achados em cada faixa da nota CVSS 3.1 (faixas oficiais da FIRST). */
export const cvssHistogram = (findings: Pick<Finding, 'cvssScore'>[]): ChartData<'bar'> => ({
  labels: CVSS_BUCKETS.map((b) => b.label),
  datasets: [
    {
      label: 'Achados',
      data: CVSS_BUCKETS.map((b) => findings.filter((f) => (f.cvssScore ?? 0) >= b.min && (f.cvssScore ?? 0) <= b.max + 0.049).length),
      backgroundColor: CVSS_BUCKETS.map((b) => b.color),
      borderRadius: 4,
      maxBarThickness: 46,
    },
  ],
});

const CONFIDENCE_ORDER = ['CONFIRMED', 'HIGH', 'MEDIUM', 'LOW'];
const CONFIDENCE_COLOR = ['#4fb276', '#8299ad', '#c5a66c', '#d07a5a', '#5b5c61'];

/** Confiança da ferramenta: o que já está provado e o que precisa de confirmação manual. */
export const confidenceDoughnut = (findings: Pick<Finding, 'confidence'>[]): ChartData<'doughnut'> => {
  const counts = CONFIDENCE_ORDER.map((c) => findings.filter((f) => f.confidence === c).length);
  const unknown = findings.filter((f) => !f.confidence || !CONFIDENCE_ORDER.includes(f.confidence)).length;
  return {
    labels: [...CONFIDENCE_ORDER.map((c) => CONFIDENCE_LABEL[c]), 'Sem informação'],
    datasets: [{ data: [...counts, unknown], backgroundColor: CONFIDENCE_COLOR, borderColor: '#191a1c', borderWidth: 2 }],
  };
};

/** Caminho da URL do achado, sem o domínio nem a query (/login, /api/users...). */
export const endpointOf = (url: string | null | undefined): string | null => {
  if (!url) return null;
  try {
    return new URL(url).pathname || '/';
  } catch {
    return url.split('?')[0] || null;
  }
};

/** Endpoints com mais achados: a superfície de ataque mais promissora. */
export const endpointsBar = (findings: Pick<Finding, 'affectedUrl'>[], limit = 6): ChartData<'bar'> => {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    const path = endpointOf(finding.affectedUrl);
    if (path) counts[path] = (counts[path] ?? 0) + 1;
  }
  const top = Object.fromEntries(Object.entries(counts).sort(([, a], [, b]) => b - a).slice(0, limit));
  return countBar(top, (key) => key, '#c5a66c');
};

/** Triagem de uma varredura: quantos achados estão em cada situação. */
export interface TriageRun {
  scanId: string;
  createdAt: string;
  targetUrl: string;
  objectiveLabel: string;
  open: number;
  fixed: number;
  /** falso positivo + ignorado */
  dismissed: number;
}

/** Conta a triagem de uma lista de achados (um achado agrupado conta uma vez, pelo status dele). */
export const triageRunOf = (
  scan: Pick<Scan, 'id' | 'createdAt' | 'targetUrl' | 'objectiveLabel'>,
  findings: Pick<Finding, 'status'>[],
): TriageRun => ({
  scanId: scan.id,
  createdAt: scan.createdAt,
  targetUrl: scan.targetUrl,
  objectiveLabel: scan.objectiveLabel,
  open: findings.filter((f) => !f.status || f.status === 'OPEN').length,
  fixed: findings.filter((f) => f.status === 'FIXED').length,
  dismissed: findings.filter((f) => f.status === 'FALSE_POSITIVE' || f.status === 'IGNORED').length,
});

/**
 * Evolução das correções: uma barra por varredura (da mais antiga para a mais nova), com
 * os achados corrigidos, descartados (falso positivo/ignorado) e ainda abertos empilhados.
 */
export const triageEvolutionBar = (runs: TriageRun[]): ChartData<'bar'> => {
  const ordered = [...runs].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  const label = (r: TriageRun) => {
    const d = new Date(r.createdAt);
    return `${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}h`;
  };
  return {
    labels: ordered.map(label),
    datasets: [
      { label: 'Corrigidos', data: ordered.map((r) => r.fixed), backgroundColor: '#4fb276', borderRadius: 3, maxBarThickness: 42 },
      { label: 'Falso positivo / ignorado', data: ordered.map((r) => r.dismissed), backgroundColor: '#5b6470', borderRadius: 3, maxBarThickness: 42 },
      { label: 'Abertos', data: ordered.map((r) => r.open), backgroundColor: '#d84a56', borderRadius: 3, maxBarThickness: 42 },
    ],
  };
};

/** Colunas empilhadas com legenda embaixo (evolução das correções). */
export const STACKED_COLUMN_OPTIONS: ChartOptions<'bar'> = {
  plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 12 } } },
  scales: {
    x: { stacked: true, grid: { display: false } },
    y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } },
  },
};

// ---------- relatórios das abas do Painel ----------

/** Rosca genérica a partir de { chave: quantidade }, com rótulo e cor por chave (fora da ordem: some). */
export const countDoughnut = (
  counts: Partial<Record<string, number>>,
  order: string[],
  labelOf: Record<string, string>,
  colorOf: Record<string, string>
): ChartData<'doughnut'> => ({
  labels: order.map((k) => labelOf[k] ?? k),
  datasets: [{ data: order.map((k) => counts[k] ?? 0), backgroundColor: order.map((k) => colorOf[k] ?? INFO), borderColor: '#191a1c', borderWidth: 2 }],
});

export const SCAN_STATUS_ORDER = ['COMPLETED', 'RUNNING', 'PENDING', 'CANCELED', 'FAILED'];
export const SCAN_STATUS_COLOR: Record<string, string> = {
  COMPLETED: '#4fb276', RUNNING: '#79b8ff', PENDING: '#85858b', CANCELED: '#e5b24c', FAILED: '#f2777b',
};
export const ENVIRONMENT_ORDER = ['DEVELOPMENT', 'STAGING', 'PRODUCTION'];
export const ENVIRONMENT_COLOR: Record<string, string> = { DEVELOPMENT: '#4fb276', STAGING: '#c5a66c', PRODUCTION: '#d84a56' };

/** { "AAAA-MM-DD": quantas varreduras } a partir da data de criação (para a linha de 30 dias). */
export const scansPerDay = (scans: Pick<Scan, 'createdAt'>[]): Record<string, number> => {
  const days: Record<string, number> = {};
  for (const scan of scans) {
    const key = new Date(scan.createdAt).toISOString().slice(0, 10);
    days[key] = (days[key] ?? 0) + 1;
  }
  return days;
};

/** Minutos médios de cada tipo de teste, só das varreduras que terminaram (início e fim conhecidos). */
export const avgDurationBar = (scans: Scan[]): ChartData<'bar'> => {
  const sums: Record<string, { total: number; n: number }> = {};
  for (const scan of scans) {
    if (scan.status !== 'COMPLETED' || !scan.startedAt || !scan.finishedAt) continue;
    const minutes = (new Date(scan.finishedAt).getTime() - new Date(scan.startedAt).getTime()) / 60000;
    if (!Number.isFinite(minutes) || minutes < 0) continue;
    const entry = (sums[scan.objectiveLabel] ??= { total: 0, n: 0 });
    entry.total += minutes;
    entry.n += 1;
  }
  const avg = Object.fromEntries(Object.entries(sums).map(([k, { total, n }]) => [k, Math.round((total / n) * 10) / 10]));
  const chart = countBar(avg, (k) => k, '#79b8ff');
  chart.datasets[0].label = 'Minutos (média)';
  return chart;
};

/** Achados da varredura concluída mais recente de cada alvo (o estado atual de cada site). */
export const findingsByTargetBar = (scans: Scan[], limit = 8): ChartData<'bar'> => {
  const latest = new Map<string, number>();
  for (const scan of scans) {
    // a lista vem da mais nova para a mais antiga: a primeira de cada alvo é a atual
    if ((scan.status === 'COMPLETED' || scan.status === 'CANCELED') && !latest.has(scan.targetUrl)) {
      latest.set(scan.targetUrl, scan.findingsCount);
    }
  }
  const top = [...latest.entries()].sort(([, a], [, b]) => b - a).slice(0, limit);
  return countBar(Object.fromEntries(top.map(([url, n]) => [url.replace(/^https?:\/\//, ''), n])), (k) => k, PRIMARY);
};

export const DOUGHNUT_OPTIONS: ChartOptions<'doughnut'> = {
  cutout: '62%',
  plugins: { legend: { position: 'right', labels: { boxWidth: 10, padding: 12 } } },
};

/** Rótulo longo (título de falha, URL) abreviado no eixo; o completo aparece ao passar o mouse. */
const LABEL_MAX = 34;
function shortTick(this: { getLabelForValue(value: number): string }, value: string | number): string {
  const label = String(this.getLabelForValue(Number(value)) ?? value);
  return label.length > LABEL_MAX ? `${label.slice(0, LABEL_MAX - 1)}…` : label;
}

export const BAR_OPTIONS: ChartOptions<'bar'> = {
  indexAxis: 'y',
  maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  scales: {
    x: { beginAtZero: true, ticks: { precision: 0 } },
    y: { grid: { display: false }, ticks: { autoSkip: false, callback: shortTick } },
  },
};

export const LINE_OPTIONS: ChartOptions<'line'> = {
  plugins: { legend: { display: false } },
  scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { ticks: { maxTicksLimit: 10 } } },
};

/** Linha com legenda embaixo (várias séries, ex.: uma por URL). */
export const LINE_LEGEND_OPTIONS: ChartOptions<'line'> = {
  plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 12 } } },
  scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { title: { display: true, text: 'execução' } } },
};

/** Barras em pé (faixas, como o histograma de CVSS). */
export const COLUMN_OPTIONS: ChartOptions<'bar'> = {
  plugins: { legend: { display: false } },
  scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { grid: { display: false } } },
};

/** Total de valores de um gráfico, para decidir o estado vazio. */
export const chartTotal = (data: { datasets: { data: unknown[] }[] } | null): number =>
  (data?.datasets ?? []).reduce(
    (sum, dataset) => sum + dataset.data.reduce<number>((acc, v) => acc + (typeof v === 'number' ? v : 0), 0),
    0
  );
