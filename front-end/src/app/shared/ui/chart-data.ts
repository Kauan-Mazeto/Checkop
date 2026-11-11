import { ChartData, ChartOptions } from 'chart.js';
import { FindingSeverity } from '../../core/services/scan.service';
import { SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_ORDER, TOOL_LABEL, shortOwasp } from './labels';

const PRIMARY = '#e5484d';
const INFO = '#6aa6f8';

/** Rosca de achados por severidade, sempre na ordem crítico → informativo. */
export const severityDoughnut = (counts: Partial<Record<string, number>>): ChartData<'doughnut'> => ({
  labels: SEVERITY_ORDER.map((s) => SEVERITY_LABEL[s]),
  datasets: [
    {
      data: SEVERITY_ORDER.map((s) => counts[s] ?? 0),
      backgroundColor: SEVERITY_ORDER.map((s) => SEVERITY_COLOR[s]),
      borderColor: '#151821',
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
        backgroundColor: 'rgba(229, 72, 77, 0.10)',
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

export const DOUGHNUT_OPTIONS: ChartOptions<'doughnut'> = {
  cutout: '62%',
  plugins: { legend: { position: 'right', labels: { boxWidth: 10, padding: 12 } } },
};

export const BAR_OPTIONS: ChartOptions<'bar'> = {
  indexAxis: 'y',
  plugins: { legend: { display: false } },
  scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } },
};

export const LINE_OPTIONS: ChartOptions<'line'> = {
  plugins: { legend: { display: false } },
  scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { ticks: { maxTicksLimit: 10 } } },
};

/** Total de valores de um gráfico, para decidir o estado vazio. */
export const chartTotal = (data: { datasets: { data: unknown[] }[] } | null): number =>
  (data?.datasets ?? []).reduce(
    (sum, dataset) => sum + dataset.data.reduce<number>((acc, v) => acc + (typeof v === 'number' ? v : 0), 0),
    0
  );
