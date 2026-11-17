// Exportação consolidada (Painel > Exportar): todas as varreduras da conta em
// CSV (achados ou varreduras) e JSON. Funções puras; o controller busca os dados.

import { SCAN_OBJECTIVES } from '../constants/scan_objectives.js';

const SEVERITY_PT = { CRITICAL: 'Crítico', HIGH: 'Alto', MEDIUM: 'Médio', LOW: 'Baixo', INFO: 'Informativo' };
const STATUS_PT = { PENDING: 'Pendente', RUNNING: 'Em execução', COMPLETED: 'Concluída', FAILED: 'Falhou', CANCELED: 'Cancelada' };
const ENVIRONMENT_PT = { DEVELOPMENT: 'Desenvolvimento', STAGING: 'Homologação', PRODUCTION: 'Produção' };
const CONFIDENCE_PT = { LOW: 'Baixa', MEDIUM: 'Média', HIGH: 'Alta', CONFIRMED: 'Confirmada' };

// Excel em português usa ";" como separador; o BOM faz ele abrir em UTF-8 (acentos)
const SEPARATOR = ';';
const BOM = '﻿';

// CSV injection: célula que começa com = + - @ (ou tab/CR) vira fórmula no Excel.
// Texto vindo do alvo (título, URL, evidência) é controlado por terceiros.
const neutralize = (text) => (/^[=+\-@\t\r]/.test(text) ? `'${text}` : text);

export const csvCell = (value) => {
  if (value === null || value === undefined) return '';
  let text = value instanceof Date ? value.toISOString() : String(value);
  text = neutralize(text);
  return /[";\n\r]/.test(text) || text.includes(SEPARATOR) ? `"${text.replace(/"/g, '""')}"` : text;
};

export const toCsv = (header, rows) =>
  BOM + [header, ...rows].map((row) => row.map(csvCell).join(SEPARATOR)).join('\r\n') + '\r\n';

const iso = (date) => (date ? new Date(date).toISOString() : '');
const durationSeconds = (scan) =>
  scan.startedAt && scan.finishedAt ? Math.round((new Date(scan.finishedAt) - new Date(scan.startedAt)) / 1000) : '';
const objectiveLabel = (objective) => SCAN_OBJECTIVES[objective]?.label ?? objective;

const severityCounts = (findings) => {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const finding of findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  return counts;
};

/** Uma linha por achado (cada local é uma linha: dá para filtrar e somar na planilha). */
export const findingsCsv = (scans) =>
  toCsv(
    [
      'varredura_id', 'alvo', 'tipo_de_teste', 'data', 'status_varredura', 'severidade', 'cvss', 'vetor_cvss',
      'confianca', 'falha', 'url', 'parametro', 'ferramenta', 'regra', 'cve', 'owasp_top10', 'descricao', 'como_corrigir',
    ],
    scans.flatMap((scan) =>
      scan.findings.map((f) => [
        scan.id, scan.targetUrl, objectiveLabel(scan.objective), iso(scan.createdAt), STATUS_PT[scan.status] ?? scan.status,
        SEVERITY_PT[f.severity] ?? f.severity, f.cvssScore, f.cvssVector, CONFIDENCE_PT[f.confidence] ?? f.confidence,
        f.title, f.affectedUrl, f.parameter, f.tool, f.ruleId, f.cveId, f.owaspUrl, f.description,
        f.premiumLocked ? 'Disponível no plano Premium' : f.remediation,
      ]),
    ),
  );

/** Uma linha por varredura, com a contagem por severidade. */
export const scansCsv = (scans) =>
  toCsv(
    [
      'varredura_id', 'alvo', 'tipo_de_teste', 'ambiente', 'status', 'criada_em', 'iniciada_em', 'finalizada_em',
      'duracao_segundos', 'achados', 'critico', 'alto', 'medio', 'baixo', 'informativo',
    ],
    scans.map((scan) => {
      const counts = severityCounts(scan.findings);
      return [
        scan.id, scan.targetUrl, objectiveLabel(scan.objective), ENVIRONMENT_PT[scan.environment] ?? scan.environment,
        STATUS_PT[scan.status] ?? scan.status, iso(scan.createdAt), iso(scan.startedAt), iso(scan.finishedAt),
        durationSeconds(scan), scan.findings.length, counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW, counts.INFO,
      ];
    }),
  );

/** Tudo estruturado, para integrar com outras ferramentas. */
export const exportJson = (scans, { generatedAt = new Date(), language = null } = {}) => ({
  generatedAt: generatedAt.toISOString(),
  generator: 'Checkop',
  language,
  totals: {
    scans: scans.length,
    findings: scans.reduce((sum, scan) => sum + scan.findings.length, 0),
    bySeverity: severityCounts(scans.flatMap((scan) => scan.findings)),
  },
  scans: scans.map((scan) => ({
    id: scan.id,
    targetUrl: scan.targetUrl,
    objective: scan.objective,
    objectiveLabel: objectiveLabel(scan.objective),
    environment: scan.environment,
    status: scan.status,
    createdAt: scan.createdAt,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
    durationSeconds: durationSeconds(scan) || null,
    engineWarnings: scan.engineWarnings ? JSON.parse(scan.engineWarnings) : [],
    findings: scan.findings,
  })),
});

export const EXPORT_FORMATS = {
  'findings-csv': { type: 'text/csv; charset=utf-8', extension: 'csv', name: 'achados' },
  'scans-csv': { type: 'text/csv; charset=utf-8', extension: 'csv', name: 'varreduras' },
  json: { type: 'application/json; charset=utf-8', extension: 'json', name: 'relatorio-completo' },
};

export const exportFileName = (format, now = new Date()) => {
  const { name, extension } = EXPORT_FORMATS[format];
  return `checkop-${name}-${now.toISOString().slice(0, 10)}.${extension}`;
};
