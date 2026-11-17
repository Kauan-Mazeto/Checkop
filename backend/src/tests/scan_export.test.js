import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { fakeReq, fakeRes } from './helpers.js';

// Exportação consolidada do Painel (CSV de achados, CSV de varreduras, JSON).

let scans = [];
const prismaMock = {
  scan: { findMany: mock.fn(async () => scans) },
  auditLog: { create: mock.fn(async () => ({})) },
};
mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });

const { csvCell, findingsCsv, scansCsv, exportJson } = await import('../lib/scan_export.js');
const { default: scanController } = await import('../controllers/scan_controllers.js');

const finding = (over = {}) => ({
  id: 'f1', title: 'SQL Injection', severity: 'CRITICAL', status: 'OPEN', tool: 'ZAP', ruleId: '40018',
  affectedUrl: 'http://lab/item?id=1', parameter: 'id', cveId: null, cvssScore: 9.8,
  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvssSource: 'CWE', confidence: 'MEDIUM',
  owaspUrl: 'A03:2021 – Injection', description: 'Pode haver SQLi.', remediation: 'Use consultas parametrizadas.',
  rawRequest: 'GET /item?id=1', rawResponse: 'erro SQL', createdAt: new Date('2026-11-17T10:00:00Z'), ...over,
});
const scan = (over = {}) => ({
  id: 's1', targetUrl: 'http://lab', objective: 'SQL_INJECTION', environment: 'DEVELOPMENT', status: 'COMPLETED',
  safeMode: false, engineWarnings: null, createdAt: new Date('2026-11-17T10:00:00Z'),
  startedAt: new Date('2026-11-17T10:00:00Z'), finishedAt: new Date('2026-11-17T10:00:42Z'), findings: [finding()], ...over,
});

beforeEach(() => {
  scans = [scan()];
});

test('célula com ; aspas ou quebra de linha vai entre aspas', () => {
  assert.equal(csvCell('a;b'), '"a;b"');
  assert.equal(csvCell('diz "oi"'), '"diz ""oi"""');
  assert.equal(csvCell('linha1\nlinha2'), '"linha1\nlinha2"');
  assert.equal(csvCell(null), '');
});

test('texto que viraria fórmula no Excel é neutralizado (CSV injection)', () => {
  assert.equal(csvCell('=HYPERLINK("http://mal")'), `"'=HYPERLINK(""http://mal"")"`);
  assert.equal(csvCell('+55 11'), "'+55 11");
  assert.equal(csvCell('@cmd'), "'@cmd");
});

test('CSV de achados: BOM, ; como separador e uma linha por achado', () => {
  const csv = findingsCsv([scan({ findings: [finding(), finding({ id: 'f2', affectedUrl: 'http://lab/x' })] })]);
  assert.ok(csv.startsWith('﻿'));
  const lines = csv.trim().split('\r\n');
  assert.equal(lines.length, 3);
  assert.ok(lines[0].includes('severidade;cvss;vetor_cvss'));
  assert.ok(lines[1].includes('Crítico;9.8'));
});

test('CSV de varreduras traz duração e contagem por severidade', () => {
  const [, row] = scansCsv([scan()]).trim().split('\r\n');
  assert.ok(row.includes(';42;1;1;0;0;0;0'), row);
});

test('JSON tem totais e varreduras', () => {
  const json = exportJson([scan()], { generatedAt: new Date('2026-11-17T12:00:00Z') });
  assert.equal(json.totals.findings, 1);
  assert.equal(json.totals.bySeverity.CRITICAL, 1);
  assert.equal(json.scans[0].durationSeconds, 42);
});

const exportAs = async (format, overrides = {}) => {
  const res = fakeRes();
  await scanController.exportScans(fakeReq({ query: { format }, userId: 'u1', userRole: 'DEV', ...overrides }), res);
  return res;
};

test('Free não exporta (403)', async () => {
  const res = await exportAs('json', { userPlan: 'FREE' });
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, 'PREMIUM_REQUIRED');
});

test('formato inválido: 400', async () => {
  assert.equal((await exportAs('xlsx')).statusCode, 400);
});

test('Premium baixa o CSV como anexo', async () => {
  const res = await exportAs('findings-csv');
  assert.equal(res.statusCode, 200);
  assert.match(res.headers['content-type'], /text\/csv/);
  assert.match(res.headers['content-disposition'], /attachment; filename="checkop-achados-\d{4}-\d{2}-\d{2}\.csv"/);
  assert.ok(res.body.includes('SQL Injection'));
});

test('JSON agrupa a mesma falha e respeita o Modo Seguro da varredura', async () => {
  scans = [scan({ safeMode: true, findings: [finding(), finding({ id: 'f2', affectedUrl: 'http://lab/item?id=2' })] })];
  const res = await exportAs('json');
  const body = JSON.parse(res.body);
  assert.equal(body.scans[0].findings.length, 1);
  assert.equal(body.scans[0].findings[0].locations.length, 2);
  assert.equal(body.scans[0].findings[0].rawRequest, undefined); // Modo Seguro corta a PoC
});
