import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { fakeReq, fakeRes } from './helpers.js';

// RF-19 - comparação entre varreduras do mesmo alvo.

let candidates = [];
let findingsByScan = {};

const prismaMock = {
  scan: { findMany: mock.fn(async () => candidates) },
  finding: { findMany: mock.fn(async ({ where }) => findingsByScan[where.scanId] ?? []) },
  auditLog: { create: mock.fn(async () => ({})) },
};
mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });

const { compareFindings } = await import('../lib/scan_compare.js');
const { default: scanController } = await import('../controllers/scan_controllers.js');

const f = (title, affectedUrl, severity = 'HIGH', extra = {}) => ({
  id: `${title}-${affectedUrl}-${severity}`,
  title,
  affectedUrl,
  severity,
  tool: 'ZAP',
  owaspUrl: null,
  ...extra,
});

beforeEach(() => {
  candidates = [];
  findingsByScan = {};
  prismaMock.scan.findMany.mock.resetCalls();
  prismaMock.finding.findMany.mock.resetCalls();
});

// ---------- lógica ----------

test('separa novas, corrigidas e persistentes', () => {
  const before = [f('SQL Injection', 'http://a/busca'), f('Cookie sem HttpOnly', 'http://a/')];
  const after = [f('SQL Injection', 'http://a/busca'), f('XSS refletido', 'http://a/q')];
  const diff = compareFindings(before, after);
  assert.deepEqual(diff.summary, { added: 1, fixed: 1, persistent: 1 });
  assert.equal(diff.added[0].title, 'XSS refletido');
  assert.equal(diff.fixed[0].title, 'Cookie sem HttpOnly');
  assert.equal(diff.persistent[0].trend, 'SAME');
});

test('mesma falha com outro nome ou com query string é a mesma (não vira nova + corrigida)', () => {
  const before = [f('SQL Injection - MySQL', 'http://a/busca?q=1')];
  const after = [f('Generic SQLi', 'http://a/busca/?q=2')];
  assert.deepEqual(compareFindings(before, after).summary, { added: 0, fixed: 0, persistent: 1 });
});

test('persistente indica se piorou ou melhorou', () => {
  const worse = compareFindings([f('XSS', 'http://a/', 'MEDIUM')], [f('XSS', 'http://a/', 'CRITICAL')]);
  assert.equal(worse.persistent[0].trend, 'WORSE');
  assert.equal(worse.persistent[0].previousSeverity, 'MEDIUM');
  const better = compareFindings([f('XSS', 'http://a/', 'HIGH')], [f('XSS', 'http://a/', 'LOW')]);
  assert.equal(better.persistent[0].trend, 'BETTER');
});

test('listas vêm da mais grave para a mais leve', () => {
  const diff = compareFindings([], [f('A', 'http://a/1', 'LOW'), f('B', 'http://a/2', 'CRITICAL')]);
  assert.deepEqual(diff.added.map((x) => x.severity), ['CRITICAL', 'LOW']);
});

// ---------- rota ----------

const current = {
  id: 's2',
  userId: 'u1',
  targetUrl: 'http://localhost:3000',
  objective: 'SQL_INJECTION',
  status: 'COMPLETED',
  safeMode: false,
  createdAt: new Date('2026-11-16T12:00:00Z'),
};
const previous = { ...current, id: 's1', createdAt: new Date('2026-11-15T12:00:00Z') };

const callCompare = async (overrides = {}) => {
  const res = fakeRes();
  await scanController.compareScans(fakeReq({ userId: 'u1', resource: current, query: {}, ...overrides }), res);
  return res;
};

test('Free não compara (histórico é Premium)', async () => {
  const res = await callCompare({ userPlan: 'FREE' });
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, 'PREMIUM_REQUIRED');
});

test('sem ?with compara com a anterior do mesmo alvo e objetivo', async () => {
  candidates = [previous];
  findingsByScan = { s1: [f('Cookie sem HttpOnly', 'http://a/')], s2: [f('XSS', 'http://a/q')] };
  const res = await callCompare();
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.base.id, 's1');
  assert.deepEqual(res.body.summary, { added: 1, fixed: 1, persistent: 0 });

  const where = prismaMock.scan.findMany.mock.calls[0].arguments[0].where;
  assert.equal(where.targetUrl, current.targetUrl);
  assert.equal(where.objective, current.objective);
  assert.equal(where.userId, 'u1'); // só varreduras do próprio usuário
});

test('sem varredura anterior devolve base null', async () => {
  const res = await callCompare();
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.base, null);
});

test('?with de outro alvo/usuário não é aceito', async () => {
  candidates = [previous];
  const res = await callCompare({ query: { with: 'scan-de-outra-pessoa' } });
  assert.equal(res.statusCode, 404);
});

test('varredura que não terminou não é comparada', async () => {
  const res = await callCompare({ resource: { ...current, status: 'RUNNING' } });
  assert.equal(res.statusCode, 409);
});
