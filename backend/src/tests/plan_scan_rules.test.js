import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import { fakeReq, fakeRes, dnsAnswer } from './helpers.js';

// Regras de plano aplicadas às varreduras (constants/plans.js):
// Free = 1 varredura por dia, sempre o scan básico e só a mais recente visível.

let scansToday = 0;
let latestIds = ['scan-recente'];

const prismaMock = {
  scan: {
    count: mock.fn(async () => scansToday),
    create: mock.fn(async ({ data }) => ({ id: 'scan-new', status: 'PENDING', createdAt: new Date(), ...data })),
    findMany: mock.fn(async ({ take, select }) =>
      select?._count
        ? [{ id: 'scan-recente', resolvedIps: '', objective: 'BASIC_SCAN', _count: { findings: 0 } }].slice(0, take ?? 99)
        : latestIds.slice(0, take ?? 99).map((id) => ({ id }))
    ),
    update: mock.fn(async () => ({})),
    updateMany: mock.fn(async () => ({ count: 1 })),
  },
  finding: { findMany: mock.fn(async () => []), createMany: mock.fn(async () => ({ count: 0 })) },
  target: { findMany: mock.fn(async () => []) },
  auditLog: { create: mock.fn(async () => ({})) },
  $transaction: mock.fn(async (ops) => Promise.all(ops)),
};
mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });

const { default: scanController } = await import('../controllers/scan_controllers.js');
const { createScanSchema } = await import('../validators/scan_validator.js');
const { planRules, isObjectiveAllowed, startOfToday } = await import('../constants/plans.js');
const { SCAN_OBJECTIVES } = await import('../constants/scan_objectives.js');

beforeEach(() => {
  mock.restoreAll();
  scansToday = 0;
  latestIds = ['scan-recente'];
  for (const model of Object.values(prismaMock)) {
    if (typeof model === 'function') model.mock.resetCalls();
    else for (const fn of Object.values(model)) fn.mock.resetCalls();
  }
  mock.method(dns, 'lookup', async () => dnsAnswer('127.0.0.1'));
  mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({ findings: [] }), { status: 200 }));
});

const create = async (plan, body) => {
  const res = fakeRes();
  await scanController.createScan(
    fakeReq({ userId: 'u1', userPlan: plan, body: { targetUrl: 'http://localhost:3000', authorizationConfirmed: true, ...body } }),
    res
  );
  return res;
};

// ---------- regras ----------

test('plano ausente ou desconhecido cai no Free (mais restrito)', () => {
  assert.equal(planRules(undefined), planRules('FREE'));
  assert.equal(planRules('GOLD'), planRules('FREE'));
});

test('o objetivo do Free existe e não envia ataque', () => {
  const basic = SCAN_OBJECTIVES[planRules('FREE').defaultObjective];
  assert.ok(basic);
  assert.equal(basic.requiresActiveScan, false);
  assert.deepEqual(basic.zap.activeScannerIds, []);
});

test('Premium pode qualquer objetivo; Free só o básico', () => {
  for (const key of Object.keys(SCAN_OBJECTIVES)) assert.ok(isObjectiveAllowed('PREMIUM', key), key);
  assert.ok(isObjectiveAllowed('FREE', 'BASIC_SCAN'));
  assert.ok(!isObjectiveAllowed('FREE', 'SQL_INJECTION'));
  assert.ok(!isObjectiveAllowed('FREE', 'FULL_SCAN'));
});

test('o limite diário zera à meia-noite', () => {
  const start = startOfToday(new Date(2026, 10, 16, 15, 30));
  assert.equal(start.getHours(), 0);
  assert.equal(start.getDate(), 16);
});

test('validator aceita varredura sem objetivo (o plano decide)', () => {
  const parsed = createScanSchema.parse({ targetUrl: 'http://localhost:3000', authorizationConfirmed: true });
  assert.equal(parsed.objective, undefined);
});

// ---------- criação ----------

test('Free sem objetivo registra o scan básico', async () => {
  const res = await create('FREE', {});
  assert.equal(res.statusCode, 201);
  assert.equal(res.body.scan.objective, 'BASIC_SCAN');
});

test('Free escolhendo outro objetivo recebe PREMIUM_REQUIRED e nada é gravado', async () => {
  const res = await create('FREE', { objective: 'SQL_INJECTION' });
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, 'PREMIUM_REQUIRED');
  assert.equal(prismaMock.scan.create.mock.callCount(), 0);
});

test('Free na segunda varredura do dia recebe DAILY_SCAN_LIMIT', async () => {
  scansToday = 1;
  const res = await create('FREE', {});
  assert.equal(res.statusCode, 429);
  assert.equal(res.body.code, 'DAILY_SCAN_LIMIT');
  assert.equal(prismaMock.scan.create.mock.callCount(), 0);
  // contou só as varreduras de hoje deste usuário
  const where = prismaMock.scan.count.mock.calls[0].arguments[0].where;
  assert.equal(where.userId, 'u1');
  assert.equal(where.createdAt.gte.getTime(), startOfToday().getTime());
});

test('Premium não tem limite diário e usa a varredura completa por padrão', async () => {
  scansToday = 50;
  const res = await create('PREMIUM', {});
  assert.equal(res.statusCode, 201);
  assert.equal(res.body.scan.objective, 'FULL_SCAN');
  assert.equal(prismaMock.scan.count.mock.callCount(), 0);
});

// ---------- leitura ----------

test('Free lista só a varredura mais recente; Premium lista todas', async () => {
  await scanController.listScans(fakeReq({ userId: 'u1', userPlan: 'FREE' }), fakeRes());
  assert.equal(prismaMock.scan.findMany.mock.calls.at(-1).arguments[0].take, 1);

  await scanController.listScans(fakeReq({ userId: 'u1', userPlan: 'PREMIUM' }), fakeRes());
  assert.equal(prismaMock.scan.findMany.mock.calls.at(-1).arguments[0].take, undefined);
});

test('Free não abre uma varredura antiga (histórico é Premium)', async () => {
  const res = fakeRes();
  await scanController.getScanById(
    fakeReq({ userId: 'u1', userPlan: 'FREE', resource: { id: 'scan-antigo', safeMode: false } }),
    res
  );
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, 'PREMIUM_REQUIRED');
});

test('Free abre a varredura mais recente', async () => {
  const res = fakeRes();
  await scanController.getScanById(
    fakeReq({ userId: 'u1', userPlan: 'FREE', resource: { id: 'scan-recente', safeMode: false, objective: 'BASIC_SCAN' } }),
    res
  );
  assert.equal(res.statusCode, 200);
});

test('estatísticas do Free consideram só a varredura visível', async () => {
  await scanController.getScanStats(fakeReq({ userId: 'u1', userPlan: 'FREE' }), fakeRes());
  const findingsWhere = prismaMock.finding.findMany.mock.calls.at(-1).arguments[0].where;
  assert.deepEqual(findingsWhere.scan.id, { in: ['scan-recente'] });
});

// ---------- execução ----------

test('varredura de objetivo Premium não roda depois de voltar ao Free', async () => {
  const res = fakeRes();
  await scanController.runScan(
    fakeReq({
      userId: 'u1',
      userPlan: 'FREE',
      body: {},
      resource: { id: 's1', objective: 'SQL_INJECTION', environment: 'DEVELOPMENT', targetUrl: 'http://localhost:3000', suspiciousEnvironment: false },
    }),
    res
  );
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, 'PREMIUM_REQUIRED');
  assert.equal(prismaMock.scan.updateMany.mock.callCount(), 0);
});
