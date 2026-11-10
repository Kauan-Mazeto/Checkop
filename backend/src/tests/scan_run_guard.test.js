import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import { fakeReq, fakeRes, dnsAnswer } from './helpers.js';

// Regras de execução de varredura:
// B3/B5 - destino suspeito ou que mudou para rede interna é recusado
// Etapa 2 - alvo público só com propriedade verificada (conferida de novo no run)
//         - ataque ativo em alvo público só com opt-in explícito

const TOKEN = 'tok123';
const verifiedTarget = {
  id: 'target-1',
  userId: 'user-1',
  hostname: 'exemplo.com',
  scope: 'DOMAIN',
  verificationMethod: 'DNS_TXT',
  verificationToken: TOKEN,
  verifiedAt: new Date('2026-11-01'),
};

const prismaMock = {
  scan: {
    create: mock.fn(async ({ data }) => ({ id: 'scan-new', status: 'PENDING', createdAt: new Date(), ...data })),
    update: mock.fn(async () => ({})),
    updateMany: mock.fn(async () => ({ count: 1 })),
    findUnique: mock.fn(async () => ({ status: 'COMPLETED' })),
  },
  target: {
    findMany: mock.fn(async () => [verifiedTarget]),
    findUnique: mock.fn(async () => verifiedTarget),
    update: mock.fn(async () => ({})),
  },
  finding: { createMany: mock.fn(async () => ({ count: 0 })) },
  auditLog: { create: mock.fn(async () => ({})) },
  $transaction: mock.fn(async (ops) => Promise.all(ops)),
};

mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });

const { default: scanController } = await import('../controllers/scan_controllers.js');
const { runScanAuthSchema } = await import('../validators/scan_validator.js');

const publicScan = {
  id: 'scan-1',
  userId: 'user-1',
  targetUrl: 'https://www.exemplo.com',
  environment: 'PRODUCTION',
  safeMode: true,
  objective: 'SQL_INJECTION',
  suspiciousEnvironment: false,
  targetId: 'target-1',
  status: 'PENDING',
};
const localScan = { ...publicScan, targetUrl: 'http://localhost:3000', environment: 'DEVELOPMENT', safeMode: false, targetId: null };

const engineCalls = [];
const flush = () => new Promise((resolve) => setTimeout(resolve, 20));

const mockPublicDns = () => mock.method(dns, 'lookup', async () => dnsAnswer('93.184.216.34'));
const mockTxt = (...values) => mock.method(dns, 'resolveTxt', async () => values.map((v) => [v]));

const run = async (scan, body = {}) => {
  const res = fakeRes();
  await scanController.runScan(fakeReq({ resource: scan, body, userId: 'user-1' }), res);
  await flush(); // executeScan roda em segundo plano
  return res;
};

const lastClaim = () => prismaMock.scan.updateMany.mock.calls.at(-1)?.arguments[0];
const lastAuditAction = () => prismaMock.auditLog.create.mock.calls.at(-1)?.arguments[0].data.action;

beforeEach(() => {
  mock.restoreAll();
  for (const model of Object.values(prismaMock)) {
    if (typeof model === 'function') model.mock.resetCalls();
    else for (const fn of Object.values(model)) fn.mock.resetCalls();
  }
  prismaMock.target.findMany.mock.mockImplementation(async () => [verifiedTarget]);
  prismaMock.target.findUnique.mock.mockImplementation(async () => verifiedTarget);
  engineCalls.length = 0;
  mock.method(globalThis, 'fetch', async (url, init) => {
    engineCalls.push({ url: String(url), body: JSON.parse(init.body) });
    return new Response(JSON.stringify({ findings: [] }), { status: 200 });
  });
});

// ---------- B3/B5 ----------

test('varredura já marcada como suspeita não executa (403) e nem tenta reservar', async () => {
  const res = await run({ ...publicScan, suspiciousEnvironment: true });
  assert.equal(res.statusCode, 403);
  assert.equal(prismaMock.scan.updateMany.mock.callCount(), 0);
});

test('DNS que passou a apontar para rede interna bloqueia o run e marca a varredura', async () => {
  mock.method(dns, 'lookup', async () => dnsAnswer('127.0.0.1'));

  const res = await run(publicScan);

  assert.equal(res.statusCode, 403);
  assert.equal(prismaMock.scan.updateMany.mock.callCount(), 0);
  assert.equal(prismaMock.scan.update.mock.calls[0].arguments[0].data.suspiciousEnvironment, true);
  assert.equal(lastAuditAction(), 'SCAN_BLOCKED');
});

test('domínio que deixou de resolver bloqueia o run', async () => {
  mock.method(dns, 'lookup', async () => {
    throw new Error('ENOTFOUND');
  });
  assert.equal((await run(publicScan)).statusCode, 403);
});

// ---------- verificação de propriedade ----------

test('alvo público cuja prova de controle foi removida é bloqueado e perde a verificação', async () => {
  mockPublicDns();
  mockTxt('outro-valor');

  const res = await run(publicScan);

  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, 'TARGET_NOT_VERIFIED');
  assert.equal(prismaMock.target.update.mock.calls[0].arguments[0].data.verifiedAt, null);
  assert.equal(prismaMock.scan.updateMany.mock.callCount(), 0);
});

test('alvo público sem nenhum alvo cadastrado é bloqueado', async () => {
  mockPublicDns();
  prismaMock.target.findMany.mock.mockImplementation(async () => []);

  const res = await run({ ...publicScan, targetId: null });

  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, 'TARGET_NOT_VERIFIED');
});

// ---------- opt-in de varredura ativa ----------

test('objetivo de ataque (SQLi) em alvo público SEM opt-in é recusado: ACTIVE_SCAN_REQUIRED', async () => {
  mockPublicDns();
  mockTxt(`checkop-verification=${TOKEN}`);

  const res = await run(publicScan);

  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, 'ACTIVE_SCAN_REQUIRED');
  assert.equal(prismaMock.scan.updateMany.mock.callCount(), 0);
  assert.equal(engineCalls.length, 0);
});

test('objetivo sem ataque em alvo público SEM opt-in roda só passivo (ZAP sem ativo, Nuclei seguro)', async () => {
  mockPublicDns();
  mockTxt(`checkop-verification=${TOKEN}`);

  const res = await run({ ...publicScan, objective: 'EXPOSED_FILES' });

  assert.equal(res.statusCode, 202);
  assert.equal(res.body.scan.activeScan, false);
  assert.equal(lastClaim().data.activeScanConfirmedAt, null);
  const zap = engineCalls.find((c) => c.url.endsWith('/scans/zap'));
  const nuclei = engineCalls.find((c) => c.url.endsWith('/scans/nuclei'));
  assert.equal(zap.body.activeScan, false);
  assert.equal(nuclei.body.safeMode, true);
});

test('alvo público verificado COM opt-in registra a autorização e libera o ataque', async () => {
  mockPublicDns();
  mockTxt(`checkop-verification=${TOKEN}`);

  const res = await run(publicScan, { activeScanConfirmed: true, hostingTermsConfirmed: true });

  assert.equal(res.statusCode, 202);
  assert.equal(res.body.scan.activeScan, true);
  assert.ok(lastClaim().data.activeScanConfirmedAt instanceof Date);
  assert.equal(lastClaim().data.activeScanConfirmationIp, '203.0.113.10');
  assert.equal(engineCalls.find((c) => c.url.endsWith('/scans/zap')).body.activeScan, true);
  assert.ok(prismaMock.auditLog.create.mock.calls.some((c) => c.arguments[0].data.action === 'SCAN_STARTED'));
});

test('localhost dispensa verificação e opt-in (ambiente de desenvolvimento)', async () => {
  const res = await run(localScan);

  assert.equal(res.statusCode, 202);
  assert.equal(res.body.scan.activeScan, true);
  assert.equal(prismaMock.target.findUnique.mock.callCount(), 0);
  assert.equal(lastClaim().data.activeScanConfirmedAt, null); // opt-in só se registra em alvo público
});

test('validator: opt-in de ataque sem a declaração de hospedagem é recusado', () => {
  assert.equal(runScanAuthSchema.safeParse({ activeScanConfirmed: true }).success, false);
  assert.equal(
    runScanAuthSchema.safeParse({ activeScanConfirmed: true, hostingTermsConfirmed: true }).success,
    true
  );
  assert.equal(runScanAuthSchema.safeParse(undefined).success, true);
});

// ---------- createScan ----------

const create = async (targetUrl) => {
  const res = fakeRes();
  await scanController.createScan(
    fakeReq({ userId: 'user-1', body: { targetUrl, objective: 'SQL_INJECTION', authorizationConfirmed: true } }),
    res
  );
  return res;
};

test('criar varredura de site público sem alvo verificado: 403 TARGET_NOT_VERIFIED', async () => {
  mockPublicDns();
  prismaMock.target.findMany.mock.mockImplementation(async () => []);

  const res = await create('https://site-de-outra-pessoa.com');

  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, 'TARGET_NOT_VERIFIED');
  assert.equal(prismaMock.scan.create.mock.callCount(), 0);
  assert.equal(lastAuditAction(), 'SCAN_BLOCKED');
});

test('verificação de exemplo.com (DNS) cobre www.exemplo.com, mas não exemplo.com.evil.net', async () => {
  mockPublicDns();

  const ok = await create('https://www.exemplo.com/loja');
  assert.equal(ok.statusCode, 201);
  assert.equal(prismaMock.scan.create.mock.calls[0].arguments[0].data.targetId, 'target-1');

  const evil = await create('https://exemplo.com.evil.net');
  assert.equal(evil.statusCode, 403);
});

test('criar varredura em localhost não exige alvo', async () => {
  const res = await create('http://localhost:3000');
  assert.equal(res.statusCode, 201);
  assert.equal(prismaMock.target.findMany.mock.callCount(), 0);
});
