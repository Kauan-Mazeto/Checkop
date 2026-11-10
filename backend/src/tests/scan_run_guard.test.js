import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import { fakeReq, fakeRes, dnsAnswer } from './helpers.js';

// B3/B5: o run de uma varredura deve ser recusado para alvos suspeitos,
// inclusive quando o DNS mudou depois do cadastro.
const prismaMock = {
  scan: {
    update: mock.fn(async () => ({})),
    updateMany: mock.fn(async () => ({ count: 0 })),
    findUnique: mock.fn(async () => ({ status: 'COMPLETED' })),
  },
};

mock.module(new URL('../lib/prisma.js', import.meta.url).href, {
  defaultExport: prismaMock,
});

const { default: scanController } = await import('../controllers/scan_controllers.js');

const baseScan = {
  id: 'scan-1',
  targetUrl: 'https://app.exemplo.com',
  suspiciousEnvironment: false,
  status: 'PENDING',
};

const runWith = async (scan) => {
  const res = fakeRes();
  await scanController.runScan(fakeReq({ resource: scan, body: {} }), res);
  return res;
};

beforeEach(() => {
  mock.restoreAll();
  prismaMock.scan.update.mock.resetCalls();
  prismaMock.scan.updateMany.mock.resetCalls();
});

test('varredura já marcada como suspeita não executa (403) e nem tenta reservar', async () => {
  const res = await runWith({ ...baseScan, suspiciousEnvironment: true });
  assert.equal(res.statusCode, 403);
  assert.equal(prismaMock.scan.updateMany.mock.callCount(), 0);
});

test('DNS que passou a apontar para rede interna bloqueia o run e marca a varredura', async () => {
  mock.method(dns, 'lookup', async () => dnsAnswer('127.0.0.1'));

  const res = await runWith(baseScan);

  assert.equal(res.statusCode, 403);
  assert.equal(prismaMock.scan.updateMany.mock.callCount(), 0);
  const [{ arguments: [updateArgs] }] = prismaMock.scan.update.mock.calls;
  assert.equal(updateArgs.data.suspiciousEnvironment, true);
});

test('domínio que deixou de resolver bloqueia o run', async () => {
  mock.method(dns, 'lookup', async () => {
    throw new Error('ENOTFOUND');
  });
  const res = await runWith(baseScan);
  assert.equal(res.statusCode, 403);
});

test('alvo público válido segue para a reserva atômica da varredura', async () => {
  mock.method(dns, 'lookup', async () => dnsAnswer('93.184.216.34'));

  const res = await runWith(baseScan);

  // o mock de updateMany devolve count 0 (já concluída), então esperamos o 409
  assert.equal(prismaMock.scan.updateMany.mock.callCount(), 1);
  assert.equal(res.statusCode, 409);
});

test('localhost continua liberado (política escolhida: só bloquear suspeitos)', async () => {
  const res = await runWith({ ...baseScan, targetUrl: 'http://localhost:3000' });
  assert.equal(prismaMock.scan.updateMany.mock.callCount(), 1);
  assert.notEqual(res.statusCode, 403);
});
