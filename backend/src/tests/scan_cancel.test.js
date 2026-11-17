import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { fakeReq, fakeRes } from './helpers.js';

// Cancelar varredura: para as ferramentas e guarda o que já foi verificado.

const prismaMock = {
  scan: { update: mock.fn(async ({ data }) => data) },
  auditLog: { create: mock.fn(async () => ({})) },
};
mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });

let engineFails = false;
const cancelEngineJob = mock.fn(async () => {
  if (engineFails) throw new Error('motor fora');
  return { running: true };
});
mock.module(new URL('../lib/py/security_engine_client.js', import.meta.url).href, {
  namedExports: {
    cancelEngineJob,
    runNucleiScan: async () => ({ findings: [] }),
    runZapScan: async () => ({ findings: [] }),
    runSubdomainEnum: async () => ({ findings: [] }),
    translateTexts: async () => ({}),
    updateNucleiTemplates: async () => ({}),
    engineHeaders: () => ({}),
    SecurityEngineError: class extends Error {},
  },
});

const { default: scanController } = await import('../controllers/scan_controllers.js');

const cancel = async (status) => {
  const res = fakeRes();
  await scanController.cancelScan(fakeReq({ resource: { id: 's1', status }, userId: 'u1' }), res);
  return res;
};

beforeEach(() => {
  engineFails = false;
  cancelEngineJob.mock.resetCalls();
  prismaMock.scan.update.mock.resetCalls();
});

test('em andamento: avisa o motor e responde 202 (o resultado parcial é salvo ao terminar)', async () => {
  const res = await cancel('RUNNING');
  assert.equal(res.statusCode, 202);
  assert.equal(cancelEngineJob.mock.calls[0].arguments[0], 's1');
  assert.equal(prismaMock.scan.update.mock.callCount(), 0);
});

test('ainda não começou: fica cancelada na hora', async () => {
  const res = await cancel('PENDING');
  assert.equal(res.statusCode, 200);
  assert.equal(prismaMock.scan.update.mock.calls[0].arguments[0].data.status, 'CANCELED');
  assert.equal(cancelEngineJob.mock.callCount(), 0);
});

test('já terminada não pode ser cancelada', async () => {
  for (const status of ['COMPLETED', 'FAILED', 'CANCELED']) {
    assert.equal((await cancel(status)).statusCode, 409, status);
  }
});

test('motor fora do ar não impede o cancelamento', async () => {
  engineFails = true;
  assert.equal((await cancel('RUNNING')).statusCode, 202);
});
