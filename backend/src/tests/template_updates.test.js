import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { fakeReq, fakeRes } from './helpers.js';

// RF-45 - atualização dos templates do Nuclei (motor simulado).

let engineFails = false;
mock.module(new URL('../lib/py/security_engine_client.js', import.meta.url).href, {
  namedExports: {
    updateNucleiTemplates: async () => {
      if (engineFails) throw new Error('Motor de segurança indisponível.');
      return { message: 'ok' };
    },
  },
});

const { runTemplateUpdate, templateUpdateStatus, resetTemplateUpdateState, scheduleTemplateUpdates } = await import('../lib/template_updates.js');
const { requireAdmin } = await import('../routes/admin_routes.js');

beforeEach(() => {
  engineFails = false;
  resetTemplateUpdateState();
});

test('atualização bem-sucedida registra a data', async () => {
  const result = await runTemplateUpdate();
  assert.equal(result.started, true);
  assert.ok(result.lastSuccessAt instanceof Date);
  assert.equal(result.lastError, null);
});

test('falha do motor fica registrada sem derrubar o servidor', async () => {
  engineFails = true;
  const result = await runTemplateUpdate();
  assert.equal(result.lastSuccessAt, null);
  assert.match(result.lastError, /indisponível/);
  assert.equal(templateUpdateStatus().running, false);
});

test('duas atualizações ao mesmo tempo: a segunda não roda', async () => {
  const first = runTemplateUpdate();
  const second = await runTemplateUpdate();
  assert.equal(second.started, false);
  await first;
});

test('só administrador acessa as rotas de administração', () => {
  let passed = false;
  const blocked = fakeRes();
  requireAdmin(fakeReq({ userRole: 'PENTESTER' }), blocked, () => (passed = true));
  assert.equal(blocked.statusCode, 403);
  assert.equal(passed, false);
  requireAdmin(fakeReq({ userRole: 'ADM' }), fakeRes(), () => (passed = true));
  assert.equal(passed, true);
});

test('NUCLEI_TEMPLATE_UPDATE_HOURS=0 desliga a atualização automática', () => {
  process.env.NUCLEI_TEMPLATE_UPDATE_HOURS = '0';
  assert.equal(scheduleTemplateUpdates(), null);
  delete process.env.NUCLEI_TEMPLATE_UPDATE_HOURS;
});
