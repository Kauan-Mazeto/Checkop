import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import { fakeReq, fakeRes, dnsAnswer } from './helpers.js';

const prismaMock = {
  target: {
    findUnique: mock.fn(async () => null),
    count: mock.fn(async () => 0),
    create: mock.fn(async ({ data }) => ({ id: 'target-1', verifiedAt: null, lastCheckedAt: null, createdAt: new Date(), ...data })),
    update: mock.fn(async () => ({})),
  },
  auditLog: {
    create: mock.fn(async () => ({})),
    deleteMany: mock.fn(async () => ({ count: 3 })),
  },
  loginAttempt: { deleteMany: mock.fn(async () => ({ count: 2 })) },
  $transaction: mock.fn(async (ops) => Promise.all(ops)),
};

mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });

const { default: targetController } = await import('../controllers/target_controllers.js');
const { purgeExpiredRecords, retentionCutoff } = await import('../lib/retention.js');

const resetAll = () => {
  mock.restoreAll();
  for (const model of Object.values(prismaMock)) {
    if (typeof model === 'function') model.mock.resetCalls();
    else for (const fn of Object.values(model)) fn.mock.resetCalls();
  }
  prismaMock.target.findUnique.mock.mockImplementation(async () => null);
  prismaMock.target.count.mock.mockImplementation(async () => 0);
  mock.method(dns, 'lookup', async () => dnsAnswer('93.184.216.34'));
};

beforeEach(resetAll);

const createTarget = async (body) => {
  const res = fakeRes();
  await targetController.createTarget(fakeReq({ userId: 'user-1', body }), res);
  return res;
};

// ---------- cadastro de alvo ----------

test('cadastrar alvo público devolve as instruções e registra auditoria', async () => {
  const res = await createTarget({ url: 'https://www.meusite.com', method: 'DNS_TXT' });

  assert.equal(res.statusCode, 201);
  assert.equal(res.body.target.hostname, 'meusite.com');
  assert.equal(res.body.target.scope, 'DOMAIN');
  assert.equal(res.body.target.verified, false);
  assert.match(res.body.target.instructions.recordValue, /^checkop-verification=[0-9a-f]{48}$/);
  assert.equal(prismaMock.auditLog.create.mock.calls[0].arguments[0].data.action, 'TARGET_CREATED');
});

test('localhost não precisa (nem pode) ser cadastrado como alvo', async () => {
  const res = await createTarget({ url: 'http://localhost:3000', method: 'HTTP_FILE' });
  assert.equal(res.statusCode, 400);
  assert.equal(prismaMock.target.create.mock.callCount(), 0);
});

test('domínio público que resolve para rede interna é recusado', async () => {
  mock.method(dns, 'lookup', async () => dnsAnswer('192.168.0.5'));
  const res = await createTarget({ url: 'https://interno.meusite.com', method: 'HTTP_FILE' });
  assert.equal(res.statusCode, 400);
});

test('alvo duplicado devolve 409 com o existente', async () => {
  prismaMock.target.findUnique.mock.mockImplementation(async () => ({
    id: 'target-0', hostname: 'meusite.com', scope: 'DOMAIN', verificationMethod: 'DNS_TXT', verificationToken: 't',
  }));
  const res = await createTarget({ url: 'https://meusite.com', method: 'DNS_TXT' });
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.target.id, 'target-0');
});

test('limite de alvos por conta', async () => {
  prismaMock.target.count.mock.mockImplementation(async () => 20);
  const res = await createTarget({ url: 'https://meusite.com', method: 'DNS_TXT' });
  assert.equal(res.statusCode, 400);
});

// ---------- verificação ----------

const pendingTarget = {
  id: 'target-1', userId: 'user-1', hostname: 'meusite.com', scope: 'DOMAIN',
  verificationMethod: 'DNS_TXT', verificationToken: 'tok', verifiedAt: null,
};

const verify = async () => {
  const res = fakeRes();
  await targetController.verifyTarget(fakeReq({ userId: 'user-1', resource: pendingTarget }), res);
  return res;
};

test('verificação com o TXT publicado marca o alvo como verificado', async () => {
  mock.method(dns, 'resolveTxt', async () => [['checkop-verification=tok']]);
  prismaMock.target.findUnique.mock.mockImplementation(async () => ({ ...pendingTarget, verifiedAt: new Date() }));

  const res = await verify();

  assert.equal(res.statusCode, 200);
  assert.ok(prismaMock.target.update.mock.calls[0].arguments[0].data.verifiedAt instanceof Date);
  assert.equal(prismaMock.auditLog.create.mock.calls[0].arguments[0].data.action, 'TARGET_VERIFIED');
});

test('verificação sem o TXT responde 422 e registra a falha', async () => {
  mock.method(dns, 'resolveTxt', async () => []);
  prismaMock.target.findUnique.mock.mockImplementation(async () => pendingTarget);

  const res = await verify();

  assert.equal(res.statusCode, 422);
  assert.equal(res.body.code, 'VERIFICATION_NOT_FOUND');
  assert.equal(prismaMock.auditLog.create.mock.calls[0].arguments[0].data.action, 'TARGET_VERIFICATION_FAILED');
});

// ---------- retenção (Marco Civil art. 15 / LGPD) ----------

test('corte de retenção é 6 meses antes de agora', () => {
  assert.equal(retentionCutoff(new Date('2026-11-09T12:00:00Z')).toISOString(), '2026-05-09T12:00:00.000Z');
});

test('limpeza apaga auditoria e tentativas de login mais antigas que o corte', async () => {
  const result = await purgeExpiredRecords(new Date('2026-11-09T12:00:00Z'));

  const [{ arguments: [args] }] = prismaMock.auditLog.deleteMany.mock.calls;
  assert.equal(args.where.createdAt.lt.toISOString(), '2026-05-09T12:00:00.000Z');
  assert.equal(prismaMock.loginAttempt.deleteMany.mock.callCount(), 1);
  assert.deepEqual(result, { auditLogs: 3, loginAttempts: 2 });
});
