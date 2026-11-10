import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { fakeReq, fakeRes } from './helpers.js';

process.env.JWT_SECRET ??= 'segredo-de-teste';
process.env.EXPIRES_IN ??= '1h';

const googlePayload = { sub: 'google-123', email: 'novo@exemplo.com', name: 'Novo', email_verified: true };

const prismaMock = {
  user: {
    findUnique: mock.fn(async () => null),
    create: mock.fn(async ({ data }) => ({ id: 'user-1', role: 'DEV', tokenVersion: 0, ...data })),
    update: mock.fn(async ({ data }) => ({ id: 'user-1', role: 'DEV', tokenVersion: 0, ...data })),
    delete: mock.fn(async () => ({})),
  },
  termsAcceptance: {
    findUnique: mock.fn(async () => null),
    create: mock.fn(async () => ({})),
  },
  loginAttempt: {
    create: mock.fn(async () => ({})),
    updateMany: mock.fn(async () => ({ count: 1 })),
  },
  $transaction: mock.fn(async (ops) => Promise.all(ops)),
};

mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });
mock.module(new URL('../lib/google_client.js', import.meta.url).href, {
  namedExports: { verifyGoogleToken: async () => googlePayload },
});
mock.module(new URL('../lib/mailer.js', import.meta.url).href, {
  namedExports: { sendPasswordResetEmail: async () => {} },
});

const { default: authController } = await import('../controllers/auth_controllers.js');
const { googleLoginSchema } = await import('../validators/auth_validator.js');

const resetMocks = () => {
  for (const model of Object.values(prismaMock)) {
    if (typeof model === 'function') model.mock.resetCalls();
    else for (const fn of Object.values(model)) fn.mock.resetCalls();
  }
  prismaMock.user.findUnique.mock.mockImplementation(async () => null);
  prismaMock.termsAcceptance.findUnique.mock.mockImplementation(async () => null);
};

beforeEach(resetMocks);

// ---------- B7: aceite de termos no login com Google ----------

test('schema do login Google aceita termsAccepted opcional', () => {
  assert.equal(googleLoginSchema.safeParse({ credential: 'x' }).success, true);
  assert.equal(googleLoginSchema.safeParse({ credential: 'x', termsAccepted: true }).success, true);
  assert.equal(googleLoginSchema.safeParse({ credential: 'x', termsAccepted: 'sim' }).success, false);
});

test('primeiro login Google sem aceite: 400 TERMS_REQUIRED e nenhuma conta criada', async () => {
  const res = fakeRes();
  await authController.googleLogin(fakeReq({ body: { credential: 'x' } }), res);

  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, 'TERMS_REQUIRED');
  assert.equal(prismaMock.user.create.mock.callCount(), 0);
});

test('primeiro login Google com aceite: cria conta e registra o aceite', async () => {
  const res = fakeRes();
  await authController.googleLogin(fakeReq({ body: { credential: 'x', termsAccepted: true } }), res);

  assert.equal(res.statusCode, 200);
  assert.equal(prismaMock.user.create.mock.callCount(), 1);
  assert.equal(prismaMock.termsAcceptance.create.mock.callCount(), 1);
  assert.equal(prismaMock.termsAcceptance.create.mock.calls[0].arguments[0].data.userId, 'user-1');
});

test('usuário Google que já aceitou os termos entra sem reenviar o aceite', async () => {
  prismaMock.user.findUnique.mock.mockImplementation(async () => ({
    id: 'user-1', email: googlePayload.email, googleId: 'google-123', role: 'DEV', tokenVersion: 0,
  }));
  prismaMock.termsAcceptance.findUnique.mock.mockImplementation(async () => ({ id: 't-1' }));

  const res = fakeRes();
  await authController.googleLogin(fakeReq({ body: { credential: 'x' } }), res);

  assert.equal(res.statusCode, 200);
  assert.equal(prismaMock.termsAcceptance.create.mock.callCount(), 0);
});

test('conta Google antiga sem aceite registrado precisa aceitar no próximo login', async () => {
  prismaMock.user.findUnique.mock.mockImplementation(async () => ({
    id: 'user-1', email: googlePayload.email, googleId: 'google-123', role: 'DEV', tokenVersion: 0,
  }));

  const res = fakeRes();
  await authController.googleLogin(fakeReq({ body: { credential: 'x' } }), res);

  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, 'TERMS_REQUIRED');
});

// ---------- B8: exclusão de conta anonimiza o log de login ----------

test('excluir conta troca o e-mail dos LoginAttempt e apaga o usuário na mesma transação', async () => {
  prismaMock.user.findUnique.mock.mockImplementation(async () => ({
    id: 'user-1', email: 'alguem@exemplo.com', password: null,
  }));

  const res = fakeRes();
  await authController.deleteAccount(
    fakeReq({ userId: 'user-1', body: { confirmation: 'EXCLUIR MINHA CONTA' } }),
    res
  );

  assert.equal(res.statusCode, 200);
  assert.equal(prismaMock.$transaction.mock.callCount(), 1);

  const [{ arguments: [updateArgs] }] = prismaMock.loginAttempt.updateMany.mock.calls;
  assert.deepEqual(updateArgs.where, { OR: [{ userId: 'user-1' }, { email: 'alguem@exemplo.com' }] });
  assert.notEqual(updateArgs.data.email, 'alguem@exemplo.com');
  assert.equal(prismaMock.user.delete.mock.callCount(), 1);
});

test('confirmação errada não apaga nada', async () => {
  prismaMock.user.findUnique.mock.mockImplementation(async () => ({
    id: 'user-1', email: 'alguem@exemplo.com', password: null,
  }));

  const res = fakeRes();
  await authController.deleteAccount(fakeReq({ userId: 'user-1', body: { confirmation: 'sim' } }), res);

  assert.equal(res.statusCode, 400);
  assert.equal(prismaMock.$transaction.mock.callCount(), 0);
});
