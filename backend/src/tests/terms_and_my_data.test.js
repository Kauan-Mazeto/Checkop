import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { fakeReq, fakeRes } from './helpers.js';

// Novo aceite quando os Termos mudam e "Baixar meus dados" (LGPD art. 18).

process.env.JWT_SECRET ??= 'segredo-de-teste';
process.env.EXPIRES_IN ??= '1h';

const user = {
  id: 'user-1', name: 'Ana', email: 'ana@exemplo.com', role: 'DEV', plan: 'FREE', tokenVersion: 0,
  notifyScanEmail: true, language: 'pt-BR',
};

let latest; // aceite mais recente no "banco"
const prismaMock = {
  user: { findUnique: mock.fn(async () => user) },
  termsAcceptance: {
    findFirst: mock.fn(async () => latest),
    findMany: mock.fn(async () => [{ version: '1.0', acceptedAt: new Date('2026-08-20'), ipAddress: '1.2.3.4', userAgent: 'x' }]),
    create: mock.fn(async ({ data }) => {
      latest = { version: data.version, acceptedAt: new Date() };
      return latest;
    }),
  },
  target: { findMany: mock.fn(async () => [{ id: 't1', hostname: 'exemplo.com' }]) },
  scan: {
    findMany: mock.fn(async () => [
      { id: 's1', userId: 'user-1', targetUrl: 'http://localhost:3000', findings: [{ id: 'f1', scanId: 's1', title: 'SQLi' }] },
    ]),
  },
  loginAttempt: { findMany: mock.fn(async () => [{ success: true, createdAt: new Date() }]) },
  auditLog: { findMany: mock.fn(async () => []), create: mock.fn(async () => ({})) },
};
mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });

const { TERMS_OF_USE } = await import('../lib/terms_of_use.js');
const { generateToken } = await import('../constants/utils.js');
const { default: authMiddleware } = await import('../middlewares/auth_middleware.js');
const { default: authController } = await import('../controllers/auth_controllers.js');
const { acceptTermsSchema } = await import('../validators/auth_validator.js');

const token = await generateToken(user);

const through = async (baseUrl) => {
  const req = fakeReq({ cookies: { token }, baseUrl });
  const res = fakeRes();
  let passed = false;
  await authMiddleware(req, res, () => (passed = true));
  return { req, res, passed };
};

beforeEach(() => {
  latest = { version: TERMS_OF_USE.version, acceptedAt: new Date() };
  for (const model of Object.values(prismaMock)) for (const fn of Object.values(model)) fn.mock.resetCalls();
});

// ---------- novo aceite dos Termos ----------

test('termos em dia: segue normal e o /me recebe a situação', async () => {
  const { req, passed } = await through('/api/scans');
  assert.equal(passed, true);
  assert.equal(req.termsStatus.updateRequired, false);
  assert.equal(req.termsStatus.currentVersion, TERMS_OF_USE.version);
});

test('versão aceita antiga: usar a plataforma é bloqueado com 403 TERMS_UPDATE_REQUIRED', async () => {
  latest = { version: '1.0', acceptedAt: new Date('2026-08-20') };
  for (const baseUrl of ['/api/scans', '/api/targets', '/api/sast', '/api/admin']) {
    const { res, passed } = await through(baseUrl);
    assert.equal(passed, false, baseUrl);
    assert.equal(res.statusCode, 403, baseUrl);
    assert.equal(res.body.code, 'TERMS_UPDATE_REQUIRED');
    assert.equal(res.body.currentVersion, TERMS_OF_USE.version);
  }
});

test('conta sem aceite nenhum (criada antes da regra) também precisa aceitar', async () => {
  latest = null;
  const { res, passed } = await through('/api/scans');
  assert.equal(passed, false);
  assert.equal(res.statusCode, 403);
});

test('com termos desatualizados ainda dá para cuidar da conta (aceitar, baixar dados, excluir, sair)', async () => {
  latest = { version: '1.0', acceptedAt: new Date('2026-08-20') };
  const { req, passed } = await through('/api/auth');
  assert.equal(passed, true);
  assert.equal(req.termsStatus.updateRequired, true);
  assert.equal(req.termsStatus.acceptedVersion, '1.0');
});

test('aceitar a nova versão grava um registro novo (histórico) com versão, IP e navegador', async () => {
  latest = { version: '1.0', acceptedAt: new Date('2026-08-20') };
  const { req } = await through('/api/auth');
  const res = fakeRes();

  await authController.acceptTerms({ ...req, body: { accepted: true } }, res);

  assert.equal(res.statusCode, 200);
  const saved = prismaMock.termsAcceptance.create.mock.calls[0].arguments[0].data;
  assert.deepEqual(saved, { userId: 'user-1', version: TERMS_OF_USE.version, ipAddress: '203.0.113.10', userAgent: 'node-test' });
  assert.equal(res.body.terms.updateRequired, false);
  assert.equal(prismaMock.auditLog.create.mock.calls[0].arguments[0].data.action, 'TERMS_ACCEPTED');
  // depois do aceite a plataforma volta a funcionar
  assert.equal((await through('/api/scans')).passed, true);
});

test('aceitar de novo a versão que já está aceita não duplica o registro', async () => {
  const { req } = await through('/api/auth');
  const res = fakeRes();
  await authController.acceptTerms({ ...req, body: { accepted: true } }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(prismaMock.termsAcceptance.create.mock.callCount(), 0);
});

test('o aceite precisa ser explícito (accepted: true)', () => {
  assert.equal(acceptTermsSchema.safeParse({ accepted: true }).success, true);
  assert.equal(acceptTermsSchema.safeParse({ accepted: false }).success, false);
  assert.equal(acceptTermsSchema.safeParse({}).success, false);
});

// ---------- Baixar meus dados ----------

test('baixar meus dados: JSON em anexo com conta, aceites, alvos, varreduras, acessos e auditoria', async () => {
  const res = fakeRes();
  await authController.exportMyData(fakeReq({ userId: 'user-1' }), res);

  assert.equal(res.statusCode, 200);
  assert.match(res.headers['content-disposition'], /^attachment; filename="checkop-meus-dados-\d{4}-\d{2}-\d{2}\.json"$/);
  assert.match(res.headers['content-type'], /application\/json/);
  const data = JSON.parse(res.body);
  for (const key of ['about', 'account', 'termsAcceptances', 'targets', 'scans', 'loginAttempts', 'auditLogs']) {
    assert.ok(key in data, key);
  }
  assert.equal(data.account.email, 'ana@exemplo.com');
  assert.equal(data.scans[0].findings[0].title, 'SQLi');
  assert.equal(prismaMock.auditLog.create.mock.calls[0].arguments[0].data.action, 'DATA_EXPORTED');
});

test('baixar meus dados: só da própria conta e sem segredos de autenticação', async () => {
  const res = fakeRes();
  await authController.exportMyData(fakeReq({ userId: 'user-1' }), res);

  // toda consulta filtra pelo usuário logado
  for (const fn of [prismaMock.termsAcceptance.findMany, prismaMock.target.findMany, prismaMock.scan.findMany, prismaMock.loginAttempt.findMany, prismaMock.auditLog.findMany]) {
    assert.deepEqual(fn.mock.calls[0].arguments[0].where, { userId: 'user-1' });
  }
  // a conta é lida com lista fechada de campos: nada de senha, códigos ou versão do token
  const selected = Object.keys(prismaMock.user.findUnique.mock.calls[0].arguments[0].select);
  for (const secret of ['password', 'resetPasswordToken', 'tokenVersion', 'failedLoginAttempts']) {
    assert.ok(!selected.includes(secret), secret);
  }
  assert.ok(!Object.keys(prismaMock.target.findMany.mock.calls[0].arguments[0].select).includes('verificationToken'));
  // ids internos repetidos (dono da varredura, varredura do achado) saem do arquivo
  const data = JSON.parse(res.body);
  assert.equal(data.scans[0].userId, undefined);
  assert.equal(data.scans[0].findings[0].scanId, undefined);
});
