import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';

// Textos dos achados no idioma do usuário (ZAP/Nuclei vêm em inglês).

let cacheRows = [];
let engineAnswer = {};
let engineFails = false;

const prismaMock = {
  translationCache: {
    findMany: mock.fn(async ({ where }) => cacheRows.filter((r) => r.language === where.language && where.sourceHash.in.includes(r.sourceHash))),
    upsert: mock.fn(async ({ create }) => create),
  },
};
const translateTexts = mock.fn(async (texts) => {
  if (engineFails) throw new Error('motor fora');
  return Object.fromEntries(texts.map((t) => [t, engineAnswer[t] ?? t]));
});

mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });
mock.module(new URL('../lib/py/security_engine_client.js', import.meta.url).href, { namedExports: { translateTexts } });

const { translateFindings, sourceHash } = await import('../lib/finding_translation.js');

const zap = { tool: 'ZAP', title: 'SQL Injection', description: 'SQL injection may be possible.', remediation: 'Use prepared statements.' };

beforeEach(() => {
  cacheRows = [];
  engineAnswer = {};
  engineFails = false;
  translateTexts.mock.resetCalls();
  prismaMock.translationCache.upsert.mock.resetCalls();
});

test('traduz título, descrição e correção para o idioma do usuário e grava no cache', async () => {
  engineAnswer = {
    'SQL Injection': 'Inyección SQL',
    'SQL injection may be possible.': 'Puede ser posible una inyección SQL.',
    'Use prepared statements.': 'Use sentencias preparadas.',
  };
  const [out] = await translateFindings([zap], 'es');
  assert.equal(out.title, 'Inyección SQL');
  assert.equal(out.remediation, 'Use sentencias preparadas.');
  assert.equal(translateTexts.mock.calls[0].arguments[1], 'es');
  assert.equal(prismaMock.translationCache.upsert.mock.callCount(), 3);
});

test('usa o cache e só pede ao motor o que falta', async () => {
  cacheRows = [{ language: 'pt-BR', sourceHash: sourceHash('SQL Injection'), text: 'Injeção de SQL' }];
  engineAnswer = { 'Use prepared statements.': 'Use consultas parametrizadas.' };
  const [out] = await translateFindings([zap], 'pt-BR');
  assert.equal(out.title, 'Injeção de SQL');
  assert.equal(out.remediation, 'Use consultas parametrizadas.');
  assert.deepEqual(translateTexts.mock.calls[0].arguments[0].sort(), ['SQL injection may be possible.', 'Use prepared statements.']);
});

test('inglês é o original: não chama o motor', async () => {
  const [out] = await translateFindings([zap], 'en');
  assert.equal(out.title, 'SQL Injection');
  assert.equal(translateTexts.mock.callCount(), 0);
});

test('motor indisponível mantém o texto original, sem quebrar', async () => {
  engineFails = true;
  const [out] = await translateFindings([zap], 'fr');
  assert.equal(out.remediation, 'Use prepared statements.');
});

test('texto que o motor não traduziu não vai para o cache', async () => {
  await translateFindings([zap], 'de');
  assert.equal(prismaMock.translationCache.upsert.mock.callCount(), 0);
});

test('achado do Subfinder (texto do próprio Checkop) não é traduzido', async () => {
  const sub = { tool: 'SUBFINDER', title: 'Subdomínio encontrado', description: 'api.exemplo.com', remediation: null };
  const [out] = await translateFindings([sub], 'es');
  assert.equal(out.title, 'Subdomínio encontrado');
  assert.equal(translateTexts.mock.callCount(), 0);
});
