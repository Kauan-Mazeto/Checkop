import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { fakeReq, fakeRes } from './helpers.js';

// espec.txt 3.2 - correção sugerida pela IA (SDK da Anthropic simulada).

let nextResponse;
let lastRequest;

class FakeAnthropic {
  constructor() {
    this.beta = {
      messages: {
        parse: async (params) => {
          lastRequest = params;
          if (nextResponse instanceof Error) throw nextResponse;
          return nextResponse;
        },
      },
    };
  }
}
class APIError extends Error {}
FakeAnthropic.APIError = APIError;
FakeAnthropic.RateLimitError = class extends APIError {};
FakeAnthropic.AuthenticationError = class extends APIError {};
FakeAnthropic.PermissionDeniedError = class extends APIError {};

mock.module('@anthropic-ai/sdk', { defaultExport: FakeAnthropic });

const { buildFixPrompt, suggestFix, isAiFixEnabled, AI_FIX_MODEL } = await import('../lib/ai_fix.js');
const { default: sastController } = await import('../controllers/sast_controllers.js');
const { aiFixSchema } = await import('../validators/sast_validator.js');

const input = {
  code: "const q = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(q);",
  firstLine: 10,
  startLine: 10,
  endLine: 10,
  language: 'javascript',
  title: 'SQL Injection',
  description: 'Consulta montada com entrada do usuário.',
  remediation: 'Use consultas parametrizadas.',
};

beforeEach(() => {
  process.env.ANTHROPIC_API_KEY = 'chave-de-teste';
  lastRequest = undefined;
  nextResponse = { stop_reason: 'end_turn', model: AI_FIX_MODEL, parsed_output: { fixedCode: 'db.query("SELECT * FROM users WHERE id = ?", [id]);', explanation: 'Parametrizada.' } };
});

test('prompt leva o código só entre as marcas de dado e com as linhas', () => {
  const prompt = buildFixPrompt(input);
  assert.match(prompt, /<codigo>\nconst q = /);
  assert.match(prompt, /<\/codigo>$/);
  assert.match(prompt, /Linhas vulneráveis: 10 \(a janela começa na linha 10\)/);
  assert.match(prompt, /Orientação de correção: Use consultas parametrizadas\./);
});

test('sem credencial no servidor a IA fica desligada (503 AI_NOT_CONFIGURED)', async () => {
  delete process.env.ANTHROPIC_API_KEY;
  delete process.env.ANTHROPIC_AUTH_TOKEN;
  assert.equal(isAiFixEnabled(), false);

  const config = fakeRes();
  sastController.getAiConfig(fakeReq(), config);
  assert.deepEqual(config.body, { enabled: false });

  const res = fakeRes();
  await sastController.fixWithAi(fakeReq({ body: input }), res);
  assert.equal(res.statusCode, 503);
  assert.equal(res.body.code, 'AI_NOT_CONFIGURED');
  assert.equal(lastRequest, undefined); // nada foi enviado
});

test('gera a correção com saída estruturada, esforço médio e fallback de recusa', async () => {
  const res = fakeRes();
  await sastController.fixWithAi(fakeReq({ body: input }), res);
  assert.equal(res.statusCode, 200);
  assert.match(res.body.fixedCode, /\?/);
  assert.equal(lastRequest.model, AI_FIX_MODEL);
  assert.equal(lastRequest.output_config.effort, 'medium');
  assert.equal(lastRequest.output_config.format.type, 'json_schema');
  assert.equal(lastRequest.fallbacks, 'default');
  assert.deepEqual(lastRequest.betas, ['server-side-fallback-2026-07-01']);
});

test('recusa do modelo vira mensagem clara (422 AI_REFUSED)', async () => {
  nextResponse = { stop_reason: 'refusal', parsed_output: null };
  const res = fakeRes();
  await sastController.fixWithAi(fakeReq({ body: input }), res);
  assert.equal(res.statusCode, 422);
  assert.equal(res.body.code, 'AI_REFUSED');
});

test('resposta cortada ou sem JSON não é devolvida como correção', async () => {
  nextResponse = { stop_reason: 'max_tokens', parsed_output: null };
  const res = fakeRes();
  await sastController.fixWithAi(fakeReq({ body: input }), res);
  assert.equal(res.statusCode, 502);
});

test('limite da API vira 429 AI_BUSY', async () => {
  nextResponse = new FakeAnthropic.RateLimitError('rate');
  const res = fakeRes();
  await sastController.fixWithAi(fakeReq({ body: input }), res);
  assert.equal(res.statusCode, 429);
  assert.equal(res.body.code, 'AI_BUSY');
});

test('validação: trecho e intervalo de linhas', () => {
  assert.equal(aiFixSchema.safeParse(input).success, true);
  assert.equal(aiFixSchema.safeParse({ ...input, endLine: 5 }).success, false);
  assert.equal(aiFixSchema.safeParse({ ...input, code: 'x'.repeat(20001) }).success, false);
});

test('suggestFix direto também respeita o desligado', async () => {
  delete process.env.ANTHROPIC_API_KEY;
  await assert.rejects(() => suggestFix(input), /não está configurada/);
});
