import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import pkg from '@prisma/client';

// Regressão: no Prisma 7, `prisma migrate dev` aplica a migração mas NÃO
// regenera o cliente. Os outros testes simulam o Prisma e não perceberiam; a
// API real quebraria (401 em tudo, varredura sem gravar achados).
// Se este teste falhar: rode `npm run prisma:generate` e reinicie a API.
const { Prisma } = pkg;

const schema = readFileSync(new URL('../../prisma/schema.prisma', import.meta.url), 'utf8');

const schemaFields = (model) => {
  const body = schema.match(new RegExp(`model ${model} \\{([^}]*)\\}`))[1];
  return body
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('//') && !line.startsWith('@@'))
    .map((line) => line.split(/\s+/))
    // só campos escalares (relações não aparecem no ScalarFieldEnum)
    .filter(([, type]) => type && /^(String|Int|Float|Boolean|DateTime|Role|Plan|ToolType|ScanObjective|TargetEnvironment|ScanStatus|FindingSeverity|FindingStatus|VerificationMethod|TargetScope)\??$/.test(type))
    .map(([name]) => name);
};

for (const model of ['User', 'Scan', 'Finding', 'Target', 'AuditLog', 'LoginAttempt', 'TermsAcceptance']) {
  test(`cliente Prisma gerado tem todos os campos de ${model} do schema`, () => {
    const generated = Object.keys(Prisma[`${model}ScalarFieldEnum`] ?? {});
    const missing = schemaFields(model).filter((field) => !generated.includes(field));
    assert.deepEqual(missing, [], `campos fora do cliente gerado: ${missing.join(', ')} — rode npm run prisma:generate`);
  });
}
