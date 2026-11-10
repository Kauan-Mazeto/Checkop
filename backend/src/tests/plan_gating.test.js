import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serializeFinding } from '../lib/py/finding_serializer.js';
import { requirePlan } from '../middlewares/plan_middleware.js';
import { fakeReq, fakeRes } from './helpers.js';

const finding = {
  id: 'f1',
  title: 'SQL Injection',
  severity: 'HIGH',
  status: 'OPEN',
  tool: 'ZAP',
  ruleId: '40018',
  affectedUrl: 'http://localhost:3000/busca',
  parameter: 'q',
  description: 'desc',
  remediation: 'Use queries parametrizadas.',
  rawRequest: 'GET /busca?q=1 HTTP/1.1',
  rawResponse: 'erro de sintaxe SQL',
  owaspUrl: 'A03:2021 – Injection',
  cveId: null,
  cvssScore: 8.5,
  createdAt: new Date(),
};

test('Free não recebe correção, PoC nem compliance (corte no servidor)', () => {
  const out = serializeFinding(finding, { safeMode: false, plan: 'FREE' });
  for (const field of ['remediation', 'rawRequest', 'rawResponse', 'parameter']) {
    assert.equal(field in out, false, field);
  }
  assert.deepEqual(out.compliance, []);
  assert.equal(out.premiumLocked, true);
  assert.equal(out.title, 'SQL Injection'); // diagnóstico macro continua
});

test('Premium em ambiente local recebe tudo', () => {
  const out = serializeFinding(finding, { safeMode: false, plan: 'PREMIUM' });
  assert.equal(out.rawRequest, finding.rawRequest);
  assert.equal(out.remediation, finding.remediation);
  assert.ok(out.compliance.length > 0);
  assert.equal(out.premiumLocked, false);
});

test('Premium em produção (Modo Seguro) continua sem PoC (RF-08)', () => {
  const out = serializeFinding(finding, { safeMode: true, plan: 'PREMIUM' });
  assert.equal(out.rawRequest ?? null, null);
  assert.equal(out.rawResponse ?? null, null);
  assert.equal(out.remediation, finding.remediation);
});

test('requirePlan bloqueia Free com PREMIUM_REQUIRED e libera Premium', () => {
  const blocked = fakeRes();
  let nextCalled = false;
  requirePlan('PREMIUM')(fakeReq({ userPlan: 'FREE' }), blocked, () => (nextCalled = true));
  assert.equal(blocked.statusCode, 403);
  assert.equal(blocked.body.code, 'PREMIUM_REQUIRED');
  assert.equal(nextCalled, false);

  requirePlan('PREMIUM')(fakeReq({ userPlan: 'PREMIUM' }), fakeRes(), () => (nextCalled = true));
  assert.equal(nextCalled, true);
});
