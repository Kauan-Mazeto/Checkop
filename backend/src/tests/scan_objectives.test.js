import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fakeReq, fakeRes } from './helpers.js';

const prismaMock = {
  scan: {
    updateMany: mock.fn(async () => ({ count: 1 })),
    update: mock.fn(async () => ({})),
  },
  finding: { createMany: mock.fn(async () => ({ count: 0 })) },
  auditLog: { create: mock.fn(async () => ({})) },
  target: { findMany: mock.fn(async () => []) },
  $transaction: mock.fn(async (ops) => Promise.all(ops)),
};
mock.module(new URL('../lib/prisma.js', import.meta.url).href, { defaultExport: prismaMock });

const { SCAN_OBJECTIVES, filterFindingsByObjective, listObjectives } = await import('../constants/scan_objectives.js');
const { default: scanController } = await import('../controllers/scan_controllers.js');

// IDs válidos no ZAP 2.17 (https://www.zaproxy.org/docs/alerts/), usados pela configuração.
// Se alguém digitar um id errado no scan_objectives.js, este teste acusa.
const KNOWN_ZAP_IDS = new Set([
  '0', '2', '6', '7', '41', '42',
  '10010', '10011', '10020', '10021', '10023', '10024', '10027', '10028', '10033', '10035', '10036',
  '10037', '10038', '10054', '10055', '10061', '10063', '10095', '10096', '10097', '10098', '10202',
  '20012', '20019', '40003', '40012', '40014', '40016', '40017', '40018', '40019', '40020', '40021',
  '40022', '40024', '40026', '40027', '40028', '40029', '40032', '40034', '40035', '40040', '40046',
  '90018', '90019', '90020', '90022', '90023', '90033', '90035', '90036', '90037',
]);

// ---------- integridade da configuração ----------

test('todo objetivo existe também no enum ScanObjective do Prisma (e vice-versa)', () => {
  const schema = readFileSync(new URL('../../prisma/schema.prisma', import.meta.url), 'utf8');
  const enumBody = schema.match(/enum ScanObjective \{([^}]*)\}/)[1];
  const prismaValues = enumBody.split('\n').map((l) => l.trim()).filter((l) => /^[A-Z_]+$/.test(l));
  assert.deepEqual([...prismaValues].sort(), Object.keys(SCAN_OBJECTIVES).sort());
});

test('todos os objetivos documentados na matriz existem', () => {
  const expected = [
    'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'XXE', 'SSTI', 'CRLF_INJECTION',
    'OPEN_REDIRECT', 'CSRF', 'SSRF', 'SECURITY_HEADERS', 'COOKIES', 'CLICKJACKING', 'CORS',
    'DIRECTORY_LISTING', 'EXPOSED_FILES', 'ADMIN_PANELS', 'INFO_DISCLOSURE', 'API_EXPOSURE',
    'KNOWN_CVE', 'SSL_TLS', 'DNS_CHECK', 'SUBDOMAIN_ENUM', 'FULL_SCAN',
  ];
  for (const key of expected) assert.ok(SCAN_OBJECTIVES[key], `falta o objetivo ${key}`);
});

test('configuração de cada objetivo é coerente', () => {
  for (const [key, o] of Object.entries(SCAN_OBJECTIVES)) {
    assert.ok(o.label && o.description, `${key}: label/description`);
    assert.ok(['FULL', 'PARTIAL'].includes(o.coverage), `${key}: coverage`);
    assert.equal(o.engines.includes('NUCLEI'), Boolean(o.nuclei), `${key}: engine NUCLEI x config`);
    assert.equal(o.engines.includes('ZAP'), Boolean(o.zap), `${key}: engine ZAP x config`);

    for (const id of [...(o.zap?.activeScannerIds ?? []), ...(o.zap?.alertIds ?? [])]) {
      assert.ok(KNOWN_ZAP_IDS.has(id), `${key}: id do ZAP desconhecido ${id}`);
    }
    // todo scanner ativo do objetivo precisa estar no filtro, senão o achado dele some
    for (const id of o.zap?.activeScannerIds ?? []) {
      assert.ok(o.zap.alertIds.includes(id), `${key}: scanner ${id} fora do filtro`);
    }
    // objetivo que exige ataque precisa ter algum ataque configurado
    if (o.requiresActiveScan) assert.ok(o.zap?.activeScannerIds?.length, `${key}: requiresActiveScan sem scanner ativo`);
  }
});

test('regressão: ids errados antigos não voltam', () => {
  assert.ok(!SCAN_OBJECTIVES.SQL_INJECTION.zap.activeScannerIds.includes('90019')); // é Code Injection
  assert.ok(!SCAN_OBJECTIVES.OPEN_REDIRECT.zap.activeScannerIds.includes('10044')); // é passivo "Big Redirect"
  assert.deepEqual(SCAN_OBJECTIVES.SSRF.zap.activeScannerIds, ['40046']); // 40047/48 são Text4shell/React2Shell
});

test('objetivos passivos não enviam nenhum ataque', () => {
  for (const key of ['SECURITY_HEADERS', 'COOKIES', 'CLICKJACKING', 'INFO_DISCLOSURE']) {
    assert.deepEqual(SCAN_OBJECTIVES[key].zap.activeScannerIds, [], key);
  }
});

test('listObjectives não expõe ids internos dos motores', () => {
  const list = listObjectives();
  assert.equal(list.length, Object.keys(SCAN_OBJECTIVES).length);
  for (const item of list) {
    assert.equal(item.zap, undefined);
    assert.equal(item.nuclei, undefined);
  }
});

// ---------- filtro do resultado ----------

const zap = (ruleId) => ({ tool: 'ZAP', ruleId, title: `zap-${ruleId}` });
const nuclei = { tool: 'NUCLEI', ruleId: 'generic-sqli', title: 'nuclei' };

test('SQLi mantém os achados de SQLi e descarta o barulho do passivo (headers, cookies)', () => {
  const kept = filterFindingsByObjective([zap('40018'), zap('10020'), zap('10010'), nuclei], 'SQL_INJECTION');
  assert.deepEqual(kept.map((f) => f.title), ['zap-40018', 'nuclei']);
});

test('Cookies mantém só os alertas de cookie', () => {
  const kept = filterFindingsByObjective([zap('10010'), zap('10054'), zap('10021')], 'COOKIES');
  assert.deepEqual(kept.map((f) => f.ruleId), ['10010', '10054']);
});

test('varredura completa mantém tudo', () => {
  const all = [zap('40018'), zap('10020'), nuclei];
  assert.equal(filterFindingsByObjective(all, 'FULL_SCAN').length, 3);
});

// ---------- execução ----------

const flush = () => new Promise((r) => setTimeout(r, 20));
const localScan = (objective) => ({
  id: 's1', userId: 'u1', targetUrl: 'http://localhost:3000', environment: 'DEVELOPMENT',
  safeMode: false, objective, suspiciousEnvironment: false, status: 'PENDING', targetId: null,
});

let engineCalls;
let engineResponses;
beforeEach(() => {
  mock.restoreAll();
  for (const m of Object.values(prismaMock)) {
    if (typeof m === 'function') m.mock.resetCalls();
    else for (const fn of Object.values(m)) fn.mock.resetCalls();
  }
  engineCalls = [];
  engineResponses = {};
  mock.method(globalThis, 'fetch', async (url, init) => {
    const path = new URL(String(url)).pathname;
    engineCalls.push({ path, body: JSON.parse(init.body) });
    return new Response(JSON.stringify(engineResponses[path] ?? { findings: [] }), { status: 200 });
  });
});

const run = async (scan, body = {}) => {
  const res = fakeRes();
  await scanController.runScan(fakeReq({ resource: scan, body, userId: 'u1' }), res);
  await flush();
  return res;
};

test('objetivo passivo manda lista vazia de scanners (ZAP não ataca) mesmo em ambiente local', async () => {
  await run(localScan('COOKIES'));
  assert.deepEqual(engineCalls.find((c) => c.path === '/scans/zap').body.scannerIds, []);
});

test('login padrão (default-login) só entra com ataque liberado', async () => {
  await run(localScan('ADMIN_PANELS'));
  assert.deepEqual(engineCalls.find((c) => c.path === '/scans/nuclei').body.tags, ['panel', 'default-login']);
});

test('resultado gravado já vem filtrado e com os avisos do motor', async () => {
  engineResponses['/scans/zap'] = {
    findings: [
      { tool: 'ZAP', ruleId: '40018', title: 'SQL Injection', severity: 'HIGH', affectedUrl: 'http://localhost:3000/a' },
      { tool: 'ZAP', ruleId: '10020', title: 'Missing Anti-clickjacking Header', severity: 'MEDIUM', affectedUrl: 'http://localhost:3000/' },
    ],
    warnings: ['Regras do ZAP indisponíveis nesta instalação: 90018.'],
  };

  await run(localScan('SQL_INJECTION'));

  const saved = prismaMock.finding.createMany.mock.calls[0].arguments[0].data;
  assert.deepEqual(saved.map((f) => f.ruleId), ['40018']);
  const completed = prismaMock.scan.update.mock.calls.at(-1).arguments[0].data;
  assert.equal(completed.status, 'COMPLETED');
  assert.deepEqual(JSON.parse(completed.engineWarnings), ['Regras do ZAP indisponíveis nesta instalação: 90018.']);
});

test('enumeração de subdomínios usa o domínio registrável e não se aplica a localhost', async () => {
  await run({ ...localScan('SUBDOMAIN_ENUM'), targetUrl: 'http://localhost:3000' });
  assert.equal(engineCalls.length, 0);
  const completed = prismaMock.scan.update.mock.calls.at(-1).arguments[0].data;
  assert.match(JSON.parse(completed.engineWarnings)[0], /não se aplica/);
});

test('GET /api/scans/objectives devolve a lista para o seletor', () => {
  const res = fakeRes();
  scanController.getObjectives(fakeReq(), res);
  assert.equal(res.statusCode, 200);
  assert.ok(res.body.objectives.some((o) => o.key === 'COMMAND_INJECTION' && o.requiresActiveScan));
});
