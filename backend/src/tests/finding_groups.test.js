import { test } from 'node:test';
import assert from 'node:assert/strict';
import { groupFindings } from '../lib/finding_groups.js';

// Uma entrada por falha; os locais ficam dentro dela.

const f = (id, title, affectedUrl, severity = 'MEDIUM', extra = {}) => ({
  id, title, affectedUrl, severity, tool: 'ZAP', cvssScore: null, remediation: 'Corrija.', ...extra,
});

test('mesma falha em várias páginas vira uma entrada com todos os locais', () => {
  const groups = groupFindings([
    f('1', 'Content Security Policy (CSP) Header Not Set', 'http://a/'),
    f('2', 'Content Security Policy (CSP) Header Not Set', 'http://a/login'),
    f('3', 'Content Security Policy (CSP) Header Not Set', 'http://a/item?id=1'),
    f('4', 'SQL Injection', 'http://a/item?id=%27', 'HIGH'),
  ]);
  assert.equal(groups.length, 2);
  const csp = groups.find((g) => g.title.startsWith('Content'));
  assert.deepEqual(csp.locations.map((l) => l.affectedUrl), ['http://a/', 'http://a/item?id=1', 'http://a/login']);
  assert.equal(groups.find((g) => g.title === 'SQL Injection').locations.length, 1);
});

test('nomes diferentes da mesma classe (ZAP e Nuclei) se juntam; o grupo assume a severidade mais alta', () => {
  const [xss] = groupFindings([
    f('1', 'Cross Site Scripting (Reflected)', 'http://a/search', 'MEDIUM'),
    f('2', 'Reflected XSS', 'http://a/item', 'HIGH', { tool: 'NUCLEI', rawRequest: 'GET /item?id=<script>' }),
  ]);
  assert.equal(xss.severity, 'HIGH');
  assert.equal(xss.locations[0].affectedUrl, 'http://a/item'); // o mais grave primeiro
  assert.equal(xss.locations[0].rawRequest, 'GET /item?id=<script>');
  assert.deepEqual(xss.tools.sort(), ['NUCLEI', 'ZAP']);
});

test('local não carrega campo que o plano ou o perfil cortou', () => {
  const [g] = groupFindings([f('1', 'SQL Injection', 'http://a/x')]); // sem rawRequest (Free/estudante)
  assert.equal('rawRequest' in g.locations[0], false);
});
