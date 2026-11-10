import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import {
  buildInstructions,
  checkTargetOwnership,
  resolveTargetHostname,
  targetCoversHost,
  TargetVerificationError,
} from '../lib/target_verification.js';
import { dnsAnswer } from './helpers.js';

const TOKEN = 'abc123';
const target = (overrides) => ({
  hostname: 'meusite.com.br',
  scope: 'DOMAIN',
  verificationMethod: 'DNS_TXT',
  verificationToken: TOKEN,
  ...overrides,
});

const mockFetch = (handler) => {
  const calls = [];
  mock.method(globalThis, 'fetch', async (url, init) => {
    calls.push({ url: String(url), init });
    return handler(String(url));
  });
  return calls;
};

beforeEach(() => {
  mock.restoreAll();
  mock.method(dns, 'lookup', async () => dnsAnswer('93.184.216.34'));
});

// ---------- normalização e escopo ----------

test('DNS verifica o domínio registrável; arquivo e meta tag, o host exato', () => {
  assert.equal(resolveTargetHostname('https://www.loja.meusite.com.br/x', 'DNS_TXT'), 'meusite.com.br');
  assert.equal(resolveTargetHostname('https://www.loja.meusite.com.br/x', 'HTTP_FILE'), 'www.loja.meusite.com.br');
  assert.equal(resolveTargetHostname('https://WWW.Meusite.com.br', 'META_TAG'), 'www.meusite.com.br');
});

test('escopo DOMAIN cobre subdomínios mas não domínios que só terminam parecido', () => {
  const t = target();
  assert.equal(targetCoversHost(t, 'meusite.com.br'), true);
  assert.equal(targetCoversHost(t, 'api.meusite.com.br'), true);
  assert.equal(targetCoversHost(t, 'falsomeusite.com.br'), false);
  assert.equal(targetCoversHost(t, 'meusite.com.br.evil.net'), false);
});

test('escopo HOST cobre só o host verificado', () => {
  const t = target({ hostname: 'www.meusite.com.br', scope: 'HOST' });
  assert.equal(targetCoversHost(t, 'www.meusite.com.br'), true);
  assert.equal(targetCoversHost(t, 'api.meusite.com.br'), false);
});

test('instruções do DNS indicam o registro TXT esperado', () => {
  const info = buildInstructions(target());
  assert.equal(info.recordName, '_checkop-challenge.meusite.com.br');
  assert.equal(info.recordValue, `checkop-verification=${TOKEN}`);
});

// ---------- DNS TXT ----------

test('DNS TXT: aceita o valor correto, inclusive quebrado em pedaços', async () => {
  mock.method(dns, 'resolveTxt', async () => [['v=spf1 -all'], ['checkop-verification=', TOKEN]]);
  assert.equal(await checkTargetOwnership(target()), true);
});

test('DNS TXT: valor errado ou registro inexistente reprova', async () => {
  mock.method(dns, 'resolveTxt', async () => [['checkop-verification=outro']]);
  assert.equal(await checkTargetOwnership(target()), false);

  mock.method(dns, 'resolveTxt', async () => {
    throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
  });
  assert.equal(await checkTargetOwnership(target()), false);
});

// ---------- arquivo ----------

const fileTarget = target({ hostname: 'www.meusite.com.br', scope: 'HOST', verificationMethod: 'HTTP_FILE' });

test('arquivo: conteúdo correto em https aprova, sem seguir redirecionamento', async () => {
  const calls = mockFetch(() => new Response(`checkop-verification=${TOKEN}\n`, { status: 200 }));

  assert.equal(await checkTargetOwnership(fileTarget), true);
  assert.equal(calls[0].url, 'https://www.meusite.com.br/.well-known/checkop-verification.txt');
  assert.equal(calls[0].init.redirect, 'manual');
});

test('arquivo: redirecionamento não conta como prova', async () => {
  mockFetch(() => new Response(null, { status: 301, headers: { location: 'https://outro.com' } }));
  assert.equal(await checkTargetOwnership(fileTarget), false);
});

test('arquivo: sem https, tenta http', async () => {
  const calls = mockFetch((url) =>
    url.startsWith('https') ? Promise.reject(new Error('ECONNREFUSED')) : new Response(`checkop-verification=${TOKEN}`)
  );
  assert.equal(await checkTargetOwnership(fileTarget), true);
  assert.equal(calls.length, 2);
});

test('arquivo: host que resolve para rede interna é recusado antes de qualquer requisição (SSRF)', async () => {
  mock.method(dns, 'lookup', async () => dnsAnswer('10.0.0.8'));
  const calls = mockFetch(() => new Response('x'));

  await assert.rejects(checkTargetOwnership(fileTarget), TargetVerificationError);
  assert.equal(calls.length, 0);
});

// ---------- meta tag ----------

const metaTarget = target({ hostname: 'www.meusite.com.br', scope: 'HOST', verificationMethod: 'META_TAG' });
const page = (head) => new Response(`<!doctype html><html><head>${head}</head><body></body></html>`);

test('meta tag: aceita qualquer ordem de atributos e aspas simples', async () => {
  mockFetch(() => page(`<meta content='${TOKEN}' name="checkop-verification">`));
  assert.equal(await checkTargetOwnership(metaTarget), true);
});

test('meta tag: data-name ou conteúdo errado não valem', async () => {
  mockFetch(() => page(`<meta data-name="checkop-verification" content="${TOKEN}"><meta name="checkop-verification" content="x">`));
  assert.equal(await checkTargetOwnership(metaTarget), false);
});
