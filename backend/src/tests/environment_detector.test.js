import { test, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import { detectEnvironment, ScanValidationError } from '../lib/environment_detector.js';
import { dnsAnswer } from './helpers.js';

const mockDns = (...addresses) => mock.method(dns, 'lookup', async () => dnsAnswer(...addresses));

beforeEach(() => mock.restoreAll());

test('localhost é DEVELOPMENT e não suspeito (uso local com DVWA/Juice Shop)', async () => {
  const result = await detectEnvironment('http://localhost:3000');
  assert.equal(result.environment, 'DEVELOPMENT');
  assert.equal(result.suspicious, false);
});

test('IP privado literal é DEVELOPMENT e não suspeito', async () => {
  const result = await detectEnvironment('http://192.168.0.10');
  assert.equal(result.environment, 'DEVELOPMENT');
  assert.equal(result.suspicious, false);
});

test('domínio público que resolve para IP interno é marcado como suspeito', async () => {
  mockDns('127.0.0.1');
  const result = await detectEnvironment('https://rebind.exemplo.com');
  assert.equal(result.suspicious, true);
});

test('domínio com um IP público e um privado também é suspeito', async () => {
  mockDns('93.184.216.34', '10.0.0.5');
  const result = await detectEnvironment('https://misto.exemplo.com');
  assert.equal(result.suspicious, true);
});

test('endpoint de metadata de nuvem é rejeitado', async () => {
  await assert.rejects(detectEnvironment('http://169.254.169.254/latest'), ScanValidationError);
});

test('domínio que resolve para metadata de nuvem é rejeitado', async () => {
  mockDns('169.254.169.254');
  await assert.rejects(detectEnvironment('https://meta.exemplo.com'), ScanValidationError);
});

test('domínio que não resolve é rejeitado', async () => {
  mock.method(dns, 'lookup', async () => {
    throw new Error('ENOTFOUND');
  });
  await assert.rejects(detectEnvironment('https://naoexiste.exemplo.com'), ScanValidationError);
});

test('subdomínio de homologação é STAGING', async () => {
  mockDns('93.184.216.34');
  const result = await detectEnvironment('https://hml.exemplo.com.br');
  assert.equal(result.environment, 'STAGING');
  assert.equal(result.suspicious, false);
});

test('domínio público comum é PRODUCTION', async () => {
  mockDns('93.184.216.34');
  const result = await detectEnvironment('https://www.exemplo.com');
  assert.equal(result.environment, 'PRODUCTION');
  assert.equal(result.suspicious, false);
});
