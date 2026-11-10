import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { getDomain } from 'tldts';
import { detectEnvironment, ScanValidationError } from './environment_detector.js';

// Verificação de propriedade do alvo (TCC, seção 9). O usuário só varre um alvo
// público depois de provar que o controla, o que sustenta a "autorização expressa"
// exigida pelo art. 154-A do Código Penal.
//
// DNS TXT  -> prova o domínio registrável inteiro (vale para os subdomínios)
// Arquivo  -> prova só o host onde foi publicado
// Meta tag -> prova só o host onde foi publicada

export const DNS_RECORD_PREFIX = '_checkop-challenge';
export const VERIFICATION_FILE_PATH = '/.well-known/checkop-verification.txt';
export const META_TAG_NAME = 'checkop-verification';
const VERIFICATION_VALUE_PREFIX = 'checkop-verification';

const FETCH_TIMEOUT_MS = 8_000; // cabe no timeout de 25s da API mesmo tentando https e depois http
const MAX_BODY_BYTES = 512 * 1024; // página inicial grande o bastante para achar a meta tag no <head>

export const SCOPE_BY_METHOD = Object.freeze({
  DNS_TXT: 'DOMAIN',
  HTTP_FILE: 'HOST',
  META_TAG: 'HOST',
});

export class TargetVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TargetVerificationError';
  }
}

export const generateVerificationToken = () => crypto.randomBytes(24).toString('hex');

const expectedValue = (token) => `${VERIFICATION_VALUE_PREFIX}=${token}`;

/**
 * Normaliza o que será verificado a partir da URL informada:
 * DNS -> domínio registrável (www.loja.com.br -> loja.com.br); demais -> host exato.
 */
export const resolveTargetHostname = (url, method) => {
  const host = new URL(url).hostname.toLowerCase().replace(/\.$/, '');
  if (SCOPE_BY_METHOD[method] === 'HOST') return host;

  const domain = getDomain(host);
  if (!domain) {
    throw new TargetVerificationError('Não foi possível identificar o domínio registrável desta URL.');
  }
  return domain;
};

/** O alvo verificado cobre este host? DOMAIN cobre o próprio domínio e os subdomínios. */
export const targetCoversHost = (target, host) => {
  const normalized = host.toLowerCase().replace(/\.$/, '');
  if (target.scope === 'HOST') return normalized === target.hostname;
  return normalized === target.hostname || normalized.endsWith(`.${target.hostname}`);
};

export const buildInstructions = (target) => {
  const value = expectedValue(target.verificationToken);

  if (target.verificationMethod === 'DNS_TXT') {
    return {
      method: 'DNS_TXT',
      covers: `${target.hostname} e todos os seus subdomínios`,
      recordType: 'TXT',
      recordName: `${DNS_RECORD_PREFIX}.${target.hostname}`,
      recordValue: value,
      note: 'A propagação de DNS pode levar alguns minutos. Mantenha o registro: ele é conferido de novo antes de cada varredura.',
    };
  }

  if (target.verificationMethod === 'HTTP_FILE') {
    return {
      method: 'HTTP_FILE',
      covers: `somente ${target.hostname}`,
      fileUrl: `https://${target.hostname}${VERIFICATION_FILE_PATH}`,
      fileContent: value,
      note: 'O arquivo deve responder 200 sem redirecionamento. Mantenha-o publicado: ele é conferido de novo antes de cada varredura.',
    };
  }

  return {
    method: 'META_TAG',
    covers: `somente ${target.hostname}`,
    pageUrl: `https://${target.hostname}/`,
    metaTag: `<meta name="${META_TAG_NAME}" content="${target.verificationToken}">`,
    note: 'Coloque a tag dentro do <head> da página inicial. Ela é conferida de novo antes de cada varredura.',
  };
};

// ---------- busca HTTP protegida contra SSRF ----------

// A verificação faz o servidor do Checkop buscar uma URL indicada pelo usuário.
// Só aceitamos destino público (nada de localhost, rede interna ou metadata de
// nuvem), sem seguir redirecionamento e com tempo e tamanho limitados.
const assertPublicDestination = async (url) => {
  let detection;
  try {
    detection = await detectEnvironment(url);
  } catch (err) {
    if (err instanceof ScanValidationError) throw new TargetVerificationError(err.message);
    throw err;
  }
  if (detection.suspicious || detection.environment === 'DEVELOPMENT') {
    throw new TargetVerificationError('Alvos locais ou de rede interna não precisam (nem podem) ser verificados.');
  }
};

const readLimitedBody = async (response) => {
  const reader = response.body?.getReader();
  if (!reader) return '';

  const chunks = [];
  let total = 0;
  while (total < MAX_BODY_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
  }
  await reader.cancel().catch(() => {});
  return Buffer.concat(chunks).subarray(0, MAX_BODY_BYTES).toString('utf8');
};

const fetchPublicText = async (url) => {
  await assertPublicDestination(url);

  let response;
  try {
    response = await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { 'User-Agent': 'Checkop-Verification/1.0' },
    });
  } catch {
    return null; // fora do ar, TLS inválido, timeout
  }

  if (response.status !== 200) {
    await response.body?.cancel().catch(() => {});
    return null;
  }
  return readLimitedBody(response);
};

// https primeiro; http só como alternativa para sites que ainda não têm TLS
const fetchFromHost = async (hostname, path) => {
  for (const protocol of ['https', 'http']) {
    const body = await fetchPublicText(`${protocol}://${hostname}${path}`);
    if (body !== null) return body;
  }
  return null;
};

// ---------- os três métodos ----------

const checkDnsTxt = async (target) => {
  let records;
  try {
    records = await dns.resolveTxt(`${DNS_RECORD_PREFIX}.${target.hostname}`);
  } catch {
    return false; // NXDOMAIN / sem registro
  }
  // cada registro TXT pode vir quebrado em pedaços de até 255 caracteres
  return records.some((chunks) => chunks.join('').trim() === expectedValue(target.verificationToken));
};

const checkHttpFile = async (target) => {
  const body = await fetchFromHost(target.hostname, VERIFICATION_FILE_PATH);
  return body !== null && body.trim() === expectedValue(target.verificationToken);
};

const META_TAG_REGEX = /<meta\b[^>]*>/gi;
// \s antes do nome evita casar "data-name=" quando procuramos "name="
const attr = (tag, name) => tag.match(new RegExp(`\\s${name}\\s*=\\s*["']([^"']*)["']`, 'i'))?.[1];

const checkMetaTag = async (target) => {
  const html = await fetchFromHost(target.hostname, '/');
  if (!html) return false;
  return (html.match(META_TAG_REGEX) ?? []).some(
    (tag) => attr(tag, 'name') === META_TAG_NAME && attr(tag, 'content') === target.verificationToken
  );
};

const CHECKERS = { DNS_TXT: checkDnsTxt, HTTP_FILE: checkHttpFile, META_TAG: checkMetaTag };

/**
 * Confere se a prova de controle ainda está publicada.
 * @returns {Promise<boolean>}
 * @throws {TargetVerificationError} se o destino for proibido (rede interna etc.)
 */
export const checkTargetOwnership = async (target) => {
  const checker = CHECKERS[target.verificationMethod];
  if (!checker) throw new TargetVerificationError('Método de verificação desconhecido.');
  return checker(target);
};
