import dns from 'node:dns/promises';
import privateIp from 'private-ip';
import { parse } from 'tldts';

// metadados de artefatos em nuvem
const CLOUD_METADATA_ADDRESSES = new Set([
  '169.254.169.254',       
  '169.254.170.2',         
  'fd00:ec2::254',          
  '100.100.100.200',        
  'metadata.google.internal',
]);

const STAGING_KEYWORDS = new Set([
  'staging', 'stg', 'homolog', 'hml', 'test',
  'qa', 'sandbox', 'dev', 'preprod', 'pre-prod',
]);

export class ScanValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScanValidationError';
  }
}

const isBlockedAddress = (value) => {
  const normalized = value.toLowerCase().replace(/\.$/, '');
  return CLOUD_METADATA_ADDRESSES.has(normalized);
};

const resolveAllAddresses = async (hostname) => {
  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    return records.map((record) => record.address);
  } catch {
    return [];
  }
};

// Nomes que o operador do servidor declara como "esta máquina", além de localhost.
// No Docker, host.docker.internal aponta para o computador de quem roda o Checkop
// (IP interno); sem esta lista ele cairia na regra de domínio que resolve para
// rede interna e seria bloqueado. Vazio por padrão: nada muda fora do Docker.
const localTargetHosts = () =>
  new Set(
    (process.env.LOCAL_TARGET_HOSTS ?? '')
      .split(',')
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean),
  );

const classifyAsStaging = (hostname) => {
  const parsed = parse(hostname);
  const subdomainParts = (parsed.subdomain || '').split('.').filter(Boolean);
  return subdomainParts.some((part) => STAGING_KEYWORDS.has(part.toLowerCase()));
};

/**
 * Analisa um alvo de varredura e determina:
 * - se deve ser rejeitado de forma incondicional (metadata de nuvem, domínio
 *   que não resolve)
 * - o ambiente (DEVELOPMENT / STAGING / PRODUCTION)
 * - se o padrão observado é suspeito (hostname público que resolve para rede
 *   interna - indício de DNS rebinding)
 * - todos os IPs resolvidos, para permitir "pinning" na execução futura da
 *   varredura (o motor de scan deve reutilizar esses IPs, não resolver o
 *   hostname de novo no momento de disparar a requisição real - do
 *   contrário, a validação feita aqui pode já estar desatualizada)
 *
 * @throws {ScanValidationError} se o alvo for inválido ou proibido
 */
export const detectEnvironment = async (targetUrl) => {
  const { hostname } = new URL(targetUrl);
  const normalizedHostname = hostname.toLowerCase();

  if (isBlockedAddress(normalizedHostname)) {
    throw new ScanValidationError(
      'Este endereço corresponde a um endpoint de metadata de infraestrutura em nuvem e não pode ser utilizado como alvo de varredura.'
    );
  }

  if (normalizedHostname === 'localhost' || privateIp(normalizedHostname) || localTargetHosts().has(normalizedHostname)) {
    return {
      environment: 'DEVELOPMENT',
      resolvedIps: [normalizedHostname],
      suspicious: false,
    };
  }

  const resolvedIps = await resolveAllAddresses(hostname);

  if (resolvedIps.length === 0) {
    throw new ScanValidationError(
      'Não foi possível resolver o domínio informado. Verifique se a URL está correta.'
    );
  }

  if (resolvedIps.some((ip) => isBlockedAddress(ip))) {
    throw new ScanValidationError(
      'Este domínio resolve para um endpoint de metadata de infraestrutura em nuvem e não pode ser utilizado como alvo de varredura.'
    );
  }

  const resolvesToPrivateIp = resolvedIps.some((ip) => privateIp(ip));

  if (resolvesToPrivateIp) {
    // manual (RNF-23).
    return { environment: 'DEVELOPMENT', resolvedIps, suspicious: true };
  }

  if (classifyAsStaging(normalizedHostname)) {
    return { environment: 'STAGING', resolvedIps, suspicious: false };
  }

  return { environment: 'PRODUCTION', resolvedIps, suspicious: false };
};