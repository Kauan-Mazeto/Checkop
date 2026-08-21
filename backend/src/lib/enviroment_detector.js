import dns from 'node:dns/promises';
import privateIp from 'private-ip';
import { parse } from 'tldts';

const STAGING_KEYWORDS = [
  'staging', 'stg', 'homolog', 'hml', 'test',
  'qa', 'sandbox', 'dev', 'preprod', 'pre-prod',
];

/*
    1 - primeiramente, checa o obvio ( localhost / 192.0.1 / ipPrivado), para evitar ações desenecessárias
    2 - pega o IP por trás do domínio
    3 - analisa esse domínio e o subdomínio
*/
export const detectEnvironment = async (targetUrl) => {
  const { hostname } = new URL(targetUrl);

  // caso 1
  if (hostname === 'localhost' || privateIp(hostname)) {
    return { environment: 'DEVELOPMENT', resolvedIp: hostname, suspicious: false };
  }

  // caso 2
  let resolvedAddresses = [];
  try {
    resolvedAddresses = await dns.lookup(hostname, { all: true });
  } catch {
    resolvedAddresses = [];
  }

  const resolvedIps = resolvedAddresses.map((entry) => entry.address);
  const resolvesToPrivateIp = resolvedIps.some((ip) => privateIp(ip));

  if (resolvesToPrivateIp) {
    return {
      environment: 'DEVELOPMENT',
      resolvedIp: resolvedIps[0] ?? null,
      suspicious: true,
    };
  }

  // caso 3 - analise de subdominio via biblioteca instalada
  const parsed = parse(hostname);
  const subdomainParts = (parsed.subdomain || '').split('.').filter(Boolean);

  const isStaging = subdomainParts.some((part) =>
    STAGING_KEYWORDS.includes(part.toLowerCase())
  );

  if (isStaging) {
    return { environment: 'STAGING', resolvedIp: resolvedIps[0] ?? null, suspicious: false };
  }

  return { environment: 'PRODUCTION', resolvedIp: resolvedIps[0] ?? null, suspicious: false };
};