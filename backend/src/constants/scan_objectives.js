// Mapeia "o que o usuário quer testar" para a configuração real de cada motor.
// Adicionar um objetivo novo = adicionar uma entrada aqui (e o valor no enum
// ScanObjective do schema.prisma).
//
// Campos:
//   engines             ferramentas acionadas
//   requiresActiveScan  só detecta enviando ataque; em alvo público exige opt-in
//   coverage            FULL | PARTIAL, conforme a matriz de docs/anotacoes.txt
//   nuclei.tags         templates executados (lista vazia = todos)
//   nuclei.activeTags   só entram com ataque liberado (ex.: tentativa de login padrão)
//   zap.activeScannerIds  null = todos; [] = nenhum (objetivo só passivo)
//   zap.alertIds        regras do ZAP cujo achado é mantido no resultado
//                       (null = todos). Filtra o "barulho" do passivo.
//
// IDs conferidos em https://www.zaproxy.org/docs/alerts/ (ZAP 2.17).
// β = regra beta (add-on ascanrulesBeta/pscanrulesBeta, instalado pelo motor).

const ZAP_ACTIVE = {
  SQLI: ['40018', '40019', '40020', '40021', '40022', '40024', '40027', '90018' /* β */],
  XSS: ['40012', '40014', '40016', '40017', '40026'],
  COMMAND_INJECTION: ['90020', '90037', '90019'],
  PATH_TRAVERSAL: ['6', '7'],
  XXE: ['90023'],
  SSTI: ['90035', '90036'],
  CRLF: ['40003'],
  OPEN_REDIRECT: ['20019'],
  CSRF: ['20012' /* β */],
  SSRF: ['40046' /* β */],
  CORS: ['40040' /* β */],
  DIRECTORY_LISTING: ['0'],
  EXPOSED_FILES: ['40034', '40032', '40035', '40028', '40029', '10095', '41', '42' /* β */],
};

const ZAP_PASSIVE = {
  OPEN_REDIRECT: ['10028'],
  CSRF: ['10202'],
  SECURITY_HEADERS: ['10020', '10021', '10035', '10038', '10055', '10063' /* β */],
  COOKIES: ['10010', '10011', '10054', '90033'],
  CLICKJACKING: ['10020'],
  CORS: ['10098'],
  DIRECTORY_LISTING: ['10033'],
  INFO_DISCLOSURE: ['90022', '10023', '10036', '10037', '10061', '10027', '2', '10096', '10097', '10024'],
};

// objetivo de ataque: roda só os scanners ativos dele e mantém só os achados deles
const activeZap = (ids, passive = []) => ({ activeScannerIds: ids, alertIds: [...ids, ...passive] });
// objetivo passivo: nenhum ataque, só observa as respostas
const passiveZap = (ids) => ({ activeScannerIds: [], alertIds: ids });

export const SCAN_OBJECTIVES = {
  SQL_INJECTION: {
    label: 'Injeção de SQL (SQLi)',
    description: 'Testa os parâmetros do site com payloads de SQL (erro, booleano, tempo e UNION).',
    owasp: 'A03:2021',
    coverage: 'FULL',
    requiresActiveScan: true,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['sqli'] },
    zap: activeZap(ZAP_ACTIVE.SQLI),
  },
  XSS: {
    label: 'Cross-Site Scripting (XSS)',
    description: 'Procura XSS refletido, armazenado e baseado em DOM.',
    owasp: 'A03:2021',
    coverage: 'FULL',
    requiresActiveScan: true,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['xss'] },
    zap: activeZap(ZAP_ACTIVE.XSS),
  },
  COMMAND_INJECTION: {
    label: 'Injeção de comandos do sistema',
    description: 'Tenta executar comandos do sistema operacional ou código no servidor.',
    owasp: 'A03:2021',
    coverage: 'FULL',
    requiresActiveScan: true,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['cmdi', 'rce'] },
    zap: activeZap(ZAP_ACTIVE.COMMAND_INJECTION),
  },
  PATH_TRAVERSAL: {
    label: 'Path Traversal / LFI',
    description: 'Tenta ler arquivos do servidor fora da pasta pública (../../etc/passwd) e incluir arquivos remotos.',
    owasp: 'A01:2021',
    coverage: 'FULL',
    requiresActiveScan: true,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['lfi'] },
    zap: activeZap(ZAP_ACTIVE.PATH_TRAVERSAL),
  },
  XXE: {
    label: 'XML External Entity (XXE)',
    description: 'Envia XML com entidades externas para ler arquivos ou acessar a rede interna.',
    owasp: 'A05:2021',
    coverage: 'FULL',
    requiresActiveScan: true,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['xxe'] },
    zap: activeZap(ZAP_ACTIVE.XXE),
  },
  SSTI: {
    label: 'Server-Side Template Injection (SSTI)',
    description: 'Injeta expressões de template ({{7*7}}) para executar código no servidor.',
    owasp: 'A03:2021',
    coverage: 'FULL',
    requiresActiveScan: true,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['ssti'] },
    zap: activeZap(ZAP_ACTIVE.SSTI),
  },
  CRLF_INJECTION: {
    label: 'CRLF / injeção de cabeçalho',
    description: 'Injeta quebras de linha para criar cabeçalhos HTTP ou dividir a resposta.',
    owasp: 'A03:2021',
    coverage: 'FULL',
    requiresActiveScan: true,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['crlf'] },
    zap: activeZap(ZAP_ACTIVE.CRLF),
  },
  OPEN_REDIRECT: {
    label: 'Open Redirect',
    description: 'Verifica se o site redireciona para qualquer endereço externo (usado em phishing).',
    owasp: 'A01:2021',
    coverage: 'FULL',
    requiresActiveScan: true,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['redirect'] },
    zap: activeZap(ZAP_ACTIVE.OPEN_REDIRECT, ZAP_PASSIVE.OPEN_REDIRECT),
  },
  CSRF: {
    label: 'Cross-Site Request Forgery (CSRF)',
    description: 'Detecta formulários sem token anti-CSRF. Não prova a exploração.',
    owasp: 'A01:2021',
    coverage: 'PARTIAL',
    requiresActiveScan: false,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['csrf'] },
    zap: activeZap(ZAP_ACTIVE.CSRF, ZAP_PASSIVE.CSRF),
  },
  SSRF: {
    label: 'Server-Side Request Forgery (SSRF)',
    description: 'Tenta fazer o servidor acessar endereços indicados pelo atacante.',
    owasp: 'A10:2021',
    coverage: 'PARTIAL',
    requiresActiveScan: true,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['ssrf'] },
    zap: activeZap(ZAP_ACTIVE.SSRF),
  },
  SECURITY_HEADERS: {
    label: 'Cabeçalhos de segurança',
    description: 'Confere CSP, HSTS, X-Frame-Options, X-Content-Type-Options e Permissions-Policy.',
    owasp: 'A05:2021',
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['headers'] },
    zap: passiveZap(ZAP_PASSIVE.SECURITY_HEADERS),
  },
  COOKIES: {
    label: 'Cookies inseguros',
    description: 'Verifica os atributos HttpOnly, Secure e SameSite e o escopo dos cookies.',
    owasp: 'A05:2021',
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['cookie'] },
    zap: passiveZap(ZAP_PASSIVE.COOKIES),
  },
  CLICKJACKING: {
    label: 'Clickjacking',
    description: 'Verifica se o site pode ser embutido em iframe de outro domínio.',
    owasp: 'A05:2021',
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['clickjacking'] },
    zap: passiveZap(ZAP_PASSIVE.CLICKJACKING),
  },
  CORS: {
    label: 'CORS mal configurado',
    description: 'Verifica se outros domínios conseguem ler as respostas da API.',
    owasp: 'A05:2021',
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['cors'] },
    zap: activeZap(ZAP_ACTIVE.CORS, ZAP_PASSIVE.CORS),
  },
  DIRECTORY_LISTING: {
    label: 'Listagem de diretórios',
    description: 'Procura pastas que exibem a lista de arquivos do servidor.',
    owasp: 'A05:2021',
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['listing'] },
    zap: activeZap(ZAP_ACTIVE.DIRECTORY_LISTING, ZAP_PASSIVE.DIRECTORY_LISTING),
  },
  EXPOSED_FILES: {
    label: 'Arquivos sensíveis expostos',
    description: 'Procura .env, .git, backups e arquivos de configuração acessíveis publicamente.',
    owasp: 'A05:2021',
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['exposure', 'backup', 'git', 'env'] },
    zap: activeZap(ZAP_ACTIVE.EXPOSED_FILES),
  },
  ADMIN_PANELS: {
    label: 'Painéis administrativos e login padrão',
    description: 'Encontra painéis de administração expostos. Com a varredura ativa autorizada, testa também credenciais padrão.',
    owasp: 'A07:2021',
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI'],
    // tentativa de login é ataque: só com opt-in (art. 154-A do CP)
    nuclei: { tags: ['panel'], activeTags: ['default-login'] },
    zap: null,
  },
  INFO_DISCLOSURE: {
    label: 'Vazamento de informação',
    description: 'Detecta stack traces, versões de servidor, comentários e dados sensíveis nas respostas.',
    owasp: 'A05:2021',
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: ['disclosure', 'debug', 'error'] },
    zap: passiveZap(ZAP_PASSIVE.INFO_DISCLOSURE),
  },
  API_EXPOSURE: {
    label: 'Swagger / GraphQL expostos',
    description: 'Procura documentação de API e endpoints GraphQL abertos ao público.',
    owasp: 'A05:2021',
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI'],
    nuclei: { tags: ['swagger', 'graphql'] },
    zap: null,
  },
  KNOWN_CVE: {
    label: 'Componentes desatualizados e CVEs',
    description: 'Identifica versões de frameworks e servidores com vulnerabilidades conhecidas.',
    owasp: 'A06:2021',
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI'],
    nuclei: { tags: ['cve', 'misconfig'] },
    zap: null,
  },
  SSL_TLS: {
    label: 'TLS/SSL (certificado, protocolos e cifras)',
    description: 'Verifica certificado, protocolos obsoletos (TLS 1.0/1.1) e cifras fracas.',
    owasp: 'A02:2021',
    coverage: 'PARTIAL',
    requiresActiveScan: false,
    engines: ['NUCLEI'],
    nuclei: { tags: ['ssl', 'tls'] },
    zap: null,
  },
  DNS_CHECK: {
    label: 'DNS e subdomain takeover',
    description: 'Procura registros DNS apontando para serviços abandonados que podem ser sequestrados.',
    owasp: 'A05:2021',
    coverage: 'PARTIAL',
    requiresActiveScan: false,
    engines: ['NUCLEI'],
    nuclei: { tags: ['dns', 'takeover'] },
    zap: null,
  },
  SUBDOMAIN_ENUM: {
    label: 'Enumeração de subdomínios',
    description: 'Lista subdomínios em fontes públicas (não envia requisições ao alvo).',
    owasp: null,
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['SUBFINDER'],
    nuclei: null,
    zap: null,
  },
  FULL_SCAN: {
    label: 'Varredura completa (todas as categorias)',
    description: 'Executa todas as verificações. Pode levar mais de 20 minutos.',
    owasp: null,
    coverage: 'FULL',
    requiresActiveScan: false,
    engines: ['NUCLEI', 'ZAP'],
    nuclei: { tags: [] }, // vazio = todos os templates
    zap: { activeScannerIds: null, alertIds: null }, // todos
  },
};

export const isValidObjective = (value) => Object.prototype.hasOwnProperty.call(SCAN_OBJECTIVES, value);

/** Lista pública para o front montar o seletor (sem detalhes internos dos motores). */
export const listObjectives = () =>
  Object.entries(SCAN_OBJECTIVES).map(([key, o]) => ({
    key,
    label: o.label,
    description: o.description,
    owasp: o.owasp,
    coverage: o.coverage,
    requiresActiveScan: o.requiresActiveScan,
    engines: o.engines,
  }));

/**
 * Mantém só os achados que respondem ao objetivo escolhido. Nuclei e Subfinder
 * já rodam restritos pelas tags; o ZAP sempre devolve também os alertas do
 * passivo (que roda tudo), então é filtrado pelo id da regra.
 */
export const filterFindingsByObjective = (findings, objectiveKey) => {
  const allowedZapIds = SCAN_OBJECTIVES[objectiveKey]?.zap?.alertIds;
  if (!allowedZapIds) {
    // objetivo sem ZAP: qualquer alerta do ZAP é ruído; FULL_SCAN (alertIds null): mantém tudo
    const keepZap = objectiveKey === 'FULL_SCAN';
    return findings.filter((f) => f.tool !== 'ZAP' || keepZap);
  }
  const allowed = new Set(allowedZapIds);
  return findings.filter((f) => f.tool !== 'ZAP' || allowed.has(f.ruleId));
};
