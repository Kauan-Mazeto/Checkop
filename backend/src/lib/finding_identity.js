// Identidade de um achado: quando dois achados são "a mesma falha".
// Usada na deduplicação entre ferramentas (RF-46) e na comparação entre
// varreduras do mesmo alvo (RF-19).
//
// Dois achados são a mesma falha quando têm a mesma CLASSE de vulnerabilidade e
// a mesma URL (sem query string). Assim, ZAP e Nuclei apontando o mesmo SQLi em
// /api/busca, com nomes diferentes, contam como um só.

export const SEVERITY_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

const VULN_CLASSES = [
  ['sqli', /sql[\s-]*inj|sqli/i],
  ['xss', /xss|cross[\s-]*site[\s-]*scripting/i],
  ['csrf', /csrf|cross[\s-]*site[\s-]*request[\s-]*forgery/i],
  ['ssrf', /ssrf|server[\s-]*side[\s-]*request/i],
  ['open-redirect', /redirect/i],
  ['path-traversal', /path[\s-]*traversal|\blfi\b|local[\s-]*file/i],
  ['rce', /\brce\b|remote[\s-]*code|command[\s-]*inj/i],
];

export const classifyFinding = (finding) => {
  const title = (finding.title ?? '').trim();
  for (const [name, pattern] of VULN_CLASSES) {
    if (pattern.test(title)) return name;
  }
  return title.toLowerCase();
};

export const normalizeUrl = (value) => {
  if (!value) return null;
  try {
    const url = new URL(value);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    return `${url.protocol}//${url.host}${path}`.toLowerCase();
  } catch {
    return String(value).toLowerCase(); // ex.: Subfinder devolve só o host
  }
};

export const findingKey = (finding) => {
  const where = normalizeUrl(finding.affectedUrl) ?? finding.rawRequest ?? finding.description ?? '';
  return `${classifyFinding(finding)}::${where}`;
};
