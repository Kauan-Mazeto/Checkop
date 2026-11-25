import { SEVERITY_RANK, classifyFinding } from './finding_identity.js';

// Uma entrada por falha na tela e nos relatórios: a mesma falha em várias
// URLs (ex.: "CSP ausente" em 6 páginas) vira um item só, com a lista de
// locais dentro. No banco cada local continua sendo um registro, o que mantém
// a comparação entre varreduras (RF-19) por URL.
//
// Mesma falha = mesma classe de vulnerabilidade (finding_identity.js): ZAP e
// Nuclei apontando XSS com nomes diferentes também se juntam.

const rank = (finding) => [SEVERITY_RANK[finding.severity] ?? 0, finding.cvssScore ?? 0];

const moreSevere = (a, b) => {
  const [sa, ca] = rank(a);
  const [sb, cb] = rank(b);
  return sa !== sb ? sa > sb : ca > cb;
};

// campos que mudam de um local para outro (o resto é igual dentro do grupo)
const LOCATION_FIELDS = ['id', 'affectedUrl', 'parameter', 'attack', 'reproduction', 'severity', 'cvssScore', 'confidence', 'status', 'rawRequest', 'rawResponse'];

const toLocation = (finding) =>
  Object.fromEntries(LOCATION_FIELDS.filter((field) => field in finding).map((field) => [field, finding[field]]));

export const groupFindings = (findings) => {
  const groups = new Map();

  for (const finding of findings) {
    const key = classifyFinding(finding);
    const group = groups.get(key);
    if (!group) {
      groups.set(key, { main: finding, members: [finding] });
      continue;
    }
    group.members.push(finding);
    if (moreSevere(finding, group.main)) group.main = finding;
  }

  return [...groups.values()].map(({ main, members }) => {
    // o local mais grave primeiro; depois em ordem de URL
    const locations = [...members]
      .sort((a, b) => (moreSevere(a, b) ? -1 : moreSevere(b, a) ? 1 : String(a.affectedUrl).localeCompare(String(b.affectedUrl))))
      .map(toLocation);
    const tools = [...new Set(members.map((member) => member.tool))];
    return { ...main, tools, locations };
  });
};
