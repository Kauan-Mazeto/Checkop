import { getComplianceNotes } from '../../constants/compliance_mapping.js';

// Campos que só o plano Premium recebe (espec.txt, seções 2 e 3): a correção
// exata, a prova de conceito (PoC) e o mapeamento de compliance.
// "detection" (como a ferramenta concluiu) faz parte da prova: também é Premium.
const PREMIUM_FIELDS = ['remediation', 'rawRequest', 'rawResponse', 'parameter', 'attack', 'reproduction', 'detection'];

// Modo Seguro: "detection" fica de fora (pode citar trechos da resposta real);
// os links de referência são públicos e ficam.
const SAFE_MODE_FIELDS = [
  'id', 'title', 'severity', 'status', 'tool', 'ruleId', 'affectedUrl', 'cveId',
  'cvssScore', 'cvssVector', 'cvssSource', 'confidence', 'owaspUrl', 'remediation', 'references', 'createdAt',
];

// RF-11: o perfil Estudante recebe o painel educacional; requisições e
// respostas cruas (payloads de ataque prontos) ficam de fora. O "detection"
// do ZAP costuma citar o payload usado, então também.
const STUDENT_HIDDEN_FIELDS = ['rawRequest', 'rawResponse', 'attack', 'reproduction', 'detection'];

// RF-07 / RF-08 (Modo Seguro) + plano Free/Premium + perfil (RF-11).
// O corte é feito aqui, no servidor: esconder só na tela não protege nada.
export const serializeFinding = (finding, { safeMode, plan = 'PREMIUM', role = null }) => {
  const base = safeMode
    ? Object.fromEntries(SAFE_MODE_FIELDS.map((key) => [key, finding[key] ?? null]))
    : { ...finding };

  if (role === 'STUDENT') {
    for (const field of STUDENT_HIDDEN_FIELDS) delete base[field];
  }

  if (plan !== 'PREMIUM') {
    for (const field of PREMIUM_FIELDS) delete base[field];
    return { ...base, compliance: [], premiumLocked: true };
  }

  return { ...base, compliance: getComplianceNotes(finding.owaspUrl), premiumLocked: false };
};

export const serializeFindings = (findings, options) =>
  findings.map((finding) => serializeFinding(finding, options));
