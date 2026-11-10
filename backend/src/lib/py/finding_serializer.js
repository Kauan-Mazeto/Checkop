import { getComplianceNotes } from '../../constants/compliance_mapping.js';

// Campos que só o plano Premium recebe (espec.txt, seções 2 e 3): a correção
// exata, a prova de conceito (PoC) e o mapeamento de compliance.
const PREMIUM_FIELDS = ['remediation', 'rawRequest', 'rawResponse', 'parameter'];

const SAFE_MODE_FIELDS = [
  'id', 'title', 'severity', 'status', 'tool', 'ruleId', 'affectedUrl', 'cveId',
  'cvssScore', 'owaspUrl', 'remediation', 'createdAt',
];

// RF-07 / RF-08 (Modo Seguro) + plano Free/Premium.
// O corte é feito aqui, no servidor: esconder só na tela não protege nada.
export const serializeFinding = (finding, { safeMode, plan = 'PREMIUM' }) => {
  const base = safeMode
    ? Object.fromEntries(SAFE_MODE_FIELDS.map((key) => [key, finding[key] ?? null]))
    : { ...finding };

  if (plan !== 'PREMIUM') {
    for (const field of PREMIUM_FIELDS) delete base[field];
    return { ...base, compliance: [], premiumLocked: true };
  }

  return { ...base, compliance: getComplianceNotes(finding.owaspUrl), premiumLocked: false };
};

export const serializeFindings = (findings, options) =>
  findings.map((finding) => serializeFinding(finding, options));
