import { SEVERITY_RANK, findingKey } from './finding_identity.js';

// RF-19 - comparação entre duas varreduras do mesmo alvo.
//   novas:        estão na atual e não estavam na anterior
//   corrigidas:   estavam na anterior e sumiram na atual
//   persistentes: continuam nas duas (com a mudança de severidade, se houver)

const bySeverity = (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);

const indexByKey = (findings) => {
  const map = new Map();
  for (const finding of findings) {
    const key = findingKey(finding);
    // se a mesma falha aparecer duas vezes, vale a mais grave
    const current = map.get(key);
    if (!current || (SEVERITY_RANK[finding.severity] ?? 0) > (SEVERITY_RANK[current.severity] ?? 0)) {
      map.set(key, finding);
    }
  }
  return map;
};

export const compareFindings = (previousFindings, currentFindings) => {
  const previous = indexByKey(previousFindings);
  const current = indexByKey(currentFindings);

  const added = [];
  const persistent = [];
  for (const [key, finding] of current) {
    const before = previous.get(key);
    if (!before) {
      added.push(finding);
      continue;
    }
    const delta = (SEVERITY_RANK[finding.severity] ?? 0) - (SEVERITY_RANK[before.severity] ?? 0);
    persistent.push({
      finding,
      previousSeverity: before.severity,
      trend: delta > 0 ? 'WORSE' : delta < 0 ? 'BETTER' : 'SAME',
    });
  }

  const fixed = [...previous].filter(([key]) => !current.has(key)).map(([, finding]) => finding);

  added.sort(bySeverity);
  fixed.sort(bySeverity);
  persistent.sort((a, b) => bySeverity(a.finding, b.finding));

  return {
    added,
    fixed,
    persistent,
    summary: { added: added.length, fixed: fixed.length, persistent: persistent.length },
  };
};
