import { SEVERITY_RANK, classifyFinding, findingKey, normalizeUrl } from './finding_identity.js';

/**
 * Comparação FALHA com FALHA (entradas já agrupadas por groupFindings, com `locations`).
 * Cada falha cai em uma lista só:
 *   novas:        a falha não existia na varredura anterior
 *   corrigidas:   sumiu de todos os locais
 *   persistentes: continua existindo; traz quantos locais foram corrigidos e quantos são novos
 * Assim a mesma falha nunca aparece em duas listas (ex.: corrigida numa URL e ainda aberta em outra).
 */
export const compareGroups = (previousGroups, currentGroups) => {
  const byClass = (groups) => new Map(groups.map((group) => [classifyFinding(group), group]));
  const previous = byClass(previousGroups);
  const current = byClass(currentGroups);
  const urlsOf = (group) => new Set((group.locations ?? [group]).map((l) => normalizeUrl(l.affectedUrl) ?? ''));

  const added = [];
  const persistent = [];
  for (const [key, group] of current) {
    const before = previous.get(key);
    if (!before) {
      added.push(group);
      continue;
    }
    const nowUrls = urlsOf(group);
    const beforeUrls = urlsOf(before);
    const delta = (SEVERITY_RANK[group.severity] ?? 0) - (SEVERITY_RANK[before.severity] ?? 0);
    persistent.push({
      ...group,
      previousSeverity: before.severity,
      trend: delta > 0 ? 'WORSE' : delta < 0 ? 'BETTER' : 'SAME',
      fixedLocations: [...beforeUrls].filter((url) => !nowUrls.has(url)).length,
      newLocations: [...nowUrls].filter((url) => !beforeUrls.has(url)).length,
    });
  }
  const fixed = [...previous].filter(([key]) => !current.has(key)).map(([, group]) => group);

  added.sort(bySeverity);
  fixed.sort(bySeverity);
  persistent.sort(bySeverity);
  return {
    added,
    fixed,
    persistent,
    summary: { added: added.length, fixed: fixed.length, persistent: persistent.length },
  };
};

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
