// Histórico da análise de código (Premium).
//
// Guarda SÓ o resumo do resultado, nunca o código: nomes, linguagens e número de
// linhas dos arquivos; contagens por severidade e categoria; e, por achado,
// título, severidade, categoria, arquivo, linha, regra e ferramentas.
// Ficam de fora o conteúdo dos arquivos, o trecho vulnerável (rawResponse), a
// correção sugerida, a descrição e qualquer resposta da IA.
// Ao mudar o que é guardado aqui, atualize a Política de Privacidade (item 2.4 e 6).

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const CATEGORIES = ['SECURITY', 'LOGIC', 'SYNTAX', 'DEPENDENCY', 'QUALITY'];
// histórico mostrado no painel; as mais antigas continuam na conta até o usuário apagar
export const HISTORY_LIMIT = 100;

const LANGUAGE_BY_EXTENSION = {
  js: 'JavaScript', mjs: 'JavaScript', cjs: 'JavaScript', jsx: 'JavaScript',
  ts: 'TypeScript', tsx: 'TypeScript',
  py: 'Python', java: 'Java', kt: 'Kotlin', go: 'Go', rb: 'Ruby', php: 'PHP',
  cs: 'C#', c: 'C', h: 'C', cpp: 'C++', cc: 'C++', hpp: 'C++', rs: 'Rust', swift: 'Swift',
  scala: 'Scala', sql: 'SQL', html: 'HTML', htm: 'HTML', vue: 'Vue', css: 'CSS', scss: 'SCSS',
  sh: 'Shell', bash: 'Shell', ps1: 'PowerShell', yml: 'YAML', yaml: 'YAML', json: 'JSON',
  xml: 'XML', tf: 'Terraform', dockerfile: 'Dockerfile',
};

export const languageOf = (name) => {
  const base = String(name).split(/[\\/]/).pop().toLowerCase();
  if (base === 'dockerfile') return 'Dockerfile';
  const ext = base.includes('.') ? base.split('.').pop() : '';
  return LANGUAGE_BY_EXTENSION[ext] ?? 'Outra';
};

/** "src/app.js:12-14" -> { file: "src/app.js", line: 12 } */
const locationOf = (affectedUrl) => {
  const match = /^(.*):(\d+)(?:-\d+)?$/.exec(affectedUrl ?? '');
  return match ? { file: match[1], line: Number(match[2]) } : { file: affectedUrl ?? '', line: null };
};

const countBy = (items, keys, pick) => {
  const counts = Object.fromEntries(keys.map((key) => [key, 0]));
  for (const item of items) {
    const key = pick(item);
    if (key in counts) counts[key] += 1;
  }
  return counts;
};

const clip = (value, max) => (typeof value === 'string' ? value.slice(0, max) : null);

/** Monta a linha do banco a partir do pedido e do resultado do motor (exportada para teste). */
export const summarizeAnalysis = ({ userId, files, depth, result }) => {
  const findings = (result?.findings ?? []).map((finding) => {
    const { file, line } = locationOf(finding.affectedUrl);
    return {
      title: clip(finding.title, 200),
      severity: SEVERITIES.includes(finding.severity) ? finding.severity : 'INFO',
      // sem categoria = segurança (achados do Semgrep/Gitleaks)
      category: CATEGORIES.includes(finding.category) ? finding.category : 'SECURITY',
      file: clip(file, 300),
      line,
      ruleId: clip(finding.ruleId, 200),
      tools: Array.isArray(finding.detectedBy) ? finding.detectedBy.slice(0, 10).map((t) => clip(t, 40)) : [],
    };
  });

  return {
    userId,
    depth,
    files: JSON.stringify(
      Object.entries(files).map(([name, content]) => ({
        name: clip(name, 300),
        language: languageOf(name),
        lines: typeof content === 'string' ? content.split('\n').length : 0,
      })),
    ),
    findingsCount: findings.length,
    severityCounts: JSON.stringify(countBy(findings, SEVERITIES, (f) => f.severity)),
    categoryCounts: JSON.stringify(countBy(findings, CATEGORIES, (f) => f.category)),
    findings: JSON.stringify(findings),
    durationSeconds: Number(result?.durationSeconds) || 0,
  };
};

const parse = (value, fallback) => {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
};

/** Linha do banco -> objeto da API (os campos JSON já abertos). */
export const toHistoryItem = (row) => ({
  id: row.id,
  createdAt: row.createdAt,
  depth: row.depth,
  durationSeconds: row.durationSeconds,
  findingsCount: row.findingsCount,
  files: parse(row.files, []),
  severityCounts: parse(row.severityCounts, {}),
  categoryCounts: parse(row.categoryCounts, {}),
  findings: parse(row.findings, []),
});
