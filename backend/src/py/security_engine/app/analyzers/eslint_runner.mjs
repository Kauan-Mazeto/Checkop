import { readFileSync } from 'node:fs';
// Roda o ESLint com a configuração do Checkop sobre a pasta analisada e imprime
// o resultado em JSON. A configuração fica aqui (e não num eslint.config da pasta)
// porque o código do usuário nunca traz a nossa configuração.
//
// Uso: node eslint_runner.mjs <pasta-dos-pacotes> <pasta-analisada> [complete|essential]
// <pasta-dos-pacotes> = onde o npm instalou app/analyzers/js/package.json
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [packagesDir, scanDir, mode = 'complete'] = process.argv.slice(2);
const complete = mode !== 'essential';
const require = createRequire(path.join(packagesDir, 'package.json'));
const load = async (name) => (await import(pathToFileURL(require.resolve(name)).href)).default;

const { ESLint } = await import(pathToFileURL(require.resolve('eslint')).href);
const js = await load('@eslint/js');
const globals = await load('globals');
const security = await load('eslint-plugin-security');
const tseslint = await load('typescript-eslint');

const JS_FILES = ['**/*.js', '**/*.mjs', '**/*.cjs', '**/*.jsx'];
const TS_FILES = ['**/*.ts', '**/*.tsx', '**/*.mts', '**/*.cts'];
// trecho colado pode ser de navegador ou de Node: os dois conjuntos de globais
const environment = { ...globals.browser, ...globals.node };

const config = [
  // erros de lógica do JavaScript (variável indefinida, código inalcançável, chave duplicada...)
  {
    ...js.configs.recommended,
    files: JS_FILES,
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: environment,
    },
  },
  // TypeScript: as mesmas checagens com o parser do TS
  ...tseslint.configs.recommended.map((item) => ({ ...item, files: TS_FILES })),
  { files: TS_FILES, languageOptions: { globals: environment } },
  // padrões inseguros (eval com expressão, child_process, regex vulnerável...)
  { ...security.configs.recommended, files: [...JS_FILES, ...TS_FILES] },
  // modo essencial: ruído de estilo fica de fora (só bug e insegurança)
  {
    files: [...JS_FILES, ...TS_FILES],
    rules: {
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      'no-empty': 'off',
      // gera um alerta em quase todo acesso obj[chave]: falso positivo demais
      'security/detect-object-injection': 'off',
    },
  },
];

// modo completo: tudo o que o ESLint, o typescript-eslint e o plugin security conseguem apontar
// sem configuração do projeto (o que estiver fora do "recommended" vira "Boa prática")
const COMPLETE_JS_RULES = {
  'no-unused-vars': 'warn', eqeqeq: 'warn', 'no-shadow': 'warn', 'no-var': 'warn', 'prefer-const': 'warn',
  'no-eval': 'error', 'no-implied-eval': 'error', 'no-new-func': 'error', 'no-script-url': 'error',
  'no-param-reassign': 'warn', 'no-return-assign': 'warn', 'no-throw-literal': 'warn', 'no-unused-expressions': 'warn',
  'consistent-return': 'warn', 'default-case': 'warn', 'default-case-last': 'warn', 'array-callback-return': 'warn',
  'no-await-in-loop': 'warn', 'require-atomic-updates': 'warn', 'no-promise-executor-return': 'warn',
  'no-template-curly-in-string': 'warn', 'no-unreachable-loop': 'warn', 'no-constructor-return': 'warn',
  'no-self-compare': 'warn', 'no-unmodified-loop-condition': 'warn', 'no-use-before-define': 'warn',
  'no-alert': 'warn', 'no-caller': 'error', 'no-extend-native': 'warn', 'no-proto': 'warn', 'no-iterator': 'warn',
  'no-new-wrappers': 'warn', 'no-sequences': 'warn', 'no-lone-blocks': 'warn', 'no-useless-concat': 'warn',
  'no-useless-return': 'warn', 'no-else-return': 'warn', 'no-lonely-if': 'warn', 'no-nested-ternary': 'warn',
  'no-unneeded-ternary': 'warn', 'no-empty-function': 'warn', 'no-magic-numbers': 'off', 'radix': 'warn',
  'yoda': 'warn', 'prefer-promise-reject-errors': 'warn', 'require-await': 'warn', 'guard-for-in': 'warn',
  'no-empty': 'warn', 'complexity': ['warn', 15], 'max-depth': ['warn', 5], 'max-params': ['warn', 6],
  'max-nested-callbacks': ['warn', 4], 'no-implicit-coercion': 'warn', 'no-labels': 'warn', 'no-octal-escape': 'warn',
};
if (complete) {
  config.push({ files: JS_FILES, rules: COMPLETE_JS_RULES });
  config.push(...tseslint.configs.strict.map((item) => ({ ...item, files: TS_FILES })));
  config.push({ files: TS_FILES, rules: { ...COMPLETE_JS_RULES, 'no-unused-vars': 'off', 'no-shadow': 'off', 'no-use-before-define': 'off',
    '@typescript-eslint/no-unused-vars': 'warn', '@typescript-eslint/no-shadow': 'warn', '@typescript-eslint/no-explicit-any': 'warn' } });
  // detect-object-injection volta: no completo vale até o que costuma ser falso positivo
  config.push({ files: [...JS_FILES, ...TS_FILES], rules: { 'security/detect-object-injection': 'warn' } });
}

// regras do conjunto recomendado (bug de verdade); as demais são "boa prática"
const RECOMMENDED = new Set([
  ...Object.keys(js.configs.recommended.rules ?? {}),
  ...tseslint.configs.recommended.flatMap((item) => Object.keys(item.rules ?? {})),
]);

const eslint = new ESLint({ cwd: scanDir, overrideConfigFile: true, overrideConfig: config, errorOnUnmatchedPattern: false });
const results = await eslint.lintFiles([...JS_FILES, ...TS_FILES]);
// correção pronta do ESLint (fix automático ou a 1ª sugestão), em linha/coluna 1-based
// sobre o código enviado: o motor aplica e mostra o trecho já corrigido
const toEdits = (fix, text) => {
  if (!fix || !Array.isArray(fix.range)) return [];
  const pos = (offset) => {
    const before = text.slice(0, offset).split(String.fromCharCode(10));
    return { line: before.length, col: before[before.length - 1].length + 1 };
  };
  const a = pos(fix.range[0]);
  const b = pos(fix.range[1]);
  return [{ sl: a.line, sc: a.col, el: b.line, ec: b.col, text: fix.text ?? '' }];
};
const readSource = (file) => {
  try { return readFileSync(file, 'utf8'); } catch { return ''; }
};

const slim = results
  .filter((r) => r.messages.length > 0)
  .map((r) => ({ r, text: r.source ?? readSource(r.filePath) }))
  .map(({ r, text }) => ({
    filePath: r.filePath,
    messages: r.messages.map((m) => ({
      edits: toEdits(m.fix ?? m.suggestions?.[0]?.fix, text),
      ruleId: m.ruleId ?? null,
      category: !m.ruleId || m.ruleId.startsWith('security/') || RECOMMENDED.has(m.ruleId) ? 'LOGIC' : 'QUALITY',
      severity: m.severity,
      fatal: Boolean(m.fatal),
      message: m.message,
      line: m.line ?? 1,
      endLine: m.endLine ?? m.line ?? 1,
    })),
  }));
process.stdout.write(JSON.stringify(slim));
