// Detecta a linguagem de um código colado pelas marcas típicas de cada uma.
// Usado para barrar a análise quando a linguagem escolhida não é a do código (Python
// analisado como JavaScript não roda as ferramentas de Python e dá um resultado pobre).
//
// Só aponta uma linguagem quando ela ganha com folga: na dúvida, não bloqueia nada.

interface Signature {
  /** filename da linguagem em LANGUAGES (code-view.ts) */
  filename: string;
  /** [padrão, peso]: forte (3) é quase exclusivo da linguagem; fraco (1) só ajuda */
  marks: [RegExp, number][];
}

const SIGNATURES: Signature[] = [
  {
    filename: 'app.py',
    marks: [
      [/^\s*def \w+\s*\([^)]*\)\s*(->\s*[^:]+)?:\s*(#.*)?$/m, 3],
      [/^\s*from [\w.]+ import [\w*, ()]+$/m, 3],
      [/^\s*(elif|except\b.*|try|finally|else)\s*:\s*(#.*)?$/m, 2],
      [/^\s*(if|for|while|with|class)\b[^{;]*:\s*(#.*)?$/m, 2],
      [/__name__\s*==\s*["']__main__["']/, 3],
      [/^\s*import [\w.]+(\s+as \w+)?\s*$/m, 1],
      [/\b(None|True|False)\b/, 1],
      [/\bself\./, 1],
      [/^\s*@[\w.]+(\(.*\))?\s*$/m, 1],
      [/\bprint\(/, 1],
    ],
  },
  {
    filename: 'app.js',
    marks: [
      [/\b(const|let)\s+\w+\s*=/, 2],
      [/\bfunction\s*\w*\s*\([^)]*\)\s*\{/, 3],
      [/=>\s*[{(]?/, 2],
      [/\brequire\(\s*['"][^'"]+['"]\s*\)/, 3],
      [/\bconsole\.(log|error|warn)\(/, 2],
      [/\bmodule\.exports\b|\bexport (default|const|function)\b/, 3],
      [/===|!==/, 2],
      [/^\s*import .+ from ['"][^'"]+['"];?\s*$/m, 3],
    ],
  },
  {
    filename: 'app.ts',
    marks: [
      [/:\s*(string|number|boolean|any|void|unknown)(\[\])?\s*[,)=;{]/, 3],
      [/\binterface \w+\s*\{/, 3],
      [/\btype \w+\s*=/, 2],
      [/\b(public|private|readonly)\s+\w+\s*:/, 2],
    ],
  },
  { filename: 'login.php', marks: [[/<\?php/, 4], [/\$\w+\s*=/, 2], [/\$_(GET|POST|REQUEST|COOKIE|SESSION)\b/, 3], [/\becho\s/, 1]] },
  {
    filename: 'app.rb',
    marks: [[/^\s*def \w+[?!]?(\(.*\))?\s*$/m, 2], [/^\s*end\s*$/m, 2], [/\bputs\s/, 3], [/\brequire\s+['"]/, 2], [/\bdo\s*\|\w+/, 3], [/^\s*(module|class) \w+\s*(<\s*\w+)?\s*$/m, 1]],
  },
  { filename: 'main.go', marks: [[/^package \w+\s*$/m, 4], [/\bfunc \w*\s*\(/, 3], [/:=/, 2], [/\bfmt\.\w+\(/, 3], [/^import \(/m, 3]] },
  { filename: 'index.html', marks: [[/<!doctype html/i, 4], [/<html[\s>]/i, 4], [/<(head|body|div|form|script)[\s>]/i, 2]] },
  {
    filename: 'Busca.java',
    marks: [[/\bpublic\s+(static\s+)?(final\s+)?(class|void|interface)\b/, 3], [/\bSystem\.out\.print/, 4], [/^import java\./m, 4], [/\bString\[\]\s+\w+/, 3], [/\bnew \w+\(.*\);/, 1]],
  },
  { filename: 'Busca.kt', marks: [[/\bfun \w+\s*\(/, 4], [/\bval \w+(\s*:\s*\w+\??)?\s*=/, 2], [/\bprintln\(/, 1], [/!!/, 2]] },
  { filename: 'Ping.scala', marks: [[/^\s*object \w+/m, 3], [/\bdef \w+\(.*\)\s*(:\s*\w+)?\s*=/, 3], [/^import scala\./m, 4]] },
  {
    filename: 'HomeController.cs',
    marks: [[/^using System[\w.]*;/m, 4], [/^\s*namespace [\w.]+/m, 3], [/\bConsole\.Write/, 4], [/\[(HttpGet|HttpPost|ApiController|Route)/, 4], [/\bpublic\s+(async\s+)?\w+(<[\w,\s]+>)?\s+\w+\s*\(/, 1]],
  },
  { filename: 'main.c', marks: [[/^#include\s*[<"]/m, 4], [/\bint main\s*\(/, 3], [/\bprintf\(/, 2], [/\b(malloc|free|strcpy|sizeof)\(/, 2]] },
  { filename: 'main.rs', marks: [[/\bfn \w+\s*\(/, 3], [/\blet mut\b/, 3], [/\bprintln!\(/, 4], [/^use (std|crate)::/m, 4], [/\bimpl\b/, 2]] },
  { filename: 'Sessao.swift', marks: [[/^import (UIKit|Foundation|SwiftUI)\s*$/m, 4], [/\bguard let\b/, 4], [/\bfunc \w+\s*\(/, 2], [/\bvar \w+\s*:\s*\w+/, 1]] },
  { filename: 'deploy.sh', marks: [[/^#!.*\b(ba|z)?sh\b/m, 4], [/^\s*(fi|done|esac)\s*$/m, 3], [/\bthen\s*$/m, 2], [/\$\{?\w+\}?/, 1], [/^\s*echo\s/m, 1]] },
  { filename: 'Dockerfile', marks: [[/^FROM\s+\S+/m, 4], [/^(RUN|COPY|CMD|ENTRYPOINT|WORKDIR|EXPOSE|ENV)\s/m, 3]] },
  { filename: 'main.tf', marks: [[/^\s*(resource|provider|variable|module|output)\s+"/m, 4], [/^\s*terraform\s*\{/m, 4]] },
  { filename: 'deployment.yaml', marks: [[/^apiVersion:\s*\S+/m, 4], [/^kind:\s*\S+/m, 3], [/^\s*[\w-]+:\s*\S*\s*$/m, 1]] },
  { filename: '.github/workflows/ci.yml', marks: [[/^on:\s*($|\[|\w)/m, 3], [/^jobs:\s*$/m, 3], [/\bruns-on:/, 4], [/\buses:\s*[\w-]+\/[\w-]+@/, 4]] },
  { filename: 'requirements.txt', marks: [[/^[A-Za-z][\w.-]*\s*(==|>=|<=|~=)\s*[\d.]+\s*$/m, 3]] },
  { filename: 'go.mod', marks: [[/^module\s+\S+/m, 4], [/^go\s+\d+\.\d+/m, 4]] },
];

/** Linguagens que podem ser analisadas uma como a outra sem perder nada. */
const COMPATIBLE: Record<string, string[]> = {
  // TypeScript aceita JavaScript puro
  'app.ts': ['app.js'],
  // os dois YAMLs passam pelas mesmas ferramentas
  'deployment.yaml': ['.github/workflows/ci.yml'],
  '.github/workflows/ci.yml': ['deployment.yaml'],
};

const MIN_SCORE = 5;

const score = (code: string, signature: Signature): number =>
  signature.marks.reduce((sum, [pattern, weight]) => sum + (pattern.test(code) ? weight : 0), 0);

/** filename da linguagem detectada, ou null se não der para afirmar com segurança. */
export const detectLanguage = (code: string): string | null => {
  if (code.trim().length < 20) return null;
  const ranked = SIGNATURES.map((s) => ({ filename: s.filename, score: score(code, s) })).sort((a, b) => b.score - a.score);
  const [best, second] = ranked;
  // precisa de marcas suficientes e de folga sobre a segunda colocada
  if (!best || best.score < MIN_SCORE || best.score < (second?.score ?? 0) * 1.5) return null;
  return best.filename;
};

/**
 * A linguagem escolhida não é a do código? Devolve o filename detectado; null quando
 * bate, quando são compatíveis ou quando a detecção não tem certeza (não bloqueia).
 */
export const languageMismatch = (code: string, selected: string): string | null => {
  const detected = detectLanguage(code);
  if (!detected || detected === selected || COMPATIBLE[selected]?.includes(detected)) return null;
  // o código também tem marcas fortes da linguagem escolhida: na dúvida, deixa analisar
  const chosen = SIGNATURES.find((s) => s.filename === selected);
  if (chosen && score(code, chosen) >= MIN_SCORE) return null;
  return detected;
};
