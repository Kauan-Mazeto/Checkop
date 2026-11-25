// Destaque de sintaxe leve para o editor (cores no estilo Min Theme, escuro).
// Não é um parser: reconhece comentários, strings, números, palavras-chave, chamadas de
// função, tipos e anotações, o que basta para todas as linguagens aceitas na análise.

/** Acima disso o destaque fica desligado (o editor continua funcionando, sem cor). */
export const HIGHLIGHT_MAX_CHARS = 200_000;

const KEYWORDS = new Set([
  // controle de fluxo e declarações (JS/TS, Python, Java, C#, Go, Rust, PHP, Ruby, C/C++, Kotlin, Swift)
  'if', 'else', 'elif', 'for', 'while', 'do', 'switch', 'case', 'default', 'break', 'continue', 'return',
  'try', 'catch', 'except', 'finally', 'throw', 'throws', 'raise', 'with', 'as', 'in', 'of', 'is', 'not', 'and', 'or',
  'function', 'func', 'fn', 'def', 'lambda', 'class', 'struct', 'interface', 'enum', 'trait', 'impl', 'type', 'object',
  'const', 'let', 'var', 'val', 'mut', 'static', 'final', 'public', 'private', 'protected', 'internal', 'readonly',
  'abstract', 'override', 'virtual', 'sealed', 'async', 'await', 'yield', 'new', 'delete', 'typeof', 'instanceof',
  'import', 'from', 'export', 'package', 'namespace', 'using', 'use', 'mod', 'pub', 'extends', 'implements',
  'require', 'include', 'echo', 'print', 'pass', 'global', 'nonlocal', 'defer', 'go', 'select', 'chan', 'map',
  'match', 'when', 'unless', 'until', 'begin', 'end', 'then', 'fi', 'done', 'esac', 'elsif', 'module', 'self',
  'this', 'super', 'void', 'int', 'long', 'short', 'double', 'float', 'char', 'bool', 'boolean', 'byte', 'string',
  'decimal', 'unsigned', 'signed', 'sizeof', 'goto', 'extern', 'volatile', 'register', 'inline', 'where', 'loop',
  'unsafe', 'dyn', 'ref', 'out', 'params', 'get', 'set', 'fun', 'data', 'companion', 'guard', 'let',
  // instruções do Dockerfile
  'FROM', 'RUN', 'CMD', 'COPY', 'ADD', 'ENV', 'ARG', 'WORKDIR', 'EXPOSE', 'USER', 'ENTRYPOINT', 'LABEL', 'VOLUME', 'HEALTHCHECK',
  // SQL
  'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WHERE', 'INTO', 'VALUES', 'JOIN', 'ORDER', 'GROUP', 'BY', 'CREATE', 'TABLE',
]);

const CONSTANTS = new Set(['true', 'false', 'True', 'False', 'null', 'None', 'nil', 'undefined', 'NaN', 'NULL', 'TRUE', 'FALSE']);

/** linguagens em que # começa comentário (nas demais # é diretiva, campo privado etc.) */
const HASH_COMMENT = /\.(py|rb|sh|bash|zsh|ya?ml|tf|hcl|toml|r|pl|ex|exs|conf|ini|txt)$|(^|\/)(dockerfile|containerfile|makefile)$/i;

const escape = (text: string): string => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const span = (cls: string, text: string): string => `<span class="tk-${cls}">${escape(text)}</span>`;

/** HTML com o código destacado (o texto é escapado; só entram spans com classe). */
export const highlightCode = (code: string, filename: string): string => {
  if (code.length > HIGHLIGHT_MAX_CHARS) return escape(code);
  const hashComments = HASH_COMMENT.test(filename) || /\.php$/i.test(filename);
  const token = new RegExp(
    [
      String.raw`(?<block>\/\*[\s\S]*?(?:\*\/|$)|<!--[\s\S]*?(?:-->|$))`,
      String.raw`(?<line>\/\/[^\n]*${hashComments ? String.raw`|#[^\n]*` : ''})`,
      String.raw`(?<str>"""[\s\S]*?(?:"""|$)|'''[\s\S]*?(?:'''|$)|"(?:\\.|[^"\\\n])*"?|'(?:\\.|[^'\\\n])*'?|\x60(?:\\.|[^\x60\\])*\x60?)`,
      String.raw`(?<num>\b(?:0x[\da-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b)`,
      String.raw`(?<deco>@[A-Za-z_][\w.]*)`,
      String.raw`(?<word>[A-Za-z_$][\w$]*)`,
    ].join('|'),
    'g',
  );

  let html = '';
  let last = 0;
  for (const match of code.matchAll(token)) {
    const index = match.index ?? 0;
    html += escape(code.slice(last, index));
    const text = match[0];
    const g = match.groups ?? {};
    if (g['block'] !== undefined || g['line'] !== undefined) html += span('comment', text);
    else if (g['str'] !== undefined) html += span('string', text);
    else if (g['num'] !== undefined) html += span('number', text);
    else if (g['deco'] !== undefined) html += span('deco', text);
    else if (CONSTANTS.has(text)) html += span('number', text);
    else if (KEYWORDS.has(text)) html += span('keyword', text);
    else if (/^\s*\(/.test(code.slice(index + text.length, index + text.length + 2))) html += span('func', text);
    else if (/^[A-Z][a-z]/.test(text)) html += span('type', text);
    else html += escape(text);
    last = index + text.length;
  }
  return html + escape(code.slice(last));
};
