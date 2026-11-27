// Markdown curto das respostas da Ajuda por IA: títulos (#), listas (- e 1.),
// blocos de código (```), **negrito** e `código`. Nada vira HTML: o template
// monta os elementos a partir dos blocos, então o texto da resposta nunca executa.

export type ChatBlock =
  | { kind: 'p' | 'h'; text: string }
  | { kind: 'ul' | 'ol'; items: string[] }
  | { kind: 'code'; lang: string; text: string };

export interface ChatInline {
  text: string;
  bold?: boolean;
  code?: boolean;
}

export const parseChatMarkdown = (markdown: string): ChatBlock[] => {
  const blocks: ChatBlock[] = [];
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  let paragraph: string[] = [];
  const flush = () => {
    if (paragraph.length) blocks.push({ kind: 'p', text: paragraph.join(' ') });
    paragraph = [];
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fence = /^\s*```(\S*)\s*$/.exec(line);
    if (fence) {
      flush();
      const code: string[] = [];
      for (i++; i < lines.length && !/^\s*```\s*$/.test(lines[i]); i++) code.push(lines[i]);
      blocks.push({ kind: 'code', lang: fence[1], text: code.join('\n') });
      continue;
    }
    const trimmed = line.trim();
    if (!trimmed) {
      flush();
      continue;
    }
    const heading = /^#{1,6}\s+(.*)$/.exec(trimmed);
    const bullet = /^[-*]\s+(.*)$/.exec(trimmed);
    const numbered = /^\d+[.)]\s+(.*)$/.exec(trimmed);
    if (heading) {
      flush();
      blocks.push({ kind: 'h', text: heading[1] });
    } else if (bullet || numbered) {
      flush();
      const kind = bullet ? 'ul' : 'ol';
      const item = (bullet ?? numbered)![1];
      const last = blocks.at(-1);
      if (last && last.kind === kind) last.items.push(item);
      else blocks.push({ kind, items: [item] });
    } else {
      paragraph.push(trimmed);
    }
  }
  flush();
  return blocks;
};

/** "Use **só** o `id`" -> [{Use }, {só, bold}, { o }, {id, code}] */
export const chatInline = (text: string): ChatInline[] =>
  text
    .split(/(\*\*[^*]+\*\*|`[^`]+`)/g)
    .filter(Boolean)
    .map((part) => {
      if (part.length > 4 && part.startsWith('**') && part.endsWith('**')) return { text: part.slice(2, -2), bold: true };
      if (part.length > 2 && part.startsWith('`') && part.endsWith('`')) return { text: part.slice(1, -1), code: true };
      return { text: part };
    });
