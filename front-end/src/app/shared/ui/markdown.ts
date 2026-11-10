export type MarkdownBlock = { kind: 'h1' | 'h2' | 'p'; text: string } | { kind: 'ul'; items: string[] };

/** Converte o markdown simples dos textos legais (títulos, listas, parágrafos) em blocos. */
export const parseSimpleMarkdown = (markdown: string): MarkdownBlock[] => {
  const blocks: MarkdownBlock[] = [];
  for (const raw of markdown.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('## ')) blocks.push({ kind: 'h2', text: line.slice(3) });
    else if (line.startsWith('# ')) blocks.push({ kind: 'h1', text: line.slice(2) });
    else if (line.startsWith('- ')) {
      const last = blocks.at(-1);
      if (last?.kind === 'ul') last.items.push(line.slice(2));
      else blocks.push({ kind: 'ul', items: [line.slice(2)] });
    } else blocks.push({ kind: 'p', text: line });
  }
  return blocks;
};
