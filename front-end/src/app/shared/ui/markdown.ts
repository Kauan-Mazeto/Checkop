// Markdown simples dos textos legais (backend/src/lib/terms_of_use.js e
// privacity.js): "#", "##", "###", listas com "- ", destaque com "> " e
// negrito com **texto**. Nada vira HTML: o template monta os elementos a partir
// dos blocos e dos trechos, então nenhum conteúdo do texto é executado.

export type MarkdownBlock =
  | { kind: 'h1' | 'h3' | 'p' | 'quote'; text: string }
  | { kind: 'h2'; text: string; id: string }
  | { kind: 'ul'; items: string[] };

export interface InlineSegment {
  text: string;
  bold: boolean;
}

/** "3. Planos e cobrança" -> "3-planos-e-cobranca" (âncora do sumário) */
export const slugify = (text: string): string =>
  text
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

export const parseSimpleMarkdown = (markdown: string): MarkdownBlock[] => {
  const blocks: MarkdownBlock[] = [];
  for (const raw of markdown.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('### ')) blocks.push({ kind: 'h3', text: line.slice(4) });
    else if (line.startsWith('## ')) blocks.push({ kind: 'h2', text: line.slice(3), id: slugify(line.slice(3)) });
    else if (line.startsWith('# ')) blocks.push({ kind: 'h1', text: line.slice(2) });
    else if (line.startsWith('> ')) blocks.push({ kind: 'quote', text: line.slice(2) });
    else if (line.startsWith('- ')) {
      const last = blocks.at(-1);
      if (last?.kind === 'ul') last.items.push(line.slice(2));
      else blocks.push({ kind: 'ul', items: [line.slice(2)] });
    } else blocks.push({ kind: 'p', text: line });
  }
  return blocks;
};

/** "Use **só** alvos seus" -> [{Use }, {só, bold}, { alvos seus}] */
export const inlineSegments = (text: string): InlineSegment[] =>
  text
    .split(/(\*\*[^*]+\*\*)/g)
    .filter(Boolean)
    .map((part) =>
      part.startsWith('**') && part.endsWith('**') && part.length > 4
        ? { text: part.slice(2, -2), bold: true }
        : { text: part, bold: false }
    );

/** Títulos de seção (##) para o sumário. */
export const tableOfContents = (blocks: MarkdownBlock[]): { id: string; text: string }[] =>
  blocks.filter((b): b is Extract<MarkdownBlock, { kind: 'h2' }> => b.kind === 'h2').map(({ id, text }) => ({ id, text }));
