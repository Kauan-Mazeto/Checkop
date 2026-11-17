import { formatIp } from './labels';
import { inlineSegments, parseSimpleMarkdown, slugify, tableOfContents } from './markdown';

describe('IP nos acessos recentes', () => {
  it('localhost aparece legível e IPv4 sem o prefixo IPv6', () => {
    expect(formatIp('::1')).toBe('Este computador (local)');
    expect(formatIp('::ffff:127.0.0.1')).toBe('Este computador (local)');
    expect(formatIp('::ffff:203.0.113.7')).toBe('203.0.113.7');
    expect(formatIp('2001:db8::1')).toBe('2001:db8::1');
    expect(formatIp(null)).toBe('—');
  });
});

describe('markdown dos documentos legais', () => {
  it('converte títulos, subtítulos, destaque, parágrafos e listas', () => {
    const blocks = parseSimpleMarkdown('# Título\n\n> Resumo\n## 1. Dados\n### 1.1. Cadastro\n- nome\n- e-mail\nTexto final.');
    expect(blocks).toEqual([
      { kind: 'h1', text: 'Título' },
      { kind: 'quote', text: 'Resumo' },
      { kind: 'h2', text: '1. Dados', id: '1-dados' },
      { kind: 'h3', text: '1.1. Cadastro' },
      { kind: 'ul', items: ['nome', 'e-mail'] },
      { kind: 'p', text: 'Texto final.' },
    ]);
  });

  it('âncora do sumário sem acentos nem símbolos', () => {
    expect(slugify('3. Planos e cobrança')).toBe('3-planos-e-cobranca');
    expect(slugify('9. Seus direitos (LGPD)')).toBe('9-seus-direitos-lgpd');
  });

  it('sumário lista só as seções (##)', () => {
    const toc = tableOfContents(parseSimpleMarkdown('# T\n## 1. A\n### 1.1 x\n## 2. B'));
    expect(toc).toEqual([
      { id: '1-a', text: '1. A' },
      { id: '2-b', text: '2. B' },
    ]);
  });

  it('negrito vira trecho marcado; HTML continua texto puro', () => {
    expect(inlineSegments('Use **só** alvos seus')).toEqual([
      { text: 'Use ', bold: false },
      { text: 'só', bold: true },
      { text: ' alvos seus', bold: false },
    ]);
    expect(inlineSegments('<script>x</script>')).toEqual([{ text: '<script>x</script>', bold: false }]);
  });
});
