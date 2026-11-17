import { languageOf } from './code-analysis-page.component';
import { codeWindow, sideBySideDiff } from './code-view';

describe('correção com IA: diff lado a lado', () => {
  it('linhas iguais ficam pareadas; a trocada aparece removida à esquerda e adicionada à direita', () => {
    const before = 'const id = req.query.id;\nconst q = `SELECT * WHERE id = ${id}`;\ndb.query(q);';
    const after = 'const id = req.query.id;\ndb.query("SELECT * WHERE id = ?", [id]);';
    const rows = sideBySideDiff(before, after, 10);

    expect(rows[0]).toEqual({
      left: { number: 10, text: 'const id = req.query.id;', changed: false },
      right: { number: 10, text: 'const id = req.query.id;', changed: false },
    });
    const removed = rows.filter((r) => r.left?.changed).map((r) => r.left!.number);
    const added = rows.filter((r) => r.right?.changed).map((r) => r.right!.text);
    expect(removed).toEqual([11, 12]);
    expect(added).toEqual(['db.query("SELECT * WHERE id = ?", [id]);']);
    // linha só de um lado deixa o outro vazio, sem desalinhar
    expect(rows.some((r) => r.left && !r.right)).toBeTrue();
  });

  it('sem mudança, nada fica marcado', () => {
    expect(sideBySideDiff('a\nb', 'a\nb').every((r) => !r.left!.changed && !r.right!.changed)).toBeTrue();
  });

  it('janela leva só as linhas em volta do achado', () => {
    const file = Array.from({ length: 50 }, (_, i) => `linha ${i + 1}`).join('\n');
    const w = codeWindow(file, 20, 21, 3);
    expect(w.firstLine).toBe(17);
    expect(w.code.split('\n')).toEqual(['linha 17', 'linha 18', 'linha 19', 'linha 20', 'linha 21', 'linha 22', 'linha 23', 'linha 24']);
    expect(codeWindow(file, 2, 2, 8).firstLine).toBe(1); // não passa do começo
  });

  it('linguagem pela extensão', () => {
    expect(languageOf('src/app.py')).toBe('Python');
    expect(languageOf('index.TS')).toBe('TypeScript');
    expect(languageOf('Makefile')).toBe('makefile');
  });
});
