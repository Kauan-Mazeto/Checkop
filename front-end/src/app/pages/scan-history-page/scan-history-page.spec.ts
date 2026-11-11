import { Scan } from '../../core/services/scan.service';
import { filterScans } from './scan-history-page.component';
import { parsePolicy } from '../account-page/account-page.component';
import { NAV_GROUPS } from '../../shared/components/app-shell/app-shell.component';
import { DraftService } from '../../core/services/draft.service';

const scan = (over: Partial<Scan>): Scan => ({
  id: 'x', targetUrl: 'http://localhost:3000', objective: 'SQL_INJECTION', objectiveLabel: 'Injeção de SQL (SQLi)',
  environment: 'DEVELOPMENT', safeMode: false, status: 'COMPLETED', suspiciousEnvironment: false, resolvedIps: [],
  findingsCount: 0, createdAt: '', startedAt: null, finishedAt: null, ...over,
});

describe('histórico: filtros', () => {
  const list = [
    scan({ id: 'a', targetUrl: 'https://meusite.com', environment: 'PRODUCTION', objective: 'COOKIES', objectiveLabel: 'Cookies inseguros' }),
    scan({ id: 'b', status: 'FAILED' }),
    scan({ id: 'c' }),
  ];
  const none = { search: '', status: '' as const, environment: '' as const, objective: '' };

  it('sem filtro mostra tudo', () => expect(filterScans(list, none).length).toBe(3));
  it('busca por URL ou tipo de falha, sem diferenciar maiúsculas', () => {
    expect(filterScans(list, { ...none, search: 'MEUSITE' }).map((s) => s.id)).toEqual(['a']);
    expect(filterScans(list, { ...none, search: 'cookies' }).map((s) => s.id)).toEqual(['a']);
  });
  it('combina status e ambiente', () => {
    expect(filterScans(list, { ...none, status: 'FAILED' }).map((s) => s.id)).toEqual(['b']);
    expect(filterScans(list, { ...none, environment: 'DEVELOPMENT', status: 'COMPLETED' }).map((s) => s.id)).toEqual(['c']);
  });
});

describe('conta: política de privacidade', () => {
  it('converte títulos, parágrafos e listas', () => {
    const blocks = parsePolicy('# Título\n\n## 1. Dados\n- nome\n- e-mail\nTexto final.');
    expect(blocks).toEqual([
      { kind: 'h1', text: 'Título' },
      { kind: 'h2', text: '1. Dados' },
      { kind: 'ul', items: ['nome', 'e-mail'] },
      { kind: 'p', text: 'Texto final.' },
    ]);
  });
});

describe('menu lateral: item ativo', () => {
  const item = (label: string) => NAV_GROUPS.flatMap((g) => g.items).find((i) => i.label === label)!;
  it('nova varredura e histórico não acendem juntos', () => {
    expect(item('Nova varredura').match('/scans/new')).toBeTrue();
    expect(item('Histórico').match('/scans/new')).toBeFalse();
    expect(item('Histórico').match('/scans')).toBeTrue();
    expect(item('Histórico').match('/scans/abc-123')).toBeTrue();
  });
});

describe('rascunhos de formulário', () => {
  afterEach(() => sessionStorage.clear());

  it('guarda e recupera o rascunho, e limpa depois de enviar', () => {
    const drafts = new DraftService();
    drafts.save('teste', { email: 'ana@x.com' });
    expect(drafts.load<{ email: string }>('teste').email).toBe('ana@x.com');
    drafts.clear('teste');
    expect(drafts.load('teste')).toEqual({});
  });

  it('JSON corrompido no storage não quebra a tela', () => {
    sessionStorage.setItem('checkop_draft:ruim', '{nao-e-json');
    expect(new DraftService().load('ruim')).toEqual({});
  });
});
