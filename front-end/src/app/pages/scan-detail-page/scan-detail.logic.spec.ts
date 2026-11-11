import { Finding } from '../../core/services/scan.service';
import { groupObjectives } from '../new-scan-page/new-scan-page.component';
import { buildCodeView, isAcceptedFile } from '../code-analysis-page/code-view';
import { parseSastLocation } from '../../core/services/sast.service';
import { elapsed, exportFileName, filterBySeverity, groupCompliance, hasEvidence, sortBySeverity } from './scan-detail.logic';

const finding = (over: Partial<Finding>): Finding => ({
  id: over.id ?? Math.random().toString(36),
  title: 'Achado',
  severity: 'LOW',
  status: 'OPEN',
  tool: 'ZAP',
  affectedUrl: null,
  cveId: null,
  cvssScore: null,
  owaspUrl: null,
  remediation: null,
  compliance: [],
  createdAt: '',
  ...over,
});

describe('detalhe da varredura: lógica', () => {
  it('ordena por severidade e, empatando, pelo CVSS', () => {
    const sorted = sortBySeverity([
      finding({ title: 'baixo', severity: 'LOW' }),
      finding({ title: 'alto 7', severity: 'HIGH', cvssScore: 7 }),
      finding({ title: 'crítico', severity: 'CRITICAL' }),
      finding({ title: 'alto 9', severity: 'HIGH', cvssScore: 9 }),
    ]);
    expect(sorted.map((f) => f.title)).toEqual(['crítico', 'alto 9', 'alto 7', 'baixo']);
  });

  it('filtra por severidade', () => {
    const list = [finding({ severity: 'HIGH' }), finding({ severity: 'LOW' })];
    expect(filterBySeverity(list, 'ALL').length).toBe(2);
    expect(filterBySeverity(list, 'HIGH').length).toBe(1);
  });

  it('evidência só existe com requisição ou resposta (em Modo Seguro o backend não as manda)', () => {
    expect(hasEvidence(finding({}))).toBeFalse();
    expect(hasEvidence(finding({ rawRequest: 'GET /?id=1' }))).toBeTrue();
  });

  it('agrupa compliance por lei + artigo, sem repetir achado', () => {
    const lgpd = { law: 'LGPD', reference: 'Art. 46', message: 'm' };
    const pci = { law: 'PCI-DSS v4.0', reference: 'Requisito 6.2.4', message: 'p' };
    const a = finding({ id: 'a', compliance: [lgpd, pci] });
    const b = finding({ id: 'b', compliance: [lgpd] });

    const groups = groupCompliance([a, b]);

    expect(groups.map((g) => `${g.law}|${g.findings.length}`)).toEqual(['LGPD|2', 'PCI-DSS v4.0|1']);
  });

  it('nome do arquivo exportado usa o host e a data', () => {
    expect(exportFileName('https://www.meusite.com/x', new Date('2026-11-09T10:00:00Z'))).toBe('checkop-www.meusite.com-2026-11-09.json');
    expect(exportFileName('inválida', new Date('2026-11-09T10:00:00Z'))).toBe('checkop-alvo-2026-11-09.json');
  });

  it('tempo decorrido em mm:ss', () => {
    const start = '2026-11-09T10:00:00Z';
    expect(elapsed(start, new Date('2026-11-09T10:02:05Z').getTime())).toBe('02:05');
    expect(elapsed(null)).toBe('00:00');
  });
});

describe('nova varredura: agrupamento dos objetivos', () => {
  it('agrupa na ordem definida, esconde categorias vazias e manda desconhecidos para "Outros"', () => {
    const base = { description: '', owasp: null, coverage: 'FULL' as const, requiresActiveScan: false, engines: [] };
    const groups = groupObjectives([
      { ...base, key: 'FULL_SCAN', label: 'Completa' },
      { ...base, key: 'SQL_INJECTION', label: 'SQLi' },
      { ...base, key: 'NOVO', label: 'Novo' },
      { ...base, key: 'COOKIES', label: 'Cookies' },
    ]);
    expect(groups.map((g) => g.title)).toEqual(['Injeções', 'Configuração', 'Varredura completa', 'Outros']);
    expect(groups[0].objectives.map((o) => o.key)).toEqual(['SQL_INJECTION']);
  });
});

describe('análise de código: visualizador', () => {
  it('lê a localização "arquivo:linha" e "arquivo:inicio-fim"', () => {
    expect(parseSastLocation('src/app.js:12')).toEqual({ file: 'src/app.js', start: 12, end: 12 });
    expect(parseSastLocation('a.py:3-5')).toEqual({ file: 'a.py', start: 3, end: 5 });
    expect(parseSastLocation('sem-linha')).toBeNull();
  });

  it('recorta o arquivo em volta da linha vulnerável e a destaca', () => {
    const content = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6'].join('\n');
    const view = buildCodeView(content, 3, 3, 1);
    expect(view.map((l) => l.number)).toEqual([2, 3, 4]);
    expect(view.filter((l) => l.vulnerable).map((l) => l.text)).toEqual(['l3']);
  });

  it('não passa do início nem do fim do arquivo', () => {
    const view = buildCodeView('a\nb', 1, 2, 5);
    expect(view.map((l) => l.number)).toEqual([1, 2]);
  });

  it('aceita só extensões de código', () => {
    expect(isAcceptedFile('app.TS')).toBeTrue();
    expect(isAcceptedFile('foto.png')).toBeFalse();
  });
});
