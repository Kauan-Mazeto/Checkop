import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap, provideRouter } from '@angular/router';
import { ScanDetailPageComponent } from './scan-detail-page.component';

const OBJECTIVES = [
  { key: 'SQL_INJECTION', label: 'SQLi', description: '', owasp: 'A03:2021', coverage: 'FULL', requiresActiveScan: true, engines: [] },
  { key: 'COOKIES', label: 'Cookies', description: '', owasp: null, coverage: 'FULL', requiresActiveScan: false, engines: [] },
];

const scan = (over: Record<string, unknown> = {}) => ({
  id: 's1',
  targetUrl: 'https://meusite.com',
  objective: 'SQL_INJECTION',
  objectiveLabel: 'SQLi',
  environment: 'PRODUCTION',
  safeMode: true,
  status: 'PENDING',
  suspiciousEnvironment: false,
  resolvedIps: [],
  createdAt: '2026-11-09T10:00:00Z',
  startedAt: null,
  finishedAt: null,
  activeScanConfirmedAt: null,
  engineWarnings: [],
  summary: { badge: { emoji: '🟢', label: 'Nenhum achado', color: 'green' }, verdict: '', severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } },
  findings: [],
  ...over,
});

describe('ScanDetailPageComponent', () => {
  let http: HttpTestingController;

  const create = (scanData: Record<string, unknown>) => {
    const fixture = TestBed.createComponent(ScanDetailPageComponent);
    fixture.detectChanges();
    http.expectOne('/api/scans/objectives').flush({ objectives: OBJECTIVES });
    http.expectOne('/api/scans/s1').flush({ scan: scanData });
    fixture.detectChanges();
    return fixture;
  };

  beforeEach(() => {
    localStorage.setItem('checkop_user', JSON.stringify({ id: 'u', name: 'Ana', email: 'a@a.com', role: 'DEV' }));
    TestBed.configureTestingModule({
      imports: [ScanDetailPageComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: ActivatedRoute, useValue: { snapshot: { paramMap: convertToParamMap({ id: 's1' }) } } },
      ],
    });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    http.verify();
    localStorage.clear();
  });

  const runButton = (el: HTMLElement) =>
    Array.from(el.querySelectorAll('button')).find((b) => b.textContent?.includes('Iniciar varredura')) as HTMLButtonElement;

  it('SQLi em site público fica bloqueado até autorizar o ataque e a hospedagem', () => {
    const fixture = create(scan());
    const component = fixture.componentInstance as any;
    const el = fixture.nativeElement as HTMLElement;

    expect(runButton(el).disabled).toBeTrue();
    expect(el.textContent).toContain('Varredura ativa (ataque real)');

    component.activeScanConfirmed = true;
    fixture.detectChanges();
    expect(runButton(el).disabled).toBeTrue(); // falta a declaração de hospedagem

    component.hostingTermsConfirmed = true;
    fixture.detectChanges();
    expect(runButton(el).disabled).toBeFalse();

    runButton(el).click();
    const req = http.expectOne('/api/scans/s1/run');
    expect(req.request.body.activeScanConfirmed).toBeTrue();
    expect(req.request.body.hostingTermsConfirmed).toBeTrue();
    req.flush({ scan: { id: 's1', status: 'RUNNING', activeScan: true } });
    http.expectOne('/api/scans/s1').flush({ scan: scan({ status: 'COMPLETED' }) });
  });

  it('localhost não mostra o opt-in e não manda as declarações', () => {
    const fixture = create(scan({ environment: 'DEVELOPMENT', safeMode: false, targetUrl: 'http://localhost:3000' }));
    const el = fixture.nativeElement as HTMLElement;

    expect(el.textContent).not.toContain('Varredura ativa (ataque real)');
    runButton(el).click();
    const req = http.expectOne('/api/scans/s1/run');
    expect(req.request.body.activeScanConfirmed).toBeUndefined();
    req.flush({ scan: { id: 's1', status: 'RUNNING', activeScan: true } });
    http.expectOne('/api/scans/s1').flush({ scan: scan({ status: 'COMPLETED' }) });
  });

  it('resultado concluído mostra veredito, contagem e as abas', () => {
    const fixture = create(
      scan({
        status: 'COMPLETED',
        summary: { badge: { emoji: '🔴', label: 'Alto', color: 'red' }, verdict: 'Correção prioritária recomendada.', severityCounts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 } },
        findings: [
          { id: 'f1', title: 'SQL Injection', severity: 'HIGH', status: 'OPEN', tool: 'ZAP', affectedUrl: 'https://meusite.com/busca', cveId: null, cvssScore: 8.5, owaspUrl: 'A03:2021 – Injection', remediation: 'Use queries parametrizadas.', compliance: [{ law: 'LGPD', reference: 'Art. 46', message: 'm' }], createdAt: '' },
        ],
        engineWarnings: ['Regras do ZAP indisponíveis nesta instalação: 90018.'],
      })
    );
    const el = fixture.nativeElement as HTMLElement;

    expect(el.textContent).toContain('Correção prioritária recomendada.');
    expect(el.textContent).toContain('Achados (1)');
    expect(el.textContent).toContain('Compliance');
    expect(el.textContent).toContain('90018');
    expect(el.textContent).toContain('Modo Seguro');
  });

  it('plano Free mostra o paywall e esconde a aba de PoC; Premium não', () => {
    const free = create(scan({ status: 'COMPLETED', plan: 'FREE', environment: 'DEVELOPMENT', safeMode: false }));
    expect((free.nativeElement as HTMLElement).textContent).toContain('Recurso Premium bloqueado');
    free.destroy();

    const premium = create(scan({ status: 'COMPLETED', plan: 'PREMIUM', environment: 'DEVELOPMENT', safeMode: false }));
    expect((premium.nativeElement as HTMLElement).textContent).not.toContain('Recurso Premium bloqueado');
  });

  it('em execução, consulta o status de novo sozinho', () => {
    jasmine.clock().install();
    try {
      const fixture = create(scan({ status: 'RUNNING', startedAt: new Date().toISOString() }));
      expect((fixture.nativeElement as HTMLElement).textContent).toContain('Varredura em andamento');

      jasmine.clock().tick(5000);
      http.expectOne('/api/scans/s1').flush({ scan: scan({ status: 'COMPLETED' }) });
      fixture.destroy();
    } finally {
      jasmine.clock().uninstall();
    }
  });
});
