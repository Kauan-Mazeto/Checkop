import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ApiError } from '../http/api-error';
import { ScanService } from './scan.service';
import { TargetService } from './target.service';

describe('ScanService / TargetService', () => {
  let scans: ScanService;
  let targets: TargetService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    scans = TestBed.inject(ScanService);
    targets = TestBed.inject(TargetService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('createScan envia objetivo e autorização, com cookie de sessão', () => {
    scans.createScan('https://meusite.com', 'SQL_INJECTION').subscribe();

    const req = http.expectOne('/api/scans');
    expect(req.request.method).toBe('POST');
    expect(req.request.withCredentials).toBeTrue();
    expect(req.request.body).toEqual({ targetUrl: 'https://meusite.com', objective: 'SQL_INJECTION', authorizationConfirmed: true });
    req.flush({ scan: { id: 's1' } });
  });

  it('erro do backend vira ApiError com o code (ex.: TARGET_NOT_VERIFIED)', () => {
    let error: ApiError | undefined;
    scans.createScan('https://site.com', 'XSS').subscribe({ error: (e: ApiError) => (error = e) });

    http.expectOne('/api/scans').flush(
      { error: 'Verifique o domínio.', code: 'TARGET_NOT_VERIFIED' },
      { status: 403, statusText: 'Forbidden' }
    );

    expect(error).toEqual(jasmine.any(ApiError));
    expect(error?.status).toBe(403);
    expect(error?.code).toBe('TARGET_NOT_VERIFIED');
    expect(error?.message).toBe('Verifique o domínio.');
  });

  it('runScan manda as declarações do opt-in', () => {
    scans.runScan('s1', { activeScanConfirmed: true, hostingTermsConfirmed: true, useAjaxSpider: false }).subscribe();

    const req = http.expectOne('/api/scans/s1/run');
    expect(req.request.body).toEqual({ activeScanConfirmed: true, hostingTermsConfirmed: true, useAjaxSpider: false });
    req.flush({ scan: { id: 's1', status: 'RUNNING', activeScan: true } });
  });

  it('getScan codifica o id na URL', () => {
    scans.getScan('a/b').subscribe();
    http.expectOne('/api/scans/a%2Fb').flush({ scan: {} });
  });

  it('erro de validação junta as mensagens dos campos', () => {
    let error: ApiError | undefined;
    targets.createTarget('x', 'DNS_TXT').subscribe({ error: (e: ApiError) => (error = e) });
    http.expectOne('/api/targets').flush(
      { error: 'Dados inválidos.', formattedErrors: [{ field: 'url', message: 'URL inválida.' }] },
      { status: 400, statusText: 'Bad Request' }
    );
    expect(error?.message).toBe('URL inválida.');
  });

  it('verifyTarget faz POST em /targets/:id/verify', () => {
    targets.verifyTarget('t1').subscribe();
    const req = http.expectOne('/api/targets/t1/verify');
    expect(req.request.method).toBe('POST');
    req.flush({ target: { id: 't1', verified: true } });
  });

  it('sem conexão, mensagem amigável', () => {
    let error: ApiError | undefined;
    targets.listTargets().subscribe({ error: (e: ApiError) => (error = e) });
    http.expectOne('/api/targets').error(new ProgressEvent('error'), { status: 0 });
    expect(error?.message).toContain('Não foi possível conectar');
  });
});
