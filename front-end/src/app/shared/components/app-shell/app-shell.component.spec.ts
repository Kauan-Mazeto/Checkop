import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { AppShellComponent } from './app-shell.component';

const terms = (over: Record<string, unknown> = {}) => ({
  currentVersion: '2.2',
  lastUpdated: '2026-11-22',
  acceptedVersion: '2.1',
  acceptedAt: '2026-11-17T10:00:00Z',
  updateRequired: true,
  ...over,
});

describe('app-shell: novo aceite dos Termos', () => {
  let http: HttpTestingController;

  const create = (termsStatus: Record<string, unknown>, url = '/dashboard') => {
    localStorage.setItem('checkop_user', JSON.stringify({ id: 'u', name: 'Ana', email: 'a@a.com', role: 'DEV', terms: termsStatus }));
    spyOnProperty(TestBed.inject(Router), 'url', 'get').and.returnValue(url);
    const fixture = TestBed.createComponent(AppShellComponent);
    fixture.detectChanges();
    return fixture;
  };
  const el = (fixture: { nativeElement: HTMLElement }) => fixture.nativeElement;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AppShellComponent],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    http.verify();
    localStorage.clear();
  });

  it('termos em dia: nenhuma janela nem aviso', () => {
    const fixture = create(terms({ acceptedVersion: '2.2', updateRequired: false }));
    expect(el(fixture).querySelector('.terms-gate')).toBeNull();
    expect(el(fixture).querySelector('.terms-banner')).toBeNull();
  });

  it('versão nova: a janela cobre a tela, mostra as versões e só aceita com a caixa marcada', () => {
    const fixture = create(terms());
    const gate = el(fixture).querySelector('.terms-gate')!;
    expect(gate).not.toBeNull();
    expect(gate.textContent).toContain('2.2');
    expect(gate.textContent).toContain('versão 2.1');
    const accept = Array.from(gate.querySelectorAll('button')).find((b) => b.textContent!.includes('Aceitar'))!;
    expect(accept.disabled).toBeTrue();
  });

  it('aceitar envia o aceite e fecha a janela', () => {
    const fixture = create(terms());
    (el(fixture).querySelector('.terms-gate input[type=checkbox]') as HTMLInputElement).click();
    fixture.detectChanges();
    const accept = Array.from(el(fixture).querySelectorAll('.terms-gate button')).find((b) => b.textContent!.includes('Aceitar')) as HTMLButtonElement;
    accept.click();

    const req = http.expectOne('/api/auth/terms/accept');
    expect(req.request.body).toEqual({ accepted: true });
    req.flush({ terms: terms({ acceptedVersion: '2.2', updateRequired: false }) });
    fixture.detectChanges();

    expect(el(fixture).querySelector('.terms-gate')).toBeNull();
    expect(JSON.parse(localStorage.getItem('checkop_user')!).terms.updateRequired).toBeFalse();
  });

  it('em Conta e privacidade vira aviso no topo (para baixar os dados ou excluir a conta)', () => {
    const fixture = create(terms(), '/account');
    expect(el(fixture).querySelector('.terms-gate')).toBeNull();
    const banner = el(fixture).querySelector('.terms-banner')!;
    expect(banner.textContent).toContain('2.2');
    (banner.querySelector('button') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el(fixture).querySelector('.terms-gate')).not.toBeNull();
  });
});
