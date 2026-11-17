import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { ApiError } from '../../../core/http/api-error';
import { AuthService } from '../../../core/services/auth.service';
import { GoogleAuthService } from '../../../core/services/google-auth.service';
import { GoogleSignInComponent, readGoogleIdentity } from './google-sign-in.component';

// id_token falso só com o payload (a assinatura quem confere é o backend)
const fakeToken = (payload: object) =>
  `x.${btoa(unescape(encodeURIComponent(JSON.stringify(payload)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}.y`;

describe('login com Google', () => {
  it('lê nome e e-mail do id_token para mostrar na tela (com acentos)', () => {
    expect(readGoogleIdentity(fakeToken({ name: 'João Ação', email: 'joao@x.com' }))).toEqual({ name: 'João Ação', email: 'joao@x.com' });
    expect(readGoogleIdentity('lixo')).toEqual({ name: null, email: null });
  });

  describe('componente', () => {
    let credentialCallback: (credential: string) => void;
    let googleLogin: jasmine.Spy;

    const setup = async (enabled: boolean) => {
      googleLogin = jasmine.createSpy('googleLogin');
      await TestBed.configureTestingModule({
        imports: [GoogleSignInComponent],
        providers: [
          provideRouter([]),
          { provide: AuthService, useValue: { googleLogin } },
          {
            provide: GoogleAuthService,
            useValue: {
              getConfig: async () => ({ enabled, clientId: enabled ? 'client-id' : null }),
              renderButton: async (_el: HTMLElement, _id: string, cb: (c: string) => void) => (credentialCallback = cb),
            },
          },
        ],
      }).compileComponents();
      const fixture = TestBed.createComponent(GoogleSignInComponent);
      const events = { available: [] as boolean[], signedIn: 0 };
      fixture.componentInstance.available.subscribe((v) => events.available.push(v));
      fixture.componentInstance.signedIn.subscribe(() => events.signedIn++);
      fixture.detectChanges();
      await fixture.whenStable();
      return { fixture, events, text: () => (fixture.nativeElement as HTMLElement).textContent ?? '' };
    };

    it('sem GOOGLE_CLIENT_ID no servidor o botão não aparece', async () => {
      const { events } = await setup(false);
      expect(events.available).toEqual([false]);
    });

    it('conta que já aceitou os termos entra direto', async () => {
      const { events } = await setup(true);
      googleLogin.and.returnValue(of({ id: 'u1' }));
      credentialCallback('tok');
      expect(googleLogin).toHaveBeenCalledWith('tok', {});
      expect(events.signedIn).toBe(1);
    });

    it('primeiro acesso: pede aceite e perfil e reenvia o mesmo token', async () => {
      const { fixture, events, text } = await setup(true);
      googleLogin.and.returnValue(throwError(() => new ApiError('aceite', 400, 'TERMS_REQUIRED')));
      const token = fakeToken({ name: 'Ana', email: 'ana@x.com' });
      credentialCallback(token);
      fixture.detectChanges();
      expect(text()).toContain('Primeiro acesso com Google');
      expect(text()).toContain('ana@x.com');
      expect(events.signedIn).toBe(0);

      const concluir = () =>
        [...(fixture.nativeElement as HTMLElement).querySelectorAll('button')].find((b) => b.textContent?.includes('Concluir'))!;
      expect(concluir().disabled).toBeTrue(); // sem aceite não continua

      const component = fixture.componentInstance as unknown as { termsAccepted: boolean; role: string };
      component.termsAccepted = true;
      component.role = 'PENTESTER';
      fixture.detectChanges();
      googleLogin.and.returnValue(of({ id: 'u1' }));
      concluir().click();

      expect(googleLogin).toHaveBeenCalledWith(token, { termsAccepted: true, role: 'PENTESTER' });
      expect(events.signedIn).toBe(1);
    });
  });
});
