import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { AuthService } from './auth.service';

// Contrato atual: a sessão é um cookie httpOnly setado pelo backend
// (auth_controllers.js). O corpo não traz token, e o front só guarda o usuário
// em cache para a UI. Por isso nenhum token pode ir para o localStorage.
describe('AuthService', () => {
  let service: AuthService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
    });

    service = TestBed.inject(AuthService);
    httpMock = TestBed.inject(HttpTestingController);
    localStorage.clear();
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('cadastra com cookie de sessão e guarda só o usuário em cache (nenhum token no localStorage)', () => {
    const payload = {
      name: 'Ana Souza',
      email: 'ana@teste.com',
      password: '12345678',
      role: 'DEV' as const,
      termsAccepted: true as const,
    };

    service.register(payload).subscribe((user) => {
      expect(user.email).toBe(payload.email);
    });

    const request = httpMock.expectOne('/api/auth/register');
    expect(request.request.method).toBe('POST');
    expect(request.request.withCredentials).toBeTrue();
    expect(request.request.body).toEqual(payload);

    request.flush({
      message: 'Usuário cadastrado com sucesso!',
      user: {
        id: 'user-1',
        name: 'Ana Souza',
        email: 'ana@teste.com',
        role: 'DEV',
      },
    });

    expect(localStorage.getItem('checkop_token')).toBeNull();
    expect(JSON.parse(localStorage.getItem('checkop_user') ?? '{}')).toEqual({
      id: 'user-1',
      name: 'Ana Souza',
      email: 'ana@teste.com',
      role: 'DEV',
    });
  });
});
