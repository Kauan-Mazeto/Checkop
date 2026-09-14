import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { AuthService } from './auth.service';

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

  it('should persist a local session when the register endpoint returns no token', () => {
    const payload = {
      name: 'Ana Souza',
      email: 'ana@teste.com',
      password: '12345678',
      role: 'DEV' as const,
      termsAccepted: true,
    };

    service.register(payload).subscribe((response) => {
      expect(response.user.email).toBe(payload.email);
    });

    const request = httpMock.expectOne('http://localhost:8080/api/auth/register');
    expect(request.request.method).toBe('POST');
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

    expect(localStorage.getItem('checkop_token')).not.toBeNull();
    expect(localStorage.getItem('checkop_token')).not.toBe('undefined');
    expect(JSON.parse(localStorage.getItem('checkop_user') ?? '{}')).toEqual({
      id: 'user-1',
      name: 'Ana Souza',
      email: 'ana@teste.com',
      role: 'DEV',
    });
  });
});
