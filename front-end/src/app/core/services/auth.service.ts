import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, map, tap, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';

// Espelha o campo "role" do enum Role no backend (backend/src/constants/enums.js).
export type UserRole = 'DEV' | 'QA' | 'PENTESTER' | 'STUDENT' | 'ADM';

export interface AuthUser {
  user: any;
  id: string;
  name: string;
  email: string;
  role: UserRole;
}

// Espelha o corpo de resposta de POST /api/auth/login e /api/auth/register
// (backend/src/controllers/auth_controllers.js). IMPORTANTE: o backend não
// devolve mais um token no corpo da resposta — ele seta um cookie httpOnly
// (res.cookie('token', ...) em auth_controllers.js) e o auth_middleware.js lê
// esse cookie (req.cookies?.token), não mais um header Authorization. Por
// isso toda chamada aqui precisa ir com { withCredentials: true }: é o que
// faz o navegador guardar/enviar esse cookie em requisições cross-origin
// (front em :4200, backend em :3000/:8080).
interface AuthResponse {
  message: string;
  user: AuthUser;
}

export interface RegisterPayload {
  name: string;
  email: string;
  password: string;
  role: Exclude<UserRole, 'ADM'>;
  // Obrigatório no backend: registerSchema exige termsAccepted === true
  // (backend/src/validators/auth_validator.js), e o cadastro cria um
  // registro de TermsAcceptance vinculado ao usuário.
  termsAccepted: true;
}

// Espelha o corpo de resposta de GET /api/auth/me
interface MeResponse {
  message: string;
  userId: string;
  role: UserRole;
  email: string;
}

// Espelha os formatos de erro do backend:
interface ApiErrorBody {
  error?: string;
  formattedErrors?: { field: string; message: string }[];
}

const USER_STORAGE_KEY = 'checkop_user';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);

  /**
   * Autentica via e-mail/senha contra POST /api/auth/login.
   * O backend seta o cookie de sessão na própria resposta;
   * withCredentials garante que o navegador aceite ele e passe a mandá-lo
   * nas próximas chamadas. Em caso de sucesso, cacheia o usuário localmente
   * só pra uso imediato de UI (nome/e-mail/role), quem decide se a sessão
   * é válida de verdade é sempre o backend, via cookie.
   */
  login(email: string, password: string): Observable<AuthUser> {
    return this.http
      .post<AuthResponse>(
        `${API_BASE_URL}/auth/login`,
        { email, password },
        { withCredentials: true }
      )
      .pipe(
        tap((response) => this.cacheUser(response.user)),
        map((response) => response.user),
        catchError((error: HttpErrorResponse) => throwError(() => this.toErrorMessage(error)))
      );
  }

  /**
   * Cadastra uma nova conta contra POST /api/auth/register. Mesmo modelo do
   * login: cookie httpOnly setado pelo backend, sem token no corpo.
   */
  register(payload: RegisterPayload): Observable<AuthUser> {
    return this.http
      .post<AuthResponse>(`${API_BASE_URL}/auth/register`, payload, { withCredentials: true })
      .pipe(
        tap((response) => this.cacheUser(response.user)),
        map((response) => response.user),
        catchError((error: HttpErrorResponse) => throwError(() => this.toErrorMessage(error)))
      );
  }

  /**
   * Consulta GET /api/auth/me para confirmar (com o backend, não com o
   * cache local) se o cookie de sessão ainda é válido. Útil ao recarregar a
   * página, já que localStorage sozinho não prova nada sobre a sessão.
   */
  me(): Observable<MeResponse> {
    return this.http
      .get<MeResponse>(`${API_BASE_URL}/auth/me`, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => this.toErrorMessage(error))));
  }

  logout(): Observable<{ message: string }> {
    return this.http
      .post<{ message: string }>(`${API_BASE_URL}/auth/logout`, {}, { withCredentials: true })
      .pipe(
        tap(() => this.clearCachedUser()),
        catchError((error: HttpErrorResponse) => {
          // mesmo se a chamada falhar (ex: cookie já expirado), limpa o
          // cache local, não faz sentido manter um usuário "logado" na UI
          // se o servidor não reconhece mais a sessão.
          this.clearCachedUser();
          return throwError(() => this.toErrorMessage(error));
        })
      );
  }

  // Usuário em cache (só pra UI). Fonte de verdade é me().
  getCachedUser(): AuthUser | null {
    const raw = localStorage.getItem(USER_STORAGE_KEY);

    if (!raw) {
      return null;
    }

    try {
      return JSON.parse(raw) as AuthUser;
    } catch {
      return null;
    }
  }

  private cacheUser(user: AuthUser): void {
    localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
  }

  private clearCachedUser(): void {
    localStorage.removeItem(USER_STORAGE_KEY);
  }

  private toErrorMessage(error: HttpErrorResponse): string {
    const body = error.error as ApiErrorBody | null;

    if (body?.formattedErrors?.length) {
      return body.formattedErrors.map((issue) => issue.message).join(' ');
    }

    if (body?.error) {
      return body.error;
    }

    if (error.status === 0) {
      return 'Não foi possível conectar ao servidor. Verifique sua conexão.';
    }

    return 'Erro inesperado. Tente novamente.';
  }
}