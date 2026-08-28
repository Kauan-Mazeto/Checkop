import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, tap, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';

// Espelha o campo "role" do enum Role no backend (backend/src/constants/enums.js).
export type UserRole = 'DEV' | 'QA' | 'PENTESTER' | 'STUDENT' | 'ADM';

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: UserRole;
}

// Espelha o corpo de resposta de POST /api/auth/login
// (backend/src/controllers/auth_controllers.js -> login).
interface LoginResponse {
  message: string;
  token: string;
  user: AuthUser;
}

// Espelha o corpo de resposta de POST /api/auth/register
// (backend/src/controllers/auth_controllers.js -> register).
interface RegisterResponse {
  message: string;
  token: string;
  user: AuthUser;
}

export interface RegisterPayload {
  name: string;
  email: string;
  password: string;
  role: Exclude<UserRole, 'ADM'>;
}

// Espelha os formatos de erro do backend:
// - erro de validação (Zod, via middlewares/auth_validate.js): { error, formattedErrors? }
// - erro de negócio/infra (controllers, error handler global): { error }
interface ApiErrorBody {
  error?: string;
  formattedErrors?: { field: string; message: string }[];
}

const TOKEN_STORAGE_KEY = 'checkop_token';
const USER_STORAGE_KEY = 'checkop_user';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);

  /**
   * Autentica via e-mail/senha contra POST /api/auth/login.
   * Em caso de sucesso, persiste token e usuário localmente.
   * Em caso de erro, propaga uma mensagem já pronta para exibição
   * (extraída do corpo de erro padronizado do backend).
   */
  login(email: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${API_BASE_URL}/auth/login`, { email, password }).pipe(
      tap((response) => this.persistSession(response)),
      catchError((error: HttpErrorResponse) => throwError(() => this.toErrorMessage(error)))
    );
  }

  /**
   * Cadastra uma nova conta contra POST /api/auth/register.
   * O backend já devolve token + usuário no cadastro (auto-login), então o
   * comportamento espelha login(): persiste a sessão e propaga uma mensagem
   * de erro pronta pra exibição (409 e-mail já cadastrado, 400 validação, etc).
   */
  register(payload: RegisterPayload): Observable<RegisterResponse> {
    return this.http.post<RegisterResponse>(`${API_BASE_URL}/auth/register`, payload).pipe(
      tap((response) => this.persistSession(response)),
      catchError((error: HttpErrorResponse) => throwError(() => this.toErrorMessage(error)))
    );
  }

  logout(): void {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    localStorage.removeItem(USER_STORAGE_KEY);
  }

  getToken(): string | null {
    return localStorage.getItem(TOKEN_STORAGE_KEY);
  }

  getUser(): AuthUser | null {
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

  isAuthenticated(): boolean {
    return !!this.getToken();
  }

  private persistSession(response: LoginResponse): void {
    localStorage.setItem(TOKEN_STORAGE_KEY, response.token);
    localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(response.user));
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