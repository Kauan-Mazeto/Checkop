import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, map, tap, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';
import { toApiError } from '../http/api-error';
import { AuthService, AuthUser, UserPlan } from './auth.service';

export interface LoginAttempt {
  success: boolean;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
}

export interface PrivacyPolicy {
  lastUpdated: string;
  content: string;
}

export interface TermsOfUse extends PrivacyPolicy {
  version: string;
}

const withCredentials = { withCredentials: true };

// Espelha backend/src/routes/auth_routes.js e privacy_routes.js.
@Injectable({ providedIn: 'root' })
export class AccountService {
  private readonly http = inject(HttpClient);
  private readonly auth = inject(AuthService);

  loginHistory(): Observable<LoginAttempt[]> {
    return this.http
      .get<{ attempts: LoginAttempt[] }>(`${API_BASE_URL}/auth/login-history`, withCredentials)
      .pipe(map((r) => r.attempts), catchError(this.fail));
  }

  privacyPolicy(): Observable<PrivacyPolicy> {
    return this.http.get<PrivacyPolicy>(`${API_BASE_URL}/privacy/privacy-policy`).pipe(catchError(this.fail));
  }

  termsOfUse(): Observable<TermsOfUse> {
    return this.http.get<TermsOfUse>(`${API_BASE_URL}/privacy/terms-of-use`).pipe(catchError(this.fail));
  }

  /** Troca demonstrativa de plano (sem cobrança). Atualiza o cache local. */
  changePlan(plan: UserPlan): Observable<AuthUser> {
    return this.http
      .patch<{ user: AuthUser }>(`${API_BASE_URL}/auth/plan`, { plan }, withCredentials)
      .pipe(
        map((r) => r.user),
        tap((user) => this.auth.updateCachedUser({ plan: user.plan })),
        catchError(this.fail)
      );
  }

  /** LGPD: conta com senha confirma com a senha; conta Google, com a frase. */
  deleteAccount(body: { password?: string; confirmation?: string }): Observable<void> {
    return this.http
      .delete<unknown>(`${API_BASE_URL}/auth/account`, { ...withCredentials, body })
      .pipe(
        map(() => undefined),
        tap(() => localStorage.removeItem('checkop_user')),
        catchError(this.fail)
      );
  }

  private readonly fail = (error: HttpErrorResponse) => throwError(() => toApiError(error));
}
