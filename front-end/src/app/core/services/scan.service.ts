import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, map, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';

// Espelha os enums TargetEnvironment/ScanStatus do backend
// (backend/prisma/schema.prisma).
export type ScanEnvironment = 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION';
export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';

// Espelha o "select" de GET /api/scans (backend/src/controllers/scan_controllers.js),
//  incluindo a des-serialização de resolvedIps (feita no próprio controller).
export interface Scan {
  id: string;
  targetUrl: string;
  environment: ScanEnvironment;
  safeMode: boolean;
  status: ScanStatus;
  suspiciousEnvironment: boolean;
  resolvedIps: string[];
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

interface ListScansResponse {
  scans: Scan[];
}

interface ApiErrorBody {
  error?: string;
  formattedErrors?: { field: string; message: string }[];
}

@Injectable({ providedIn: 'root' })
export class ScanService {
  private readonly http = inject(HttpClient);

  /**
   * GET /api/scans, protegido por authMiddleware (cookie httpOnly), por
   * isso withCredentials aqui também. Lista só os scans do usuário logado.
   */
  listScans(): Observable<Scan[]> {
    return this.http
      .get<ListScansResponse>(`${API_BASE_URL}/scans`, { withCredentials: true })
      .pipe(
        map((response) => response.scans),
        catchError((error: HttpErrorResponse) => throwError(() => this.toErrorMessage(error)))
      );
  }

  /**
   * POST /api/scans — espelha createScanSchema: exige targetUrl válida e
   * authorizationConfirmed === true (checkbox de "tenho autorização para
   * testar este alvo", obrigatório por lei/ética, não é só forma).
   */
  createScan(targetUrl: string): Observable<Scan> {
    return this.http
      .post<{ message: string; scan: Scan }>(
        `${API_BASE_URL}/scans`,
        { targetUrl, authorizationConfirmed: true },
        { withCredentials: true }
      )
      .pipe(
        map((response) => response.scan),
        catchError((error: HttpErrorResponse) => throwError(() => this.toErrorMessage(error)))
      );
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