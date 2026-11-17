import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';
import { toApiError } from '../http/api-error';
import { FindingSeverity } from './scan.service';

// Espelha o Finding do motor (security_engine/app/sast_runner.py -> _parse_result):
// affectedUrl = "arquivo:linha" ou "arquivo:inicio-fim"; rawResponse = trecho vulnerável.
export interface SastFinding {
  title: string;
  description: string | null;
  severity: FindingSeverity;
  tool: 'SAST';
  affectedUrl: string;
  rawResponse: string | null;
  remediation: string | null;
  owaspUrl: string | null;
}

export interface SastResult {
  findings: SastFinding[];
  findingsCount: number;
  durationSeconds: number;
}

// Espelha backend/src/validators/sast_validator.js (aiFixSchema).
export interface AiFixRequest {
  code: string;
  firstLine: number;
  startLine: number;
  endLine: number;
  language: string;
  title: string;
  description?: string | null;
  remediation?: string | null;
}

/** Pacote de créditos de IA (compra demonstrativa, sem cobrança no TCC). */
export interface AiCreditPack {
  id: string;
  credits: number;
  priceLabel: string;
}

export interface AiConfig {
  enabled: boolean;
  /** saldo de créditos para a correção do arquivo inteiro (paga à parte do plano) */
  credits: number;
  fullFixCost: number;
  packs: AiCreditPack[];
}

export interface FullFixRequest {
  filename: string;
  language: string;
  code: string;
  findings: { title: string; startLine: number; endLine?: number | null; description?: string | null; remediation?: string | null }[];
}

export interface FullFixResult {
  fixedCode: string;
  summary: string;
  changes: { line: number; description: string }[];
  model: string;
  /** saldo depois do débito */
  credits: number;
}

export interface AiFixResult {
  fixedCode: string;
  explanation: string;
  model: string;
}

// limites do backend: 10mb por requisição (server.js) e 10 análises/hora (sastLimiter)
export const SAST_MAX_TOTAL_BYTES = 9 * 1024 * 1024;

@Injectable({ providedIn: 'root' })
export class SastService {
  private readonly http = inject(HttpClient);

  /** O servidor tem credencial da Anthropic para a correção com IA? */
  aiConfig(): Observable<AiConfig> {
    return this.http
      .get<AiConfig>(`${API_BASE_URL}/sast/ai-config`, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }

  /** POST /api/sast/fix-file — corrige o arquivo inteiro com IA; consome créditos (pagos à parte). */
  fixFullFile(request: FullFixRequest): Observable<FullFixResult> {
    return this.http
      .post<FullFixResult>(`${API_BASE_URL}/sast/fix-file`, request, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }

  /** POST /api/sast/credits/purchase — compra demonstrativa de um pacote de créditos. */
  purchaseCredits(packId: string): Observable<{ message: string; credits: number }> {
    return this.http
      .post<{ message: string; credits: number }>(`${API_BASE_URL}/sast/credits/purchase`, { packId }, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }

  /** POST /api/sast/fix — correção sugerida pela IA para a janela de código do achado. */
  suggestFix(request: AiFixRequest): Observable<AiFixResult> {
    return this.http
      .post<AiFixResult>(`${API_BASE_URL}/sast/fix`, request, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }

  /** POST /api/sast/analyze — { files: { "nome.ext": "conteúdo" } }. Pode levar até 2 min. */
  analyze(files: Record<string, string>): Observable<SastResult> {
    return this.http
      .post<SastResult>(`${API_BASE_URL}/sast/analyze`, { files }, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }
}

/** "src/app.js:12-14" -> { file: "src/app.js", start: 12, end: 14 } */
export const parseSastLocation = (location: string): { file: string; start: number; end: number } | null => {
  const match = /^(.*):(\d+)(?:-(\d+))?$/.exec(location ?? '');
  if (!match) return null;
  const start = Number(match[2]);
  return { file: match[1], start, end: match[3] ? Number(match[3]) : start };
};
