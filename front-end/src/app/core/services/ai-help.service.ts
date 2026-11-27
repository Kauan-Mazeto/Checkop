import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';
import { toApiError } from '../http/api-error';

// Espelha backend/src/routes/ai_help_routes.js (Premium + créditos de IA).
export type AiHelpKind = 'scan' | 'code';

export interface AiHelpSources {
  enabled: boolean;
  /** provedor que recebe a pergunta e o resumo (configurado no servidor) */
  provider: string | null;
  credits: number;
  /** créditos por pergunta */
  cost: number;
  scans: { id: string; targetUrl: string; objective: string; createdAt: string; findingsCount: number }[];
  analyses: { id: string; files: string[]; findingsCount: number; createdAt: string }[];
}

/** O texto exato que vai para o provedor de IA junto com a pergunta. */
export interface AiHelpContext {
  title: string;
  text: string;
}

export interface AiChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface AiChatResult {
  answer: string;
  truncated: boolean;
  model: string;
  credits: number;
}

@Injectable({ providedIn: 'root' })
export class AiHelpService {
  private readonly http = inject(HttpClient);

  sources(): Observable<AiHelpSources> {
    return this.http
      .get<AiHelpSources>(`${API_BASE_URL}/ai-help/sources`, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }

  context(kind: AiHelpKind, id: string): Observable<AiHelpContext> {
    return this.http
      .get<AiHelpContext>(`${API_BASE_URL}/ai-help/context`, { params: { kind, id }, withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }

  /** POST /api/ai-help/chat — usa 1 crédito por pergunta (devolvido se a IA falhar). */
  chat(kind: AiHelpKind, id: string, messages: AiChatMessage[]): Observable<AiChatResult> {
    return this.http
      .post<AiChatResult>(`${API_BASE_URL}/ai-help/chat`, { kind, id, messages }, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }
}
