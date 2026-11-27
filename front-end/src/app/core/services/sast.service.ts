import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';
import { toApiError } from '../http/api-error';
import { FindingSeverity } from './scan.service';

// Espelha o Finding do motor (security_engine/app/sast_runner.py -> _parse_result):
// affectedUrl = "arquivo:linha" ou "arquivo:inicio-fim"; rawResponse = trecho vulnerável.
/** Tipo do problema encontrado na análise de código. */
export type SastCategory = 'SECURITY' | 'LOGIC' | 'SYNTAX' | 'DEPENDENCY' | 'QUALITY';

/** COMPLETE = todas as regras de todas as ferramentas; ESSENTIAL = só bug, sintaxe e segurança. */
export type SastDepth = 'COMPLETE' | 'ESSENTIAL';

/** Outro problema no mesmo trecho de código, mostrado dentro do achado principal. */
export interface SastRelatedIssue {
  title: string;
  severity: SastFinding['severity'];
  category?: SastCategory | null;
  description?: string | null;
  remediation?: string | null;
  fixedCode?: string | null;
}

export interface SastFinding {
  title: string;
  /** sem categoria = segurança (achados antigos do Semgrep/Gitleaks) */
  category?: SastCategory | null;
  ruleId?: string | null;
  cveId?: string | null;
  cvssScore?: number | null;
  description: string | null;
  severity: FindingSeverity;
  tool: 'SAST';
  affectedUrl: string;
  rawResponse: string | null;
  remediation: string | null;
  /** linhas do achado já corrigidas, calculadas pela ferramenta sobre o código enviado (sem IA) */
  fixedCode?: string | null;
  /** ferramentas que apontaram o achado (Semgrep, PMD, ESLint...) */
  detectedBy?: string[] | null;
  /** outros problemas apontados no mesmo trecho (um card por trecho) */
  related?: SastRelatedIssue[] | null;
  owaspUrl: string | null;
}

export interface SastResult {
  findings: SastFinding[];
  findingsCount: number;
  durationSeconds: number;
  /** ferramentas que analisaram, as não instaladas neste servidor e avisos */
  tools?: { depth?: SastDepth; used: string[]; skipped: string[]; warnings: string[] };
  /** id da análise no histórico (só o resumo é guardado); null se não deu para gravar */
  historyId?: string | null;
}

/** Achado como fica no histórico: sem código, trecho, correção nem descrição. */
export interface SastHistoryFinding {
  title: string;
  severity: FindingSeverity;
  category: SastCategory;
  file: string;
  line: number | null;
  ruleId: string | null;
  tools: string[];
}

/** Resumo de uma análise guardado no servidor (backend/src/lib/code_analysis_history.js). */
export interface SastHistoryItem {
  id: string;
  createdAt: string;
  depth: SastDepth;
  durationSeconds: number;
  findingsCount: number;
  files: { name: string; language: string; lines: number }[];
  severityCounts: Record<FindingSeverity, number>;
  categoryCounts: Record<SastCategory, number>;
  findings: SastHistoryFinding[];
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
  /** quem recebe o código: "Anthropic (Claude)" ou "Google (Gemini...)"; null sem IA */
  provider?: string | null;
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

  /** O servidor tem credencial de um provedor de IA (Anthropic ou Gemini) para a correção com IA? */
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

  /** GET /api/sast/history — resumos das análises, da mais nova para a mais antiga (Premium). */
  history(): Observable<{ analyses: SastHistoryItem[]; limit: number }> {
    return this.http
      .get<{ analyses: SastHistoryItem[]; limit: number }>(`${API_BASE_URL}/sast/history`, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }

  /** DELETE /api/sast/history/:id — apaga uma análise do histórico. */
  deleteHistoryItem(id: string): Observable<void> {
    return this.http
      .delete<void>(`${API_BASE_URL}/sast/history/${encodeURIComponent(id)}`, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }

  /** DELETE /api/sast/history — apaga o histórico inteiro. */
  clearHistory(): Observable<{ deleted: number }> {
    return this.http
      .delete<{ deleted: number }>(`${API_BASE_URL}/sast/history`, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => toApiError(error))));
  }

  /** POST /api/sast/analyze — { files: { "nome.ext": "conteúdo" } }. Pode levar até 2 min. */
  analyze(files: Record<string, string>, depth: SastDepth = 'COMPLETE'): Observable<SastResult> {
    return this.http
      .post<SastResult>(`${API_BASE_URL}/sast/analyze`, { files, depth }, { withCredentials: true })
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
