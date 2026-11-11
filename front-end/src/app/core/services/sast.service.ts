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

// limites do backend: 10mb por requisição (server.js) e 10 análises/hora (sastLimiter)
export const SAST_MAX_TOTAL_BYTES = 9 * 1024 * 1024;

@Injectable({ providedIn: 'root' })
export class SastService {
  private readonly http = inject(HttpClient);

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
