import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, map, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';

// Espelha os enums TargetEnvironment/ScanStatus do backend
// (backend/prisma/schema.prisma).
export type ScanEnvironment = 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION';
export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';

// Espelha o enum ScanObjective (schema.prisma) e as chaves de SCAN_OBJECTIVES
// (backend/src/constants/scan_objectives.js): "o que o usuário quer testar".
export type ScanObjective =
  | 'SQL_INJECTION'
  | 'XSS'
  | 'CSRF'
  | 'SSRF'
  | 'OPEN_REDIRECT'
  | 'KNOWN_CVE'
  | 'SUBDOMAIN_ENUM'
  | 'FULL_SCAN';

// Espelha os enums FindingSeverity/FindingStatus/ToolType do backend.
export type FindingSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type FindingStatus = 'OPEN' | 'FALSE_POSITIVE' | 'FIXED' | 'IGNORED';
export type FindingTool = 'ZAP' | 'NUCLEI' | 'SUBFINDER';

// Espelha o select de GET /api/scans (backend/src/controllers/scan_controllers.js),
// incluindo a des-serialização de resolvedIps (feita no próprio controller).
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
  // BACKEND: POST /api/scans já devolve `objective`, mas o select de
  // listScans ainda não — por isso é opcional. Adicione `objective: true` ao
  // select e o histórico passa a mostrar o objetivo de cada scan.
  objective?: ScanObjective;
}

// Espelha o model Finding (schema.prisma), devolvido em GET /api/scans/:id.
// No Modo Seguro (safeMode === true) o servidor remove description, parameter,
// rawRequest e rawResponse (backend/src/lib/py/finding_serializer.js) — por
// isso esses campos são opcionais: a tela só mostra o que chegar.
export interface Finding {
  id: string;
  scanId?: string;
  title: string;
  description?: string | null;
  severity: FindingSeverity;
  status: FindingStatus;
  tool: FindingTool;
  affectedUrl: string | null;
  parameter?: string | null;
  cveId: string | null;
  cvssScore: number | null;
  rawRequest?: string | null;
  rawResponse?: string | null;
  remediation: string | null;
  owaspUrl: string | null;
  createdAt: string;
}

// Espelha o corpo de GET /api/scans/:id (scan completo + findings).
export interface ScanDetail extends Scan {
  findings: Finding[];
}

interface ListScansResponse {
  scans: Scan[];
}

// Espelha a resposta 202 de POST /api/scans/:id/run.
export interface RunScanResponse {
  message: string;
  scan: { id: string; status: ScanStatus; objective: ScanObjective };
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
   * GET /api/scans/:id — scan + findings (requireOwnership garante que o
   * scan é do usuário logado). É por aqui que se acompanha uma varredura.
   */
  getScan(id: string): Observable<ScanDetail> {
    return this.http
      .get<{ scan: ScanDetail }>(`${API_BASE_URL}/scans/${id}`, { withCredentials: true })
      .pipe(
        map((response) => response.scan),
        catchError((error: HttpErrorResponse) => throwError(() => this.toErrorMessage(error)))
      );
  }

  /**
   * POST /api/scans — espelha createScanSchema: exige targetUrl válida e
   * authorizationConfirmed === true (checkbox de "tenho autorização para
   * testar este alvo", obrigatório por lei/ética, não é só forma).
   * `objective` é opcional: sem ele o backend assume FULL_SCAN.
   * Só REGISTRA o scan (status PENDING); para executar, chame runScan().
   */
  createScan(targetUrl: string, objective?: ScanObjective): Observable<Scan> {
    return this.http
      .post<{ message: string; scan: Scan }>(
        `${API_BASE_URL}/scans`,
        { targetUrl, objective, authorizationConfirmed: true },
        { withCredentials: true }
      )
      .pipe(
        map((response) => response.scan),
        catchError((error: HttpErrorResponse) => throwError(() => this.toErrorMessage(error)))
      );
  }

  /**
   * POST /api/scans/:id/run — dispara a varredura (ZAP/Nuclei/Subfinder).
   * O servidor responde 202 NA HORA e roda em segundo plano; quem acompanha é
   * o GET /api/scans/:id (ou listScans). Só aceita scans PENDING ou FAILED:
   * COMPLETED/RUNNING voltam 409 com a mensagem pronta para exibir.
   * O corpo vazio é válido (runScanAuthSchema tem defaults).
   */
  runScan(id: string): Observable<RunScanResponse> {
    return this.http
      .post<RunScanResponse>(`${API_BASE_URL}/scans/${id}/run`, {}, { withCredentials: true })
      .pipe(catchError((error: HttpErrorResponse) => throwError(() => this.toErrorMessage(error))));
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

    if (error.status === 429) {
      return 'Muitas requisições em pouco tempo. Aguarde um instante e tente novamente.';
    }

    return 'Erro inesperado. Tente novamente.';
  }
}
