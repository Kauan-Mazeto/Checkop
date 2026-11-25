import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, map, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';
import { toApiError } from '../http/api-error';
import type { UserRole } from './auth.service';

// Espelham os enums do backend (backend/prisma/schema.prisma).
export type ScanEnvironment = 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION';
export type ExportFormat = 'findings-csv' | 'scans-csv' | 'json';

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELED';

/** Concluída ou cancelada: as duas têm resultado (a cancelada, parcial). */
export const hasResults = (status: ScanStatus): boolean => status === 'COMPLETED' || status === 'CANCELED';
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingTool = 'ZAP' | 'NUCLEI' | 'SUBFINDER';

// Espelha GET /api/scans (scan_controllers.js -> listScans).
export interface Scan {
  id: string;
  targetUrl: string;
  objective: string;
  objectiveLabel: string;
  environment: ScanEnvironment;
  safeMode: boolean;
  status: ScanStatus;
  suspiciousEnvironment: boolean;
  resolvedIps: string[];
  findingsCount: number;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

// Espelha GET /api/scans/objectives (constants/scan_objectives.js -> listObjectives).
export interface ScanObjective {
  key: string;
  label: string;
  description: string;
  owasp: string | null;
  coverage: 'FULL' | 'PARTIAL';
  requiresActiveScan: boolean;
  engines: string[];
}

export interface ComplianceNote {
  law: string;
  reference: string;
  message: string;
}

// Espelha lib/py/finding_serializer.js. Em Modo Seguro (produção) o backend
// não manda description/parameter/rawRequest/rawResponse (RF-08).
/** Um dos lugares onde a falha aparece (o backend agrupa a mesma falha). */
export interface FindingLocation {
  id: string;
  affectedUrl: string | null;
  parameter?: string | null;
  /** payload usado no ataque (PoC) */
  attack?: string | null;
  /** comando para reproduzir (curl) */
  reproduction?: string | null;
  severity: FindingSeverity;
  cvssScore?: number | null;
  rawRequest?: string | null;
  rawResponse?: string | null;
}

export interface Finding {
  id: string;
  title: string;
  severity: FindingSeverity;
  status: string;
  tool: FindingTool;
  ruleId?: string | null;
  affectedUrl: string | null;
  parameter?: string | null;
  attack?: string | null;
  reproduction?: string | null;
  cveId: string | null;
  cvssScore: number | null;
  /** CVSS 3.1: vetor usado no cálculo da nota */
  cvssVector?: string | null;
  /** origem do vetor: template (NVD), classe da falha (CWE) ou estimativa */
  cvssSource?: 'TEMPLATE' | 'CWE' | 'SEVERITY' | null;
  /** confiança da ferramenta no achado */
  confidence?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CONFIRMED' | null;
  owaspUrl: string | null;
  description?: string | null;
  remediation: string | null;
  rawRequest?: string | null;
  rawResponse?: string | null;
  compliance: ComplianceNote[];
  /** plano Free: o backend não envia correção, PoC nem compliance */
  premiumLocked?: boolean;
  createdAt: string;
  /** detalhe da varredura: ferramentas que apontaram a falha */
  tools?: FindingTool[];
  /** detalhe da varredura: todos os locais (o primeiro é o mais grave) */
  locations?: FindingLocation[];
}

export interface ScanSummary {
  badge: { label: string; color: string };
  verdict: string;
  severityCounts: Record<FindingSeverity, number>;
}

// Espelha GET /api/scans/:id.
export interface ScanDetail extends Omit<Scan, 'findingsCount'> {
  objectiveLabel: string;
  plan?: 'FREE' | 'PREMIUM';
  /** perfil de quem pediu (RF-11): define o formato do relatório */
  role?: UserRole;
  engineWarnings: string[];
  activeScanConfirmedAt: string | null;
  summary: ScanSummary;
  findings: Finding[];
}

// Espelha GET /api/scans/:id/compare (RF-19).
export interface ComparedScan {
  id: string;
  createdAt: string;
  finishedAt: string | null;
  objective: string;
  objectiveLabel: string;
}

export interface PersistentFinding extends Finding {
  previousSeverity: FindingSeverity;
  trend: 'WORSE' | 'BETTER' | 'SAME';
}

export interface ScanComparison {
  current: ComparedScan;
  /** null = não há varredura anterior do mesmo alvo e tipo de teste */
  base: ComparedScan | null;
  candidates: ComparedScan[];
  summary?: { added: number; fixed: number; persistent: number };
  added?: Finding[];
  fixed?: Finding[];
  persistent?: PersistentFinding[];
}

// Espelha GET /api/scans/stats.
export interface ScanStats {
  scans: {
    total: number;
    byStatus: Record<string, number>;
    byObjective: Record<string, number>;
    byEnvironment: Record<string, number>;
  };
  findings: {
    total: number;
    bySeverity: Record<string, number>;
    byTool: Record<string, number>;
    byOwaspCategory: Record<string, number>;
    byStatus: Record<string, number>;
    timelineLast30Days: Record<string, number>;
  };
}

export interface ZapAuthOptions {
  loginUrl: string;
  usernameField: string;
  passwordField: string;
  username: string;
  password: string;
}

// Espelha runScanAuthSchema (backend/src/validators/scan_validator.js).
export interface RunScanOptions {
  useAjaxSpider?: boolean;
  auth?: ZapAuthOptions;
  activeScanConfirmed?: boolean;
  hostingTermsConfirmed?: boolean;
}

const withCredentials = { withCredentials: true };

@Injectable({ providedIn: 'root' })
export class ScanService {
  private readonly http = inject(HttpClient);

  /** GET /api/scans — só os scans do usuário logado (o backend filtra por req.userId). */
  listScans(): Observable<Scan[]> {
    return this.http
      .get<{ scans: Scan[] }>(`${API_BASE_URL}/scans`, withCredentials)
      .pipe(map((response) => response.scans), catchError(this.fail));
  }

  getScan(id: string): Observable<ScanDetail> {
    return this.http
      .get<{ scan: ScanDetail }>(`${API_BASE_URL}/scans/${encodeURIComponent(id)}`, withCredentials)
      .pipe(map((response) => response.scan), catchError(this.fail));
  }

  /** RF-19: compara com a varredura anterior do mesmo alvo (ou com `withId`). Premium. */
  compareScan(id: string, withId?: string | null): Observable<ScanComparison> {
    const query = withId ? `?with=${encodeURIComponent(withId)}` : '';
    return this.http
      .get<ScanComparison>(`${API_BASE_URL}/scans/${encodeURIComponent(id)}/compare${query}`, withCredentials)
      .pipe(catchError(this.fail));
  }

  /** Painel > Exportar: todas as varreduras (Premium). Devolve o arquivo pronto para baixar. */
  exportAll(format: ExportFormat): Observable<Blob> {
    return this.http
      .get(`${API_BASE_URL}/scans/export`, { ...withCredentials, params: { format }, responseType: 'blob' })
      .pipe(
        catchError((error: HttpErrorResponse) =>
          // erro chega como Blob; a mensagem do backend fica legível só pelo status
          throwError(() =>
            toApiError(
              new HttpErrorResponse({
                status: error.status,
                error: { error: error.status === 403 ? 'Exportar relatórios é um recurso Premium.' : 'Não foi possível exportar agora.' },
              })
            )
          )
        )
      );
  }

  getStats(): Observable<ScanStats> {
    return this.http.get<ScanStats>(`${API_BASE_URL}/scans/stats`, withCredentials).pipe(catchError(this.fail));
  }

  getObjectives(): Observable<ScanObjective[]> {
    return this.http
      .get<{ objectives: ScanObjective[] }>(`${API_BASE_URL}/scans/objectives`, withCredentials)
      .pipe(map((response) => response.objectives), catchError(this.fail));
  }

  /**
   * POST /api/scans. authorizationConfirmed só é enviado como true quando o
   * usuário marcou o checkbox na tela (obrigatório por lei/ética, não é forma).
   * Site público sem alvo verificado → ApiError com code TARGET_NOT_VERIFIED.
   * Sem objetivo, o backend usa o padrão do plano (Free = scan básico).
   * Regras do plano → PREMIUM_REQUIRED (objetivo) ou DAILY_SCAN_LIMIT.
   */
  createScan(targetUrl: string, objective?: string | null): Observable<Scan> {
    return this.http
      .post<{ scan: Scan }>(
        `${API_BASE_URL}/scans`,
        { targetUrl, ...(objective ? { objective } : {}), authorizationConfirmed: true },
        withCredentials
      )
      .pipe(map((response) => response.scan), catchError(this.fail));
  }

  /** POST /api/scans/:id/run — responde 202 e a varredura roda em segundo plano. */
  /** Para as ferramentas; o que já foi verificado fica salvo como resultado parcial. */
  cancelScan(id: string): Observable<{ message: string }> {
    return this.http
      .post<{ message: string }>(`${API_BASE_URL}/scans/${encodeURIComponent(id)}/cancel`, {}, withCredentials)
      .pipe(catchError(this.fail));
  }

  runScan(id: string, options: RunScanOptions): Observable<{ id: string; status: ScanStatus; activeScan: boolean }> {
    return this.http
      .post<{ scan: { id: string; status: ScanStatus; activeScan: boolean } }>(
        `${API_BASE_URL}/scans/${encodeURIComponent(id)}/run`,
        options,
        withCredentials
      )
      .pipe(map((response) => response.scan), catchError(this.fail));
  }

  private readonly fail = (error: HttpErrorResponse) => throwError(() => toApiError(error));
}
