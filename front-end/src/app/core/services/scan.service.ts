import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, map, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';
import { toApiError } from '../http/api-error';

// Espelham os enums do backend (backend/prisma/schema.prisma).
export type ScanEnvironment = 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION';
export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
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
export interface Finding {
  id: string;
  title: string;
  severity: FindingSeverity;
  status: string;
  tool: FindingTool;
  ruleId?: string | null;
  affectedUrl: string | null;
  parameter?: string | null;
  cveId: string | null;
  cvssScore: number | null;
  owaspUrl: string | null;
  description?: string | null;
  remediation: string | null;
  rawRequest?: string | null;
  rawResponse?: string | null;
  compliance: ComplianceNote[];
  /** plano Free: o backend não envia correção, PoC nem compliance */
  premiumLocked?: boolean;
  createdAt: string;
}

export interface ScanSummary {
  badge: { emoji: string; label: string; color: string };
  verdict: string;
  severityCounts: Record<FindingSeverity, number>;
}

// Espelha GET /api/scans/:id.
export interface ScanDetail extends Omit<Scan, 'findingsCount'> {
  objectiveLabel: string;
  plan?: 'FREE' | 'PREMIUM';
  engineWarnings: string[];
  activeScanConfirmedAt: string | null;
  summary: ScanSummary;
  findings: Finding[];
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
   */
  createScan(targetUrl: string, objective: string): Observable<Scan> {
    return this.http
      .post<{ scan: Scan }>(
        `${API_BASE_URL}/scans`,
        { targetUrl, objective, authorizationConfirmed: true },
        withCredentials
      )
      .pipe(map((response) => response.scan), catchError(this.fail));
  }

  /** POST /api/scans/:id/run — responde 202 e a varredura roda em segundo plano. */
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
