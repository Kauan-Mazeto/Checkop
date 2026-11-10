import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, map, throwError } from 'rxjs';
import { API_BASE_URL } from '../constants/api.constants';
import { toApiError } from '../http/api-error';

// Espelham backend/src/controllers/target_controllers.js e lib/target_verification.js.
export type VerificationMethod = 'DNS_TXT' | 'HTTP_FILE' | 'META_TAG';

export interface TargetInstructions {
  method: VerificationMethod;
  covers: string;
  note: string;
  // DNS_TXT
  recordType?: string;
  recordName?: string;
  recordValue?: string;
  // HTTP_FILE
  fileUrl?: string;
  fileContent?: string;
  // META_TAG
  pageUrl?: string;
  metaTag?: string;
}

export interface Target {
  id: string;
  hostname: string;
  scope: 'DOMAIN' | 'HOST';
  verificationMethod: VerificationMethod;
  verified: boolean;
  verifiedAt: string | null;
  lastCheckedAt: string | null;
  createdAt: string;
  instructions: TargetInstructions;
}

const withCredentials = { withCredentials: true };

@Injectable({ providedIn: 'root' })
export class TargetService {
  private readonly http = inject(HttpClient);

  listTargets(): Observable<Target[]> {
    return this.http
      .get<{ targets: Target[] }>(`${API_BASE_URL}/targets`, withCredentials)
      .pipe(map((response) => response.targets), catchError(this.fail));
  }

  /** 409 (já cadastrado) devolve o alvo existente em error.body.target. */
  createTarget(url: string, method: VerificationMethod): Observable<Target> {
    return this.http
      .post<{ target: Target }>(`${API_BASE_URL}/targets`, { url, method }, withCredentials)
      .pipe(map((response) => response.target), catchError(this.fail));
  }

  /** 422 VERIFICATION_NOT_FOUND quando a prova não está publicada. */
  verifyTarget(id: string): Observable<Target> {
    return this.http
      .post<{ target: Target }>(`${API_BASE_URL}/targets/${encodeURIComponent(id)}/verify`, {}, withCredentials)
      .pipe(map((response) => response.target), catchError(this.fail));
  }

  deleteTarget(id: string): Observable<void> {
    return this.http
      .delete<unknown>(`${API_BASE_URL}/targets/${encodeURIComponent(id)}`, withCredentials)
      .pipe(map(() => undefined), catchError(this.fail));
  }

  private readonly fail = (error: HttpErrorResponse) => throwError(() => toApiError(error));
}
