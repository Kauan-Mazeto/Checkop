import { Injectable } from '@angular/core';
import { Observable, delay, of } from 'rxjs';

export interface CodeAnalysisRequest {
  snippet: string;
  language: string;
}

export interface CodeAnalysisResult {
  summary: string;
  // vazio de propósito enquanto não houver integração real: o resultado de
  // demonstração nunca inventa vulnerabilidades.
  findings: { title: string; severity: string; remediation: string | null }[];
}

@Injectable({ providedIn: 'root' })
export class CodeAnalysisService {
  // BACKEND (ainda não existe no servidor): trocar por
  //   POST /api/code-analysis  { snippet, language } -> CodeAnalysisResult
  // com a integração de análise estática (ex.: Semgrep). Recurso dos planos
  // Plus e Business — o servidor também precisa recusar o plano Free.
  analyze(request: CodeAnalysisRequest): Observable<CodeAnalysisResult> {
    void request;
    return of<CodeAnalysisResult>({
      summary: 'Nenhuma vulnerabilidade, correção ou payload foi gerado.',
      findings: [],
    }).pipe(delay(700));
  }
}
