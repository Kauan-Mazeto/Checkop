import { DOCUMENT } from '@angular/common';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, map, tap, throwError } from 'rxjs';
import {
  ENVIRONMENT_LONG_LABEL,
  OBJECTIVE_LABEL,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  STATUS_LABEL,
} from '../constants/dashboard.constants';
import { Finding, ScanDetail, ScanService } from './scan.service';

export type ReportFormat = 'json' | 'pdf';

// Exportação do relatório de um scan (recurso do plano Premium).
//
// O relatório é montado NO NAVEGADOR a partir de GET /api/scans/:id (scan +
// achados reais), então não depende de endpoint novo:
//   - JSON: baixa um arquivo .json;
//   - PDF: abre uma página de relatório pronta para impressão e chama a
//     impressão do navegador (escolha "Salvar como PDF").
// BACKEND: se um dia o servidor gerar o PDF, troque o corpo de `export` por
// um download de GET /api/scans/:id/report?format=pdf|json (mantendo a
// assinatura) e o servidor também precisa recusar o plano Free.
//
// Segurança: títulos/descrições dos achados vêm do alvo escaneado (conteúdo de
// terceiros). Tudo que entra no HTML do relatório passa por escapeHtml().
@Injectable({ providedIn: 'root' })
export class ReportExportService {
  private readonly scanService = inject(ScanService);
  private readonly document = inject(DOCUMENT);

  // Deve ser chamado direto do clique: no PDF a janela é aberta aqui, na hora,
  // porque navegadores bloqueiam pop-ups abertos depois de uma chamada HTTP.
  export(scanId: string, format: ReportFormat): Observable<void> {
    const popup = format === 'pdf' ? (this.document.defaultView?.open('', '_blank') ?? null) : null;

    if (format === 'pdf' && !popup) {
      return throwError(
        () => 'O navegador bloqueou a janela do relatório. Permita pop-ups para exportar o PDF.'
      );
    }

    return this.scanService.getScan(scanId).pipe(
      tap((detail) => (popup ? this.printReport(popup, detail) : this.downloadJson(detail))),
      map(() => undefined),
      catchError((error: unknown) => {
        popup?.close();
        return throwError(() => error);
      })
    );
  }

  // ---------- JSON ----------
  private downloadJson(detail: ScanDetail): void {
    const report = {
      produto: 'Checkop',
      geradoEm: new Date().toISOString(),
      scan: this.summary(detail),
      achados: this.sortedFindings(detail),
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const link = this.document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${this.fileName(detail)}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  // ---------- PDF (impressão do navegador) ----------
  private printReport(popup: Window, detail: ScanDetail): void {
    if (popup.closed) {
      return;
    }

    popup.document.open();
    popup.document.write(this.buildHtml(detail));
    popup.document.close();
    setTimeout(() => popup.print(), 300);
  }

  private buildHtml(detail: ScanDetail): string {
    const findings = this.sortedFindings(detail);
    const e = (value: unknown) => this.escapeHtml(value);

    const findingBlocks = findings.length
      ? findings
          .map(
            (finding) => `
      <section class="finding">
        <h3><span class="sev sev-${e(finding.severity)}">${e(SEVERITY_LABEL[finding.severity] ?? finding.severity)}</span> ${e(finding.title)}</h3>
        <p class="meta">Ferramenta: ${e(finding.tool)}${finding.affectedUrl ? ` · ${e(finding.affectedUrl)}` : ''}${finding.cvssScore != null ? ` · CVSS ${e(finding.cvssScore)}` : ''}${finding.cveId ? ` · ${e(finding.cveId)}` : ''}</p>
        ${finding.description ? `<p>${e(finding.description)}</p>` : ''}
        ${finding.remediation ? `<p><b>Como corrigir:</b> ${e(finding.remediation)}</p>` : ''}
        ${finding.owaspUrl ? `<p class="meta">Referência OWASP: ${e(finding.owaspUrl)}</p>` : ''}
      </section>`
          )
          .join('')
      : '<p>Nenhum achado registrado para este scan.</p>';

    const scan = this.summary(detail);

    return `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<title>Relatório Checkop — ${e(scan.alvo)}</title>
<style>
  body { font-family: Arial, Helvetica, sans-serif; color: #18181b; margin: 32px; line-height: 1.5; }
  h1 { margin: 0 0 4px; font-size: 22px; } h2 { margin: 28px 0 8px; font-size: 16px; }
  h3 { margin: 0 0 4px; font-size: 14px; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  td { padding: 6px 8px; border-bottom: 1px solid #e4e4e7; } td:first-child { width: 180px; color: #52525b; }
  .finding { margin: 0 0 14px; padding: 10px 12px; border: 1px solid #e4e4e7; border-radius: 6px; page-break-inside: avoid; }
  .finding p { margin: 4px 0; font-size: 13px; } .meta { color: #52525b; font-size: 12px !important; word-break: break-all; }
  .sev { display: inline-block; padding: 1px 7px; border-radius: 4px; background: #e4e4e7; font-size: 11px; }
  .sev-CRITICAL { background: #ff3347; color: #fff; } .sev-HIGH { background: #fecdd3; } .sev-MEDIUM { background: #fde68a; }
  .foot { margin-top: 24px; color: #71717a; font-size: 11px; }
</style></head><body>
  <h1>Relatório de segurança</h1>
  <div class="meta">Checkop · gerado em ${e(new Date().toLocaleString('pt-BR'))}</div>
  <h2>Resumo do scan</h2>
  <table>
    <tr><td>Alvo</td><td>${e(scan.alvo)}</td></tr>
    <tr><td>Objetivo</td><td>${e(scan.objetivo ?? '—')}</td></tr>
    <tr><td>Ambiente detectado</td><td>${e(scan.ambiente)}</td></tr>
    <tr><td>Modo</td><td>${e(scan.modo)}</td></tr>
    <tr><td>Status</td><td>${e(scan.status)}</td></tr>
    <tr><td>Criado em</td><td>${e(scan.criadoEm)}</td></tr>
    <tr><td>Achados</td><td>${findings.length}</td></tr>
  </table>
  <h2>Achados</h2>
  ${findingBlocks}
  <p class="foot">Relatório gerado automaticamente. Use apenas em alvos que você tem autorização para testar.</p>
</body></html>`;
  }

  // ---------- auxiliares ----------
  private summary(detail: ScanDetail) {
    return {
      id: detail.id,
      alvo: detail.targetUrl,
      objetivo: detail.objective ? OBJECTIVE_LABEL[detail.objective] : null,
      ambiente: ENVIRONMENT_LONG_LABEL[detail.environment],
      modo: detail.safeMode ? 'Modo Seguro' : 'Modo Verboso',
      status: STATUS_LABEL[detail.status],
      criadoEm: new Date(detail.createdAt).toLocaleString('pt-BR'),
    };
  }

  private sortedFindings(detail: ScanDetail): Finding[] {
    return [...detail.findings].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );
  }

  private fileName(detail: ScanDetail): string {
    let host = 'scan';

    try {
      host = new URL(detail.targetUrl).hostname.replace(/[^a-z0-9.-]/gi, '_');
    } catch {
      // mantém "scan"
    }

    return `checkop-relatorio-${host}-${new Date().toISOString().slice(0, 10)}`;
  }

  private escapeHtml(value: unknown): string {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
}
