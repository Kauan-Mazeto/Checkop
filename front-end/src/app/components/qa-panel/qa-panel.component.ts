import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { SEVERITY_LABEL, SEVERITY_ORDER } from '../../core/constants/dashboard.constants';
import { DashboardStateService } from '../../core/services/dashboard-state.service';
import { ReportExportService, ReportFormat } from '../../core/services/report-export.service';

@Component({
  selector: 'app-qa-panel',
  templateUrl: './qa-panel.component.html',
  styleUrl: './qa-panel.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class QaPanelComponent {
  protected readonly state = inject(DashboardStateService);
  private readonly reportExport = inject(ReportExportService);
  protected readonly severityLabel = SEVERITY_LABEL;

  // Gráficos alimentados por state.findings() (GET /api/scans/:id -> findings).
  // Enquanto a integração ZAP/Nuclei não popular a tabela Finding, ficam vazios
  // e o template mostra "aguardando primeira varredura".
  protected readonly severityCounts = computed(() =>
    SEVERITY_ORDER.map((severity) => ({
      severity,
      count: this.state.findings().filter((finding) => finding.severity === severity).length,
    }))
  );

  protected readonly maxSeverityCount = computed(() =>
    Math.max(1, ...this.severityCounts().map((item) => item.count))
  );

  // "Tipo" = título do achado (ex.: "SQL Injection"), top 5. O Subfinder gera um
  // achado por subdomínio ("Subdomínio encontrado: x.site.com"), então eles são
  // agrupados num único tipo para não poluir o gráfico.
  protected readonly typeCounts = computed(() => {
    const counts = new Map<string, number>();

    for (const finding of this.state.findings()) {
      const type = finding.tool === 'SUBFINDER' ? 'Subdomínio encontrado' : finding.title;
      counts.set(type, (counts.get(type) ?? 0) + 1);
    }

    return [...counts.entries()]
      .map(([title, count]) => ({ title, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  });

  protected readonly maxTypeCount = computed(() =>
    Math.max(1, ...this.typeCounts().map((item) => item.count))
  );

  // Alvos escaneados mais de uma vez = candidatos a comparação (regressão).
  protected readonly repeatedTargets = computed(() => {
    const counts = new Map<string, number>();

    for (const scan of this.state.scans()) {
      counts.set(scan.targetUrl, (counts.get(scan.targetUrl) ?? 0) + 1);
    }

    return [...counts.entries()]
      .filter(([, runs]) => runs > 1)
      .map(([targetUrl, runs]) => ({ targetUrl, runs }));
  });

  protected readonly exporting = signal<ReportFormat | null>(null);
  protected readonly exportError = signal<string | null>(null);

  // Recurso Premium: exporta o relatório do último scan concluído (achados reais).
  protected exportLatest(format: ReportFormat): void {
    const scan = this.state.latestCompletedScan();

    if (!scan || this.exporting()) {
      return;
    }

    this.exportError.set(null);
    this.exporting.set(format);

    this.reportExport.export(scan.id, format).subscribe({
      next: () => this.exporting.set(null),
      error: (message: string) => {
        this.exportError.set(message);
        this.exporting.set(null);
      },
    });
  }
}
