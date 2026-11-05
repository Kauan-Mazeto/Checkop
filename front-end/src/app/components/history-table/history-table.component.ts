import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  ENVIRONMENT_LABEL,
  ENVIRONMENT_LONG_LABEL,
  OBJECTIVE_LABEL,
  STATUS_LABEL,
} from '../../core/constants/dashboard.constants';
import { DashboardStateService } from '../../core/services/dashboard-state.service';
import { ReportExportService, ReportFormat } from '../../core/services/report-export.service';
import { Scan } from '../../core/services/scan.service';

@Component({
  selector: 'app-history-table',
  imports: [DatePipe, FormsModule],
  templateUrl: './history-table.component.html',
  styleUrl: './history-table.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HistoryTableComponent {
  protected readonly state = inject(DashboardStateService);
  private readonly reportExport = inject(ReportExportService);

  protected readonly statusLabel = STATUS_LABEL;
  protected readonly environmentLabel = ENVIRONMENT_LABEL;
  protected readonly environmentLongLabel = ENVIRONMENT_LONG_LABEL;
  protected readonly objectiveLabel = OBJECTIVE_LABEL;

  protected readonly term = signal('');
  // ids dos scans cujo "Executar" está em andamento (evita duplo clique)
  protected readonly startingIds = signal<string[]>([]);
  // "<id>:<formato>" das exportações em andamento
  protected readonly exportingKeys = signal<string[]>([]);
  protected readonly exportError = signal<string | null>(null);

  // O histórico é a própria lista de scans do usuário (GET /api/scans).
  // BACKEND: se a lista ficar grande, paginar/filtrar no servidor
  // (ex.: GET /api/scans?search=&page=) em vez de filtrar em memória.
  private readonly filtered = computed(() => {
    const term = this.term().toLowerCase().trim();

    if (!term) {
      return this.state.scans();
    }

    return this.state.scans().filter((scan) =>
      `${scan.targetUrl} ${ENVIRONMENT_LONG_LABEL[scan.environment]} ${STATUS_LABEL[scan.status]} ${
        scan.safeMode ? 'modo seguro' : 'modo verboso'
      }`
        .toLowerCase()
        .includes(term)
    );
  });

  // Plano Free não tem histórico: só o último scan, para acompanhar o andamento.
  // BACKEND: o servidor também deve limitar GET /api/scans no plano Free.
  protected readonly visibleScans = computed(() =>
    this.state.planDefinition().canViewHistory ? this.filtered() : this.state.scans().slice(0, 1)
  );

  // O backend só executa scans PENDING ou FAILED (409 nos demais).
  protected canRun(scan: Scan): boolean {
    return scan.status === 'PENDING' || scan.status === 'FAILED';
  }

  protected run(scan: Scan): void {
    if (this.startingIds().includes(scan.id)) {
      return;
    }

    this.startingIds.update((ids) => [...ids, scan.id]);

    this.state.runScan(scan).subscribe({
      next: () => this.finishRun(scan.id),
      error: (message: string) => {
        this.state.scansError.set(message);
        this.finishRun(scan.id);
      },
    });
  }

  protected isExporting(scan: Scan, format: ReportFormat): boolean {
    return this.exportingKeys().includes(`${scan.id}:${format}`);
  }

  // Recurso Premium: gera o relatório do scan com os achados reais.
  protected exportReport(scan: Scan, format: ReportFormat): void {
    const key = `${scan.id}:${format}`;

    if (this.exportingKeys().includes(key)) {
      return;
    }

    this.exportError.set(null);
    this.exportingKeys.update((keys) => [...keys, key]);

    this.reportExport.export(scan.id, format).subscribe({
      next: () => this.finishExport(key),
      error: (message: string) => {
        this.exportError.set(message);
        this.finishExport(key);
      },
    });
  }

  private finishRun(id: string): void {
    this.startingIds.update((ids) => ids.filter((current) => current !== id));
  }

  private finishExport(key: string): void {
    this.exportingKeys.update((keys) => keys.filter((current) => current !== key));
  }
}
