import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError } from '../../core/http/api-error';
import { DraftService } from '../../core/services/draft.service';
import { Scan, ScanEnvironment, ScanService, ScanStatus } from '../../core/services/scan.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ENVIRONMENT_LABEL, STATUS_LABEL } from '../../shared/ui/labels';

export interface HistoryFilters {
  search: string;
  status: ScanStatus | '';
  environment: ScanEnvironment | '';
  objective: string;
}

const EMPTY_FILTERS: HistoryFilters = { search: '', status: '', environment: '', objective: '' };

/** Filtro do histórico (RF-13): busca por URL ou tipo de falha + filtros exatos. */
export const filterScans = (scans: Scan[], f: HistoryFilters): Scan[] => {
  const term = f.search.trim().toLowerCase();
  return scans.filter(
    (scan) =>
      (!term || scan.targetUrl.toLowerCase().includes(term) || scan.objectiveLabel.toLowerCase().includes(term)) &&
      (!f.status || scan.status === f.status) &&
      (!f.environment || scan.environment === f.environment) &&
      (!f.objective || scan.objective === f.objective)
  );
};

@Component({
  selector: 'app-scan-history-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, AppShellComponent],
  templateUrl: './scan-history-page.component.html',
})
export class ScanHistoryPageComponent implements OnInit {
  private readonly scanService = inject(ScanService);
  private readonly drafts = inject(DraftService);

  protected readonly statusLabel = STATUS_LABEL;
  protected readonly environmentLabel = ENVIRONMENT_LABEL;
  protected readonly statuses = Object.keys(STATUS_LABEL) as ScanStatus[];
  protected readonly environments = Object.keys(ENVIRONMENT_LABEL) as ScanEnvironment[];

  protected scans: Scan[] = [];
  protected objectiveOptions: { key: string; label: string }[] = [];
  protected filters: HistoryFilters = { ...EMPTY_FILTERS, ...this.drafts.load<HistoryFilters>('history-filters') };
  protected isLoading = true;
  protected loadError: string | null = null;

  ngOnInit(): void {
    this.scanService.listScans().subscribe({
      next: (scans) => {
        this.scans = scans;
        const seen = new Map(scans.map((s) => [s.objective, s.objectiveLabel]));
        this.objectiveOptions = [...seen].map(([key, label]) => ({ key, label })).sort((a, b) => a.label.localeCompare(b.label));
        this.isLoading = false;
      },
      error: (error: ApiError) => {
        this.loadError = error.message;
        this.isLoading = false;
      },
    });
  }

  protected get visible(): Scan[] {
    return filterScans(this.scans, this.filters);
  }

  protected get hasFilters(): boolean {
    return Object.values(this.filters).some(Boolean);
  }

  protected onFilterChange(): void {
    this.drafts.save('history-filters', this.filters);
  }

  protected clearFilters(): void {
    this.filters = { ...EMPTY_FILTERS };
    this.onFilterChange();
  }

  protected duration(scan: Scan): string {
    if (!scan.startedAt || !scan.finishedAt) return '–';
    const seconds = Math.round((new Date(scan.finishedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000);
    return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}min ${seconds % 60}s`;
  }
}
