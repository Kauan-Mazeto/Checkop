import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError } from '../../core/http/api-error';
import { AuthService } from '../../core/services/auth.service';
import { DraftService } from '../../core/services/draft.service';
import { Scan, ScanEnvironment, ScanService, ScanStatus } from '../../core/services/scan.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ENVIRONMENT_LABEL, STATUS_LABEL } from '../../shared/ui/labels';
import { planOf } from '../../shared/ui/plans';

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

export interface DayGroup {
  /** "Hoje", "Ontem" ou "24 de novembro" */
  label: string;
  scans: Scan[];
}

const MONTHS = ['janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho', 'julho', 'agosto', 'setembro', 'outubro', 'novembro', 'dezembro'];

/** Agrupa por dia (a lista já vem da mais recente para a mais antiga). */
export const groupByDay = (scans: Scan[], now = new Date()): DayGroup[] => {
  const dayKey = (d: Date) => `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
  const today = dayKey(now);
  const yesterday = dayKey(new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1));
  const groups: DayGroup[] = [];
  let currentKey = '';
  for (const scan of scans) {
    const date = new Date(scan.createdAt);
    const key = dayKey(date);
    if (key !== currentKey) {
      currentKey = key;
      const label = key === today ? 'Hoje' : key === yesterday ? 'Ontem'
        : `${date.getDate()} de ${MONTHS[date.getMonth()]}${date.getFullYear() !== now.getFullYear() ? ` de ${date.getFullYear()}` : ''}`;
      groups.push({ label, scans: [] });
    }
    groups[groups.length - 1].scans.push(scan);
  }
  return groups;
};

@Component({
  selector: 'app-scan-history-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, AppShellComponent],
  templateUrl: './scan-history-page.component.html',
  styleUrl: './scan-history-page.component.scss',
})
export class ScanHistoryPageComponent implements OnInit {
  private readonly scanService = inject(ScanService);
  private readonly drafts = inject(DraftService);

  // Free: o backend devolve só a varredura mais recente (sem histórico)
  protected readonly plan = planOf(inject(AuthService).getCachedUser());
  protected readonly statusLabel = STATUS_LABEL;
  protected readonly environmentLabel = ENVIRONMENT_LABEL;
  protected readonly statuses = Object.keys(STATUS_LABEL) as ScanStatus[];
  protected readonly environments = Object.keys(ENVIRONMENT_LABEL) as ScanEnvironment[];

  protected scans: Scan[] = [];
  protected objectiveOptions: { key: string; label: string }[] = [];
  protected filters: HistoryFilters = { ...EMPTY_FILTERS, ...this.drafts.load<HistoryFilters>('history-filters') };
  protected isLoading = true;
  protected loadError: string | null = null;

  /** lista filtrada e agrupada por dia (campos, não getters: o *ngFor não recria as linhas) */
  protected visible: Scan[] = [];
  protected days: DayGroup[] = [];
  /** faixa de números do topo, por status */
  protected counts: Record<ScanStatus, number> = { PENDING: 0, RUNNING: 0, COMPLETED: 0, CANCELED: 0, FAILED: 0 };
  /** status nas abas do filtro (o pendente vai junto de "todas") */
  protected readonly statusTabs: ScanStatus[] = ['COMPLETED', 'RUNNING', 'CANCELED', 'FAILED'];

  ngOnInit(): void {
    this.scanService.listScans().subscribe({
      next: (scans) => {
        this.scans = scans;
        const seen = new Map(scans.map((s) => [s.objective, s.objectiveLabel]));
        this.objectiveOptions = [...seen].map(([key, label]) => ({ key, label })).sort((a, b) => a.label.localeCompare(b.label));
        this.counts = { PENDING: 0, RUNNING: 0, COMPLETED: 0, CANCELED: 0, FAILED: 0 };
        for (const scan of scans) this.counts[scan.status]++;
        this.refresh();
        this.isLoading = false;
      },
      error: (error: ApiError) => {
        this.loadError = error.message;
        this.isLoading = false;
      },
    });
  }

  private refresh(): void {
    // sem histórico os filtros ficam ocultos; um filtro salvo não pode esconder o último scan
    this.visible = this.plan.canViewHistory ? filterScans(this.scans, this.filters) : this.scans;
    this.days = groupByDay(this.visible);
  }

  protected get hasFilters(): boolean {
    return Object.values(this.filters).some(Boolean);
  }

  protected setStatus(status: ScanStatus | ''): void {
    this.filters = { ...this.filters, status };
    this.onFilterChange();
  }

  protected onFilterChange(): void {
    this.drafts.save('history-filters', this.filters);
    this.refresh();
  }

  protected trackById(_: number, scan: Scan): string {
    return scan.id;
  }

  protected hasResults(scan: Scan): boolean {
    return scan.status === 'COMPLETED' || scan.status === 'CANCELED';
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
