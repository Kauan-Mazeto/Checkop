import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { catchError, forkJoin, of } from 'rxjs';
import { ApiError } from '../../core/http/api-error';
import { AuthService, AuthUser, UserRole } from '../../core/services/auth.service';
import { Finding, Scan, ScanService, ScanStats } from '../../core/services/scan.service';
import { TargetService } from '../../core/services/target.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ChartComponent } from '../../shared/components/chart/chart.component';
import { BAR_OPTIONS, DOUGHNUT_OPTIONS, chartTotal, owaspBar, severityDoughnut } from '../../shared/ui/chart-data';
import { ENVIRONMENT_LABEL, ROLE_LABEL, STATUS_LABEL } from '../../shared/ui/labels';
import { planOf, scansRemainingToday } from '../../shared/ui/plans';
import {
  DevPanelComponent,
  PentesterPanelComponent,
  PlansPanelComponent,
  QaPanelComponent,
  RolePanel,
  StudentPanelComponent,
} from './role-panels';

// Cada perfil vê UM painel extra além do núcleo comum (RF-11). ADM usa o de Dev.
export const ROLE_PANEL: Record<UserRole, RolePanel> = {
  QA: 'qa',
  DEV: 'dev',
  PENTESTER: 'pentester',
  STUDENT: 'student',
  ADM: 'dev',
};

// Os painéis leem os achados das varreduras concluídas mais recentes.
// O backend não tem um endpoint que agregue achados de todas as varreduras.
const FINDINGS_FROM_LAST = 5;

@Component({
  selector: 'app-dashboard-page',
  standalone: true,
  imports: [
    CommonModule,
    RouterLink,
    AppShellComponent,
    ChartComponent,
    QaPanelComponent,
    DevPanelComponent,
    PentesterPanelComponent,
    StudentPanelComponent,
    PlansPanelComponent,
  ],
  templateUrl: './Dashboard-page.component.html',
  styleUrl: './Dashboard-page.component.scss',
})
export class DashboardPageComponent implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly scanService = inject(ScanService);
  private readonly targetService = inject(TargetService);

  protected readonly statusLabel = STATUS_LABEL;
  protected readonly environmentLabel = ENVIRONMENT_LABEL;
  protected readonly roleLabel = ROLE_LABEL;
  protected readonly doughnutOptions = DOUGHNUT_OPTIONS as ChartOptions;
  protected readonly barOptions = BAR_OPTIONS as ChartOptions;
  protected readonly chartTotal = chartTotal;

  protected user: AuthUser | null = this.auth.getCachedUser();
  protected readonly plan = planOf(this.user);
  protected readonly panel: RolePanel = ROLE_PANEL[this.user?.role ?? 'STUDENT'];

  protected scans: Scan[] = [];
  protected findings: Finding[] = [];
  protected stats: ScanStats | null = null;
  protected verifiedTargets = 0;
  protected isLoading = true;
  protected loadError: string | null = null;

  // começam vazios para os cartões dos gráficos aparecerem já no carregamento
  protected severityChart: ChartData = severityDoughnut({}) as ChartData;
  protected owaspChart: ChartData = owaspBar({}) as ChartData;

  ngOnInit(): void {
    forkJoin({
      scans: this.scanService.listScans(),
      stats: this.scanService.getStats(),
      targets: this.targetService.listTargets(),
    }).subscribe({
      next: ({ scans, stats, targets }) => {
        this.scans = scans;
        this.stats = stats;
        this.verifiedTargets = targets.filter((t) => t.verified).length;
        this.severityChart = severityDoughnut(stats.findings.bySeverity) as ChartData;
        this.owaspChart = owaspBar(stats.findings.byOwaspCategory) as ChartData;
        this.isLoading = false;
        this.loadFindings(scans);
      },
      error: (error: ApiError) => {
        this.loadError = error.message;
        this.isLoading = false;
      },
    });
  }

  private loadFindings(scans: Scan[]): void {
    const completed = scans.filter((s) => s.status === 'COMPLETED' && s.findingsCount > 0).slice(0, FINDINGS_FROM_LAST);
    if (completed.length === 0) return;

    // uma varredura que falhar ao carregar não derruba os painéis
    forkJoin(completed.map((s) => this.scanService.getScan(s.id).pipe(catchError(() => of(null))))).subscribe(
      (details) => (this.findings = details.flatMap((d) => d?.findings ?? []))
    );
  }

  protected get firstName(): string {
    return this.user?.name.split(' ')[0] ?? '';
  }

  protected get runningScans(): number {
    return this.scans.filter((scan) => scan.status === 'RUNNING').length;
  }

  protected get highRiskFindings(): number {
    const bySeverity = this.stats?.findings.bySeverity ?? {};
    return (bySeverity['CRITICAL'] ?? 0) + (bySeverity['HIGH'] ?? 0);
  }

  /** null = ilimitado */
  protected get remainingToday(): number | null {
    return scansRemainingToday(this.plan, this.scans);
  }

  protected get recentScans(): Scan[] {
    return this.scans.slice(0, 6);
  }
}
