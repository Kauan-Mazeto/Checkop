import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { forkJoin } from 'rxjs';
import { ApiError } from '../../core/http/api-error';
import { AuthService, AuthUser, UserRole } from '../../core/services/auth.service';
import { Scan, ScanService, ScanStats } from '../../core/services/scan.service';
import { TargetService } from '../../core/services/target.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ChartComponent } from '../../shared/components/chart/chart.component';
import {
  BAR_OPTIONS,
  DOUGHNUT_OPTIONS,
  LINE_OPTIONS,
  chartTotal,
  countBar,
  owaspBar,
  severityDoughnut,
  timelineLine,
} from '../../shared/ui/chart-data';
import { ENVIRONMENT_LABEL, STATUS_LABEL } from '../../shared/ui/labels';

// Cada perfil vê UM bloco extra além do núcleo comum (RF-11).
type RoleWidget = 'reports' | 'alerts' | 'logs' | 'learning';

const ROLE_WIDGET: Record<UserRole, RoleWidget> = {
  QA: 'reports',
  DEV: 'alerts',
  PENTESTER: 'logs',
  STUDENT: 'learning',
  ADM: 'alerts',
};

const STATUS_COLOR = '#6aa6f8';

@Component({
  selector: 'app-dashboard-page',
  standalone: true,
  imports: [CommonModule, RouterLink, AppShellComponent, ChartComponent],
  templateUrl: './Dashboard-page.component.html',
  styleUrl: './Dashboard-page.component.scss',
})
export class DashboardPageComponent implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly scanService = inject(ScanService);
  private readonly targetService = inject(TargetService);

  protected readonly statusLabel = STATUS_LABEL;
  protected readonly environmentLabel = ENVIRONMENT_LABEL;
  protected readonly doughnutOptions = DOUGHNUT_OPTIONS as ChartOptions;
  protected readonly barOptions = BAR_OPTIONS as ChartOptions;
  protected readonly lineOptions = LINE_OPTIONS as ChartOptions;
  protected readonly chartTotal = chartTotal;

  protected user: AuthUser | null = this.auth.getCachedUser();
  protected widget: RoleWidget = ROLE_WIDGET[this.user?.role ?? 'STUDENT'];

  protected scans: Scan[] = [];
  protected stats: ScanStats | null = null;
  protected verifiedTargets = 0;
  protected isLoading = true;
  protected loadError: string | null = null;

  // começam vazios para os cartões dos gráficos aparecerem já no carregamento
  protected severityChart: ChartData = severityDoughnut({}) as ChartData;
  protected timelineChart: ChartData = timelineLine({}) as ChartData;
  protected owaspChart: ChartData = owaspBar({}) as ChartData;
  protected statusChart: ChartData = countBar({}) as ChartData;

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
        this.timelineChart = timelineLine(stats.findings.timelineLast30Days) as ChartData;
        this.owaspChart = owaspBar(stats.findings.byOwaspCategory) as ChartData;
        this.statusChart = countBar(
          stats.scans.byStatus,
          (key) => STATUS_LABEL[key as Scan['status']] ?? key,
          STATUS_COLOR
        ) as ChartData;
        this.isLoading = false;
      },
      error: (error: ApiError) => {
        this.loadError = error.message;
        this.isLoading = false;
      },
    });
  }

  protected get firstName(): string {
    return this.user?.name.split(' ')[0] ?? '';
  }

  protected get isPremium(): boolean {
    return this.user?.plan === 'PREMIUM';
  }

  protected get completedScans(): number {
    return this.scans.filter((scan) => scan.status === 'COMPLETED').length;
  }

  protected get runningScans(): number {
    return this.scans.filter((scan) => scan.status === 'RUNNING').length;
  }

  protected get highRiskFindings(): number {
    const bySeverity = this.stats?.findings.bySeverity ?? {};
    return (bySeverity['CRITICAL'] ?? 0) + (bySeverity['HIGH'] ?? 0);
  }

  protected get totalFindings(): number {
    return this.stats?.findings.total ?? 0;
  }

  protected get recentScans(): Scan[] {
    return this.scans.slice(0, 6);
  }

  protected get flaggedScans(): Scan[] {
    return this.scans.filter((scan) => scan.status === 'FAILED' || scan.suspiciousEnvironment).slice(0, 5);
  }

  protected get completedList(): Scan[] {
    return this.scans.filter((scan) => scan.status === 'COMPLETED').slice(0, 5);
  }
}
