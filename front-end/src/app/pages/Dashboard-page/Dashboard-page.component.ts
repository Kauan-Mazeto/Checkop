import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { catchError, forkJoin, of } from 'rxjs';
import { ApiError } from '../../core/http/api-error';
import { AuthService, AuthUser, UserRole } from '../../core/services/auth.service';
import { ExportFormat, Finding, Scan, ScanService, ScanStats } from '../../core/services/scan.service';
import { TargetService } from '../../core/services/target.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import {
  BAR_OPTIONS,
  DOUGHNUT_OPTIONS,
  LINE_OPTIONS,
  TriageRun,
  chartTotal,
  confidenceDoughnut,
  countBar,
  endpointsBar,
  owaspBar,
  scansPerDay,
  severityDoughnut,
  timelineLine,
  triageDoughnut,
  triageRunOf,
} from '../../shared/ui/chart-data';
import { ReportCarouselComponent, ReportSlide } from '../../shared/components/report-carousel/report-carousel.component';
import { topTypes } from './role-panels';
import { CodeReportComponent } from './code-report';
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
import {
  FindingRow,
  LearnReportComponent,
  ProgressReportComponent,
  RiskReportComponent,
  ScansReportComponent,
  TargetsReportComponent,
} from './report-tabs';

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

/** Abas do Painel: cada uma cabe numa tela, em vez de uma página longa. */
export type DashboardView = 'overview' | 'code' | 'risk' | 'scans' | 'targets' | 'learn' | 'progress' | 'role' | 'plan';

/**
 * Abas de cada perfil (RF-11): cada um vê só os relatórios do trabalho dele.
 * Dev: o que corrigir no código ("Correções"); QA e Pentester: riscos, alvos e
 * varreduras; Estudante: aprender e acompanhar o próprio progresso. Dev e Estudante
 * têm ainda a aba exclusiva da análise de código. Admin vê tudo.
 */
export const TABS_BY_ROLE: Record<UserRole, DashboardView[]> = {
  QA: ['overview', 'risk', 'scans', 'targets', 'role', 'plan'],
  PENTESTER: ['overview', 'risk', 'targets', 'scans', 'role', 'plan'],
  DEV: ['overview', 'code', 'risk', 'targets', 'scans', 'role', 'plan'],
  STUDENT: ['overview', 'code', 'learn', 'progress', 'role', 'plan'],
  ADM: ['overview', 'code', 'risk', 'scans', 'targets', 'learn', 'progress', 'role', 'plan'],
};

const tabLabel = (view: DashboardView, role: UserRole): string =>
  ({
    overview: 'Visão geral',
    code: 'Análise de código',
    risk: role === 'DEV' ? 'Correções' : 'Riscos',
    scans: 'Varreduras',
    targets: 'Alvos',
    learn: 'Aprender',
    progress: 'Seu progresso',
    role: `Painel de ${ROLE_LABEL[role]}`,
    plan: 'Seu plano',
  })[view];
const VIEW_KEY = 'checkop.dashboard.view';

@Component({
  selector: 'app-dashboard-page',
  standalone: true,
  imports: [
    CommonModule,
    RouterLink,
    AppShellComponent,
    QaPanelComponent,
    DevPanelComponent,
    PentesterPanelComponent,
    StudentPanelComponent,
    PlansPanelComponent,
    RiskReportComponent,
    ScansReportComponent,
    TargetsReportComponent,
    LearnReportComponent,
    ProgressReportComponent,
    ReportCarouselComponent,
    CodeReportComponent,
  ],
  templateUrl: './Dashboard-page.component.html',
  styleUrl: './Dashboard-page.component.scss',
})
export class DashboardPageComponent implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly scanService = inject(ScanService);
  private readonly targetService = inject(TargetService);
  private readonly route = inject(ActivatedRoute);

  protected readonly statusLabel = STATUS_LABEL;
  protected readonly environmentLabel = ENVIRONMENT_LABEL;
  protected readonly roleLabel = ROLE_LABEL;
  protected readonly doughnutOptions = DOUGHNUT_OPTIONS as ChartOptions;
  protected readonly barOptions = BAR_OPTIONS as ChartOptions;
  protected readonly lineOptions = LINE_OPTIONS as ChartOptions;
  protected readonly chartTotal = chartTotal;

  protected readonly role: UserRole = this.auth.getCachedUser()?.role ?? 'STUDENT';
  /** abas do perfil, na ordem em que aparecem */
  protected readonly tabs: { id: DashboardView; label: string }[] = TABS_BY_ROLE[this.role].map((id) => ({ id, label: tabLabel(id, this.role) }));

  /** aba aberta; lembrada no navegador (só conveniência: sem ela, abre a visão geral) */
  protected view: DashboardView = this.readView();

  protected setView(view: DashboardView): void {
    this.view = view;
    try {
      localStorage.setItem(VIEW_KEY, view);
    } catch {
      // navegação privada ou armazenamento bloqueado: só não lembra a aba
    }
  }

  private readView(): DashboardView {
    // link de outra tela abre uma aba direto: /dashboard?aba=code
    const asked = this.route.snapshot.queryParamMap.get('aba') as DashboardView | null;
    if (asked && TABS_BY_ROLE[this.role].includes(asked)) return asked;
    try {
      // aba lembrada de outro perfil (trocou de perfil na Conta) não vale: volta à visão geral
      const saved = localStorage.getItem(VIEW_KEY) as DashboardView | null;
      return saved && TABS_BY_ROLE[this.role].includes(saved) ? saved : 'overview';
    } catch {
      return 'overview';
    }
  }

  protected user: AuthUser | null = this.auth.getCachedUser();
  protected readonly plan = planOf(this.user);
  protected readonly panel: RolePanel = ROLE_PANEL[this.user?.role ?? 'STUDENT'];

  protected scans: Scan[] = [];
  protected findings: Finding[] = [];
  /** os mesmos achados, com a varredura e o site de onde vieram (abas Riscos e Alvos) */
  protected findingRows: FindingRow[] = [];
  /** quantas varreduras concluídas alimentam os achados */
  protected scansWithFindings = 0;
  /** abertos × corrigidos × descartados de cada uma dessas varreduras (painel de QA) */
  protected triageRuns: TriageRun[] = [];
  protected stats: ScanStats | null = null;
  protected verifiedTargets = 0;
  protected isLoading = true;
  protected loadError: string | null = null;

  // começam vazios para os cartões dos gráficos aparecerem já no carregamento
  protected severityChart: ChartData = severityDoughnut({}) as ChartData;
  protected owaspChart: ChartData = owaspBar({}) as ChartData;
  protected timelineChart: ChartData = timelineLine({}) as ChartData;

  // ---------- cards com vários relatórios (setas e bolinhas) da visão geral ----------
  protected riskSlides: ReportSlide[] = [];
  protected trendSlides: ReportSlide[] = [];
  protected breakdownSlides: ReportSlide[] = [];

  /** Monta os relatórios dos cards; refeito quando chegam as estatísticas e quando chegam os achados. */
  private buildSlides(): void {
    const doughnut = DOUGHNUT_OPTIONS as ChartOptions;
    const bar = BAR_OPTIONS as ChartOptions;
    const line = LINE_OPTIONS as ChartOptions;
    const scope = this.plan.canViewHistory ? 'todas as varreduras' : 'varredura mais recente';
    const recent = `${this.scansWithFindings} varreduras mais recentes`;
    const triage = triageDoughnut(this.stats?.findings.byStatus ?? {}) as ChartData;
    const confidence = confidenceDoughnut(this.findings) as ChartData;
    this.riskSlides = [
      { title: 'Falhas por severidade', subtitle: scope, type: 'doughnut', data: this.severityChart, options: doughnut, empty: chartTotal(this.severityChart) === 0, ariaLabel: 'Falhas por severidade' },
      { title: 'Status da correção', subtitle: 'abertos × corrigidos', type: 'doughnut', data: triage, options: doughnut, empty: chartTotal(triage) === 0,
        emptyText: 'Marque achados como corrigidos ou falso positivo para acompanhar aqui.', ariaLabel: 'Achados por status da correção' },
      { title: 'Confiança dos achados', subtitle: recent, type: 'doughnut', data: confidence, options: doughnut, empty: this.findings.length === 0, ariaLabel: 'Achados por confiança da ferramenta' },
    ];

    const perDay = timelineLine(scansPerDay(this.scans)) as ChartData;
    perDay.datasets[0].label = 'Varreduras';
    this.trendSlides = [
      { title: 'Achados nos últimos 30 dias', subtitle: 'achados por dia', type: 'line', data: this.timelineChart, options: line, empty: chartTotal(this.timelineChart) === 0,
        emptyText: 'A tendência aparece depois das primeiras varreduras.', ariaLabel: 'Achados por dia nos últimos 30 dias' },
      { title: 'Varreduras nos últimos 30 dias', subtitle: 'varreduras por dia', type: 'line', data: perDay, options: line, empty: this.scans.length === 0, ariaLabel: 'Varreduras por dia nos últimos 30 dias' },
    ];

    const types = countBar(Object.fromEntries(topTypes(this.findings, 10).map((t) => [t.title, t.count])), (k) => k) as ChartData;
    const endpoints = endpointsBar(this.findings, 10) as ChartData;
    const tools = countBar(this.stats?.findings.byTool ?? {}) as ChartData;
    this.breakdownSlides = [
      { title: 'Categorias OWASP Top 10', subtitle: 'onde estão as falhas', type: 'bar', data: this.owaspChart, options: bar, empty: chartTotal(this.owaspChart) === 0, ariaLabel: 'Achados por categoria OWASP' },
      { title: 'Tipos de falha mais frequentes', subtitle: recent, type: 'bar', data: types, options: bar, empty: chartTotal(types) === 0, ariaLabel: 'Achados por tipo de falha' },
      { title: 'Endpoints com mais achados', subtitle: 'superfície de ataque', type: 'bar', data: endpoints, options: bar, empty: chartTotal(endpoints) === 0, ariaLabel: 'Achados por endpoint' },
      { title: 'Achados por ferramenta', subtitle: 'quem encontrou', type: 'bar', data: tools, options: bar, empty: chartTotal(tools) === 0, ariaLabel: 'Achados por ferramenta' },
    ];
  }

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
        this.timelineChart = timelineLine(stats.findings.timelineLast30Days ?? {}) as ChartData;
        this.buildSlides();
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
    const completed = scans.filter((s) => (s.status === 'COMPLETED' || s.status === 'CANCELED') && s.findingsCount > 0).slice(0, FINDINGS_FROM_LAST);
    this.scansWithFindings = completed.length;
    if (completed.length === 0) return;

    // uma varredura que falhar ao carregar não derruba os painéis
    forkJoin(completed.map((s) => this.scanService.getScan(s.id).pipe(catchError(() => of(null))))).subscribe((details) => {
      // a mesma falha no mesmo site, vista em várias varreduras, entra uma vez só: a da
      // mais recente (a lista de varreduras já vem da mais nova para a mais antiga).
      // Em sites diferentes são problemas diferentes e continuam separados.
      // triagem de cada varredura, ANTES de tirar as repetidas (cada varredura tem a sua)
      this.triageRuns = details
        .map((detail, i) => (detail ? triageRunOf(completed[i], detail.findings ?? []) : null))
        .filter((run): run is TriageRun => run !== null);

      const seen = new Set<string>();
      this.findingRows = details.flatMap((detail) =>
        (detail?.findings ?? [])
          .filter((finding) => {
            const key = `${detail!.targetUrl}::${finding.title.trim().toLowerCase()}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
          })
          .map((finding) => ({ finding, scanId: detail!.id, targetUrl: detail!.targetUrl })),
      );
      this.findings = this.findingRows.map((row) => row.finding);
      this.buildSlides();
    });
  }

  // exportação consolidada (Premium)
  protected isExporting = false;
  protected exportError: string | null = null;

  protected exportAll(format: ExportFormat, menu: HTMLDetailsElement): void {
    if (this.isExporting) return;
    menu.open = false;
    this.isExporting = true;
    this.exportError = null;
    this.scanService.exportAll(format).subscribe({
      next: (blob) => {
        this.isExporting = false;
        const extension = format === 'json' ? 'json' : 'csv';
        const name = { 'findings-csv': 'achados', 'scans-csv': 'varreduras', json: 'relatorio-completo' }[format];
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `checkop-${name}-${new Date().toISOString().slice(0, 10)}.${extension}`;
        anchor.click();
        URL.revokeObjectURL(url);
      },
      error: (error: ApiError) => {
        this.isExporting = false;
        this.exportError = error.message;
      },
    });
  }

  protected get firstName(): string {
    return this.user?.name.split(' ')[0] ?? '';
  }

  protected get runningScans(): number {
    return this.scans.filter((scan) => scan.status === 'RUNNING').length;
  }

  /**
   * Críticas e altas AINDA ABERTAS (corrigido, falso positivo e ignorado não contam).
   * Com os achados carregados, conta por eles (a mesma falha em várias varreduras do
   * mesmo site entra uma vez); antes disso, a estatística geral.
   */
  protected get highRiskFindings(): number {
    if (this.findingRows.length > 0) {
      return this.findings.filter(
        (f) => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && (!f.status || f.status === 'OPEN'),
      ).length;
    }
    const bySeverity = this.stats?.findings.bySeverity ?? {};
    return (bySeverity['CRITICAL'] ?? 0) + (bySeverity['HIGH'] ?? 0);
  }

  /** null = ilimitado */
  protected get remainingToday(): number | null {
    return scansRemainingToday(this.plan, this.scans);
  }

  protected get recentScans(): Scan[] {
    return this.scans.slice(0, 5);
  }

  protected trackById(_: number, scan: Scan): string {
    return scan.id;
  }

  protected hasResults(scan: Scan): boolean {
    return scan.status === 'COMPLETED' || scan.status === 'CANCELED';
  }
}
