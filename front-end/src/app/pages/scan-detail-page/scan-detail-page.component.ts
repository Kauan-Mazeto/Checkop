import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { ApiError } from '../../core/http/api-error';
import { AuthService } from '../../core/services/auth.service';
import { Finding, FindingSeverity, ScanComparison, ScanDetail, ScanObjective, ScanService, ZapAuthOptions, hasResults } from '../../core/services/scan.service';
import { RoleView, roleView } from '../../shared/ui/role-views';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ChartComponent } from '../../shared/components/chart/chart.component';
import { CheckComponent } from '../../shared/components/check/check.component';
import { BAR_OPTIONS, DOUGHNUT_OPTIONS, countBar, owaspBar, severityDoughnut } from '../../shared/ui/chart-data';
import { ENVIRONMENT_LABEL, SEVERITY_LABEL, SEVERITY_ORDER, STATUS_LABEL, TOOL_LABEL, owaspExplanation, CVSS_SOURCE_LABEL, CONFIDENCE_LABEL } from '../../shared/ui/labels';
import {
  ComplianceGroup,
  countBy,
  elapsed,
  exportFileName,
  filterBySeverity,
  groupCompliance,
  EvidenceItem,
  evidenceItems,
  hasEvidence,
  locationsOf,
  sortBySeverity,
} from './scan-detail.logic';

type Tab = 'overview' | 'findings' | 'evidence' | 'compliance' | 'compare';

const POLL_INTERVAL_MS = 5000;

@Component({
  selector: 'app-scan-detail-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, AppShellComponent, ChartComponent, CheckComponent],
  templateUrl: './scan-detail-page.component.html',
  styleUrl: './scan-detail-page.component.scss',
})
export class ScanDetailPageComponent implements OnInit, OnDestroy {
  private readonly route = inject(ActivatedRoute);
  private readonly scanService = inject(ScanService);
  private readonly auth = inject(AuthService);

  protected readonly severityLabel = SEVERITY_LABEL;
  protected readonly severityOrder = SEVERITY_ORDER;
  protected readonly statusLabel = STATUS_LABEL;
  protected readonly environmentLabel = ENVIRONMENT_LABEL;
  protected readonly toolLabel = TOOL_LABEL;
  protected readonly owaspExplanation = owaspExplanation;
  protected readonly hasEvidence = hasEvidence;
  protected readonly locationsOf = locationsOf;
  protected readonly hasResults = hasResults;

  // cancelamento: as ferramentas param e o que já foi verificado vira resultado parcial
  protected isCanceling = false;
  /** primeiro clique pede confirmação no próprio cartão (sem pop-up do navegador) */
  protected confirmingCancel = false;
  protected cancelMessage: string | null = null;
  protected cancelError: string | null = null;

  protected cancel(): void {
    if (!this.scan || this.isCanceling) return;
    this.confirmingCancel = false;
    this.isCanceling = true;
    this.cancelError = null;
    this.scanService.cancelScan(this.scan.id).subscribe({
      next: (r) => {
        this.cancelMessage = r.message;
        this.load(); // o polling segue até a varredura ficar como cancelada
      },
      error: (error: ApiError) => {
        this.isCanceling = false;
        this.cancelError = error.message;
      },
    });
  }
  protected readonly cvssSourceLabel = CVSS_SOURCE_LABEL;
  protected readonly confidenceLabel = CONFIDENCE_LABEL;
  protected readonly doughnutOptions = DOUGHNUT_OPTIONS as ChartOptions;
  protected readonly barOptions = BAR_OPTIONS as ChartOptions;
  // RF-11: formato do relatório pelo perfil (o servidor confirma o perfil em scan.role)
  protected view: RoleView = roleView(this.auth.getCachedUser()?.role);
  private viewApplied = false;

  protected get isStudent(): boolean {
    return this.view.explanations;
  }
  protected readonly today = new Date();

  private scanId = '';
  private pollTimer?: ReturnType<typeof setInterval>;
  private clockTimer?: ReturnType<typeof setInterval>;

  protected scan: ScanDetail | null = null;
  private objectives: ScanObjective[] = [];
  protected isLoading = true;
  protected loadError: string | null = null;
  protected now = Date.now();

  protected tab: Tab = 'overview';
  protected severityFilter: FindingSeverity | 'ALL' = 'ALL';
  protected expanded = new Set<string>();

  protected sortedFindings: Finding[] = [];
  protected complianceGroups: ComplianceGroup[] = [];
  protected severityChart: ChartData | null = null;
  protected toolChart: ChartData | null = null;
  protected owaspChart: ChartData | null = null;

  // opções de execução (espelham runScanAuthSchema)
  protected useAjaxSpider = false;
  protected useAuth = false;
  protected authOptions: ZapAuthOptions = { loginUrl: '', usernameField: 'email', passwordField: 'password', username: '', password: '' };
  protected activeScanConfirmed = false;
  protected hostingTermsConfirmed = false;
  protected isStarting = false;
  protected runError: ApiError | null = null;

  // RF-19: comparação com uma varredura anterior (carregada ao abrir a aba)
  protected comparison: ScanComparison | null = null;
  protected compareBaseId: string | null = null;
  protected isComparing = false;
  protected compareError: string | null = null;

  protected openCompare(): void {
    this.tab = 'compare';
    if (!this.comparison && !this.isComparing && this.isPremium) this.loadComparison();
  }

  protected loadComparison(withId: string | null = null): void {
    if (!this.scan) return;
    this.isComparing = true;
    this.compareError = null;
    this.scanService.compareScan(this.scan.id, withId).subscribe({
      next: (comparison) => {
        this.comparison = comparison;
        this.compareBaseId = comparison.base?.id ?? null;
        this.isComparing = false;
      },
      error: (error: ApiError) => {
        this.compareError = error.message;
        this.isComparing = false;
      },
    });
  }

  ngOnInit(): void {
    this.scanId = this.route.snapshot.paramMap.get('id') ?? '';
    this.scanService.getObjectives().subscribe({
      next: (objectives) => (this.objectives = objectives),
      error: () => undefined, // só enriquece a tela; o detalhe funciona sem
    });
    this.load();
  }

  ngOnDestroy(): void {
    this.stopPolling();
  }

  // ---------- estado derivado ----------

  protected get isPublic(): boolean {
    return this.scan?.environment !== 'DEVELOPMENT';
  }

  protected get canRun(): boolean {
    return this.scan?.status === 'PENDING' || this.scan?.status === 'FAILED';
  }

  protected get objective(): ScanObjective | null {
    return this.objectives.find((o) => o.key === this.scan?.objective) ?? null;
  }

  protected get requiresActive(): boolean {
    return Boolean(this.objective?.requiresActiveScan);
  }

  /** Objetivo de ataque em site público só roda com as duas declarações (backend: ACTIVE_SCAN_REQUIRED). */
  protected get runBlockedReason(): string | null {
    if (this.isPublic && this.activeScanConfirmed && !this.hostingTermsConfirmed) {
      return 'Confirme também a declaração sobre o provedor de hospedagem.';
    }
    if (this.isPublic && this.requiresActive && !this.activeScanConfirmed) {
      return 'Este tipo de falha só é detectado com a varredura ativa: autorize-a acima.';
    }
    if (this.useAuth && (!this.authOptions.loginUrl || !this.authOptions.username || !this.authOptions.password)) {
      return 'Preencha a URL de login, o usuário e a senha de teste, ou desmarque o login.';
    }
    return null;
  }

  protected get visibleFindings(): Finding[] {
    return filterBySeverity(this.sortedFindings, this.severityFilter);
  }

  // calculada uma vez por carga (em derive). Como getter, gerava objetos novos a
  // cada verificação do Angular e o *ngFor recriava todos os cartões de PoC sem
  // parar, travando a aba
  protected evidenceFindings: EvidenceItem[] = [];

  protected get elapsedTime(): string {
    return elapsed(this.scan?.startedAt ?? null, this.now);
  }

  /** plano vem do backend junto com o detalhe; o corte dos dados é feito lá */
  protected get isPremium(): boolean {
    return (this.scan?.plan ?? this.auth.getCachedUser()?.plan) === 'PREMIUM';
  }

  protected get worstSeverity(): FindingSeverity | 'NONE' {
    return this.sortedFindings[0]?.severity ?? 'NONE';
  }

  // ---------- ações ----------

  protected run(): void {
    if (!this.scan || this.isStarting || this.runBlockedReason) return;
    this.isStarting = true;
    this.runError = null;

    this.scanService
      .runScan(this.scan.id, {
        useAjaxSpider: this.useAjaxSpider,
        auth: this.useAuth ? this.authOptions : undefined,
        activeScanConfirmed: this.isPublic ? this.activeScanConfirmed : undefined,
        hostingTermsConfirmed: this.isPublic ? this.hostingTermsConfirmed : undefined,
      })
      .subscribe({
        next: () => {
          this.isStarting = false;
          this.load();
        },
        error: (error: ApiError) => {
          this.isStarting = false;
          this.runError = error;
        },
      });
  }

  protected toggle(finding: Finding): void {
    this.expanded.has(finding.id) ? this.expanded.delete(finding.id) : this.expanded.add(finding.id);
  }

  protected countOf(severity: FindingSeverity): number {
    return this.scan?.summary.severityCounts[severity] ?? 0;
  }

  /**
   * RF-12: relatório em PDF pela impressão do navegador ("Salvar como PDF").
   * O @media print esconde o menu e mostra a seção .print-report.
   */
  protected exportPdf(): void {
    if (!this.isPremium) return; // relatório é recurso Premium (shared/ui/plans.ts)
    this.expanded = new Set(this.sortedFindings.map((f) => f.id));
    setTimeout(() => window.print());
  }

  /** RF-12: relatório completo em JSON, como o usuário vê na tela. */
  protected exportJson(): void {
    if (!this.scan || !this.isPremium) return;
    const blob = new Blob([JSON.stringify(this.scan, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = exportFileName(this.scan.targetUrl);
    anchor.click();
    URL.revokeObjectURL(url);
  }

  protected load(): void {
    this.scanService.getScan(this.scanId).subscribe({
      next: (scan) => {
        this.scan = scan;
        this.isLoading = false;
        this.applyRoleView(scan);
        this.loadError = null;
        this.derive(scan);
        scan.status === 'RUNNING' ? this.startPolling() : this.stopPolling();
      },
      error: (error: ApiError) => {
        this.isLoading = false;
        this.loadError = error.message;
        this.stopPolling();
      },
    });
  }

  // ---------- internos ----------

  /** Na primeira carga, abre a aba e os achados que o perfil prioriza (RF-11). */
  private applyRoleView(scan: ScanDetail): void {
    if (scan.role) this.view = roleView(scan.role);
    if (this.viewApplied || !hasResults(scan.status)) return;
    this.viewApplied = true;
    const wantsEvidence = this.view.defaultTab === 'evidence';
    // evidência só faz sentido se o plano e o perfil a recebem e se ela existe
    this.tab = wantsEvidence && !scan.findings.some(hasEvidence) ? 'findings' : this.view.defaultTab;
    if (this.view.expandHighRisk) {
      this.expanded = new Set(scan.findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').map((f) => f.id));
    }
  }

  private derive(scan: ScanDetail): void {
    this.sortedFindings = sortBySeverity(scan.findings);
    this.evidenceFindings = evidenceItems(this.sortedFindings);
    this.complianceGroups = groupCompliance(scan.findings);
    this.severityChart = severityDoughnut(scan.summary.severityCounts) as ChartData;
    this.toolChart = countBar(countBy(scan.findings, (f) => f.tool)) as ChartData;
    this.owaspChart = owaspBar(countBy(scan.findings, (f) => f.owaspUrl)) as ChartData;
  }

  private startPolling(): void {
    if (this.pollTimer) return;
    this.pollTimer = setInterval(() => this.load(), POLL_INTERVAL_MS);
    this.clockTimer = setInterval(() => (this.now = Date.now()), 1000);
  }

  private stopPolling(): void {
    clearInterval(this.pollTimer);
    clearInterval(this.clockTimer);
    this.pollTimer = undefined;
    this.clockTimer = undefined;
  }
}
