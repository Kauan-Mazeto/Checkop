import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { ApiError } from '../../core/http/api-error';
import { AccountService } from '../../core/services/account.service';
import { AuthService, UserRole } from '../../core/services/auth.service';
import { Finding, FindingSeverity, FindingStatus, ScanComparison, ScanDetail, ScanObjective, ScanService, ZapAuthOptions, hasResults } from '../../core/services/scan.service';
import { ROLE_VIEWS, RoleView, roleView } from '../../shared/ui/role-views';
import {
  CvssPart,
  FlawGuide,
  GuideLink,
  buildTicket,
  cweLink,
  explainCvss,
  fixReferenceLinks,
  guideFor,
  isKnownGuide,
  owaspLink,
  standardLinks,
  summarizeRemediation,
  toolReferenceLinks,
} from './role-guides';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ChartComponent } from '../../shared/components/chart/chart.component';
import { CheckComponent } from '../../shared/components/check/check.component';
import { BAR_OPTIONS, DOUGHNUT_OPTIONS, countBar, owaspBar, severityDoughnut } from '../../shared/ui/chart-data';
import { ENVIRONMENT_LABEL, FINDING_STATUS_LABEL, SEVERITY_LABEL, SEVERITY_ORDER, STATUS_LABEL, TOOL_LABEL, owaspExplanation, CVSS_SOURCE_LABEL, CONFIDENCE_LABEL } from '../../shared/ui/labels';
import {
  ComplianceGroup,
  countBy,
  elapsed,
  exportFileName,
  filterBySeverity,
  groupCompliance,
  EvidenceItem,
  evidenceItems,
  filterByStatus,
  filterFindings,
  findingStatusOf,
  hasEvidence,
  withStatus,
  highlightedLines,
  locationsOf,
  pathOf,
  sortBySeverity,
  stripEvidenceMarks,
  ViewerLine,
} from './scan-detail.logic';

// a evidência fica dentro do achado (sub-aba do painel central), não numa aba própria
type Tab = 'overview' | 'findings' | 'compliance' | 'compare';
/** sub-abas do detalhe do achado (painel central) */
// learn = Estudante, ticket = QA, exploit = Pentester (conteúdo de cada perfil, RF-11)
export type DetailTab = 'fix' | 'evidence' | 'locations' | 'compliance' | 'learn' | 'ticket' | 'exploit';

/** Perfis que o usuário pode escolher na tela (Admin não troca por aqui). */
const SWITCHABLE_ROLES: Exclude<UserRole, 'ADM'>[] = ['DEV', 'QA', 'PENTESTER', 'STUDENT'];
/** abas do visor de evidência */
export type ViewerTab = 'response' | 'request' | 'curl';

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
  private readonly account = inject(AccountService);

  protected readonly severityLabel = SEVERITY_LABEL;
  protected readonly severityOrder = SEVERITY_ORDER;
  protected readonly statusLabel = STATUS_LABEL;
  protected readonly environmentLabel = ENVIRONMENT_LABEL;
  protected readonly toolLabel = TOOL_LABEL;
  protected readonly owaspExplanation = owaspExplanation;
  protected readonly hasEvidence = hasEvidence;
  protected readonly locationsOf = locationsOf;
  protected readonly hasResults = hasResults;
  protected readonly pathOf = pathOf;
  protected readonly findingStatusOf = findingStatusOf;
  protected readonly findingStatusLabel = FINDING_STATUS_LABEL;

  /** botão "Copiar comando" da PoC */
  protected copiedKey: string | null = null;

  protected copyText(value: string | null | undefined, key: string): void {
    if (!value) return;
    navigator.clipboard?.writeText(value).then(() => {
      this.copiedKey = key;
      setTimeout(() => (this.copiedKey = this.copiedKey === key ? null : this.copiedKey), 1500);
    });
  }

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
  /** perfil em vigor (o servidor confirma em scan.role) */
  protected role: UserRole = this.auth.getCachedUser()?.role ?? 'DEV';
  protected readonly switchableRoles = SWITCHABLE_ROLES;
  protected readonly roleViews = ROLE_VIEWS;
  protected isChangingRole = false;
  protected roleError: string | null = null;

  /**
   * Troca o perfil sem sair da tela: salva na conta e recarrega a varredura, porque o
   * servidor corta os dados pelo perfil (ex.: Estudante não recebe payloads).
   */
  protected changeRole(role: Exclude<UserRole, 'ADM'>): void {
    if (this.isChangingRole || role === this.role) return;
    this.isChangingRole = true;
    this.roleError = null;
    this.account.changeRole(role).subscribe({
      next: () => {
        this.isChangingRole = false;
        this.role = role;
        this.view = roleView(role);
        this.viewApplied = false; // a próxima carga reabre na aba e sub-aba do novo perfil
        this.load();
      },
      error: (error: ApiError) => {
        this.isChangingRole = false;
        this.roleError = error.message;
      },
    });
  }

  // ---------- conteúdo do perfil para o achado aberto (calculado ao abrir, não a cada verificação) ----------
  protected guide: FlawGuide | null = null;
  /** Estudante: onde estudar e como corrigir */
  protected studyLinks: GuideLink[] = [];
  /** QA: padrões oficiais que comprovam a falha */
  protected standards: GuideLink[] = [];
  /** QA: texto do ticket pronto para colar */
  protected ticketText = '';
  /** Pentester: vetor CVSS item a item */
  protected cvssParts: CvssPart[] = [];
  /** Pentester: parâmetros atingidos nos locais da falha */
  protected attackParams: string[] = [];

  // ---------- aba "Como corrigir" ----------
  /** o que fazer, em poucos itens: o guia da classe da falha ou o começo do texto da ferramenta */
  protected fixSummary: string[] = [];
  /** o resumo veio do guia do Checkop (true) ou do texto da ferramenta (false) */
  protected fixFromGuide = false;
  /** referências e exemplos de correção (OWASP, ferramenta, CWE) */
  protected fixLinks: GuideLink[] = [];
  /** mostra o texto completo da ferramenta (recolhido por padrão) */
  protected showFullFix = false;
  /** o texto da ferramenta tem mais do que o resumo mostra */
  protected fixHasMore = false;

  /** A aba só existe quando há o que mostrar: paywall, resumo ou referência específica. */
  protected hasFixTab(f: Finding | null): boolean {
    if (!f) return false;
    if (f.premiumLocked) return true;
    return this.fixSummary.length > 0 || (this.guide !== null && isKnownGuide(this.guide)) || toolReferenceLinks(f.references).length > 0;
  }

  /** Trecho da resposta (ou da requisição) que a ferramenta apontou como prova. */
  protected signalOf(e: EvidenceItem | null): string | null {
    const text = `${e?.rawResponse ?? ''}\n${e?.rawRequest ?? ''}`;
    return text.match(/>>> ([\s\S]*?) <<</)?.[1]?.trim() || null;
  }

  /** O que a confiança da ferramenta quer dizer, para quem vai decidir se corrige. */
  protected readonly confidenceNote: Record<string, string> = {
    LOW: 'Confiança baixa: a ferramenta viu só um sinal indireto (por exemplo, um erro 500 depois do ataque), não a prova da falha. Repita a requisição e confira antes de tratar como falha real.',
    MEDIUM: 'Confiança média: o comportamento bate com a falha, mas vale confirmar repetindo a requisição.',
    HIGH: 'Confiança alta: a resposta mostra o comportamento típico da falha.',
    CONFIRMED: 'Confirmado: a resposta bateu com a prova exigida pela regra da ferramenta.',
  };

  /** Sub-aba própria do perfil: só ela aparece (Admin vê as três). */
  protected roleTab(tab: 'learn' | 'ticket' | 'exploit'): boolean {
    const owner = { learn: 'STUDENT', ticket: 'QA', exploit: 'PENTESTER' }[tab];
    return this.role === owner || this.role === 'ADM';
  }

  private buildRoleContent(finding: Finding | null): void {
    if (!finding || !this.scan) {
      this.guide = null;
      this.studyLinks = this.standards = this.cvssParts = [];
      this.attackParams = [];
      this.ticketText = '';
      this.fixSummary = this.fixLinks = [];
      return;
    }
    const guide = guideFor(finding);
    this.guide = guide;
    // correção: o guia da classe (curto e em português) vale mais que o texto genérico da regra
    this.fixFromGuide = isKnownGuide(guide) && guide.fix.length > 0 && !finding.premiumLocked;
    this.fixSummary = finding.premiumLocked ? [] : this.fixFromGuide ? guide.fix : summarizeRemediation(finding.remediation);
    this.fixLinks = finding.premiumLocked ? [] : fixReferenceLinks(finding, guide);
    this.showFullFix = false;
    this.fixHasMore =
      !finding.premiumLocked &&
      Boolean(finding.remediation?.trim()) &&
      (this.fixFromGuide || summarizeRemediation(finding.remediation, 99).length > this.fixSummary.length);
    const unique = (links: (GuideLink | null)[]) =>
      links.filter((l, i, all): l is GuideLink => Boolean(l) && all.findIndex((o) => o?.url === l!.url) === i);
    this.studyLinks = unique([owaspLink(finding.owaspUrl), ...guide.learn, cweLink(guide.cwe)]);
    this.standards = standardLinks(finding, guide);
    this.cvssParts = explainCvss(finding.cvssVector);
    this.attackParams = [...new Set(locationsOf(finding).map((l) => l.parameter).filter((p): p is string => Boolean(p)))];
    const proof = this.selectedEvidence.find((e) => e.reproduction || e.rawResponse);
    const marked = (proof?.rawResponse ?? '').match(/>>> ([\s\S]*?) <<</)?.[1] ?? null;
    this.ticketText = buildTicket({
      finding,
      guide,
      severityLabel: this.severityLabel[finding.severity],
      targetUrl: this.scan.targetUrl,
      environment: this.environmentLabel[this.scan.environment],
      locations: locationsOf(finding).map((l) => [l.affectedUrl, l.parameter && `parâmetro ${l.parameter}`].filter(Boolean).join(' · ')),
      reproduction: proof?.reproduction ?? null,
      evidenceLine: marked,
    });
  }

  /** Requisição HTTP crua da ocorrência aberta, sem os marcadores (para o Burp Repeater). */
  protected get rawRequestText(): string {
    return stripEvidenceMarks(this.currentEvidence?.rawRequest ?? '');
  }

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

  // ---------- painel de achados: lista | detalhe | metadados ----------
  protected query = '';
  /** triagem: Abertos, Corrigidos, Falso positivo, Ignorados ou todos */
  protected statusFilter: FindingStatus | 'ALL' = 'ALL';
  /** ação de triagem em andamento (desabilita os botões) */
  protected statusSaving: FindingStatus | null = null;
  protected statusError: string | null = null;
  /** lista filtrada por severidade e busca (campo, não getter: o *ngFor não recria as linhas) */
  protected filteredFindings: Finding[] = [];
  protected selected: Finding | null = null;
  protected detailTab: DetailTab = 'fix';
  protected viewerTab: ViewerTab = 'response';
  /** ocorrências do achado selecionado que têm requisição/resposta */
  protected selectedEvidence: EvidenceItem[] = [];
  protected occurrenceIndex = 0;
  /** linhas do visor (recalculadas só quando muda o achado, a ocorrência ou a aba) */
  protected viewerLines: ViewerLine[] = [];

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


  // ---------- painel de achados ----------

  protected trackById(_: number, item: { id: string }): string {
    return item.id;
  }

  protected get currentEvidence(): EvidenceItem | null {
    return this.selectedEvidence[this.occurrenceIndex] ?? null;
  }

  /** Texto cru da aba aberta no visor (botão "Copiar"). */
  protected get viewerText(): string {
    return stripEvidenceMarks(this.rawViewerText);
  }

  /** Texto como veio do motor, com a evidência marcada (>>> <<<): base do destaque. */
  private get rawViewerText(): string {
    const e = this.currentEvidence;
    if (!e) return '';
    if (this.viewerTab === 'response') return e.rawResponse ?? '';
    if (this.viewerTab === 'request') return e.rawRequest ?? '';
    return e.reproduction ?? '';
  }

  /** Ferramentas que apontaram a falha ("OWASP ZAP, Nuclei"). */
  protected toolsOf(finding: Finding): string {
    const tools = finding.tools?.length ? finding.tools : [finding.tool];
    return tools.map((t) => this.toolLabel[t] || t).join(', ');
  }

  protected setSeverityFilter(severity: FindingSeverity | 'ALL'): void {
    this.severityFilter = severity;
    this.applyFilter();
  }

  protected setQuery(query: string): void {
    this.query = query;
    this.applyFilter();
  }

  protected setStatusFilter(status: FindingStatus | 'ALL'): void {
    this.statusFilter = status;
    this.applyFilter();
  }

  /** Quantos achados há em cada triagem (contadores do filtro). */
  protected countByStatus(status: FindingStatus): number {
    return this.sortedFindings.filter((f) => findingStatusOf(f) === status).length;
  }

  /**
   * Triagem do achado aberto: corrigido, falso positivo, ignorado ou de volta a aberto.
   * Vale para todos os locais do grupo; a tela atualiza sem recarregar a varredura.
   */
  protected setFindingStatus(status: FindingStatus): void {
    const finding = this.selected;
    if (!this.scan || !finding || this.statusSaving) return;
    const ids = locationsOf(finding).map((l) => l.id);
    this.statusSaving = status;
    this.statusError = null;
    this.scanService.updateFindingsStatus(this.scan.id, ids, status).subscribe({
      next: () => {
        this.statusSaving = null;
        const updated = withStatus(finding, status);
        const swap = (list: Finding[]) => list.map((f) => (f.id === finding.id ? updated : f));
        this.scan = this.scan ? { ...this.scan, findings: swap(this.scan.findings) } : this.scan;
        this.sortedFindings = swap(this.sortedFindings);
        this.selected = updated;
        // some da lista se o filtro de status atual não o inclui mais (abre o próximo)
        this.applyFilter();
      },
      error: (error: ApiError) => {
        this.statusSaving = null;
        this.statusError = error.message;
      },
    });
  }

  /** Abre o achado no painel central. keepTab: mantém a sub-aba aberta, se ela existir para ele. */
  protected select(finding: Finding | null, keepTab = true): void {
    this.selected = finding;
    this.selectedEvidence = finding ? evidenceItems([finding]) : [];
    this.occurrenceIndex = 0;
    // antes de escolher a aba: a "Como corrigir" só existe se houver conteúdo
    this.buildRoleContent(finding);
    const roleTabs: DetailTab[] = ['learn', 'ticket', 'exploit'];
    const tabMissing =
      (this.detailTab === 'fix' && !this.hasFixTab(finding)) ||
      (this.detailTab === 'evidence' && this.selectedEvidence.length === 0) ||
      (this.detailTab === 'compliance' && !finding?.compliance.length) ||
      (roleTabs.includes(this.detailTab) && !this.roleTab(this.detailTab as 'learn' | 'ticket' | 'exploit'));
    if (!keepTab || tabMissing) this.detailTab = this.preferredDetailTab();
    this.viewerTab = this.firstViewerTab(this.currentEvidence);
    this.buildViewer();
  }

  protected setDetailTab(tab: DetailTab): void {
    this.detailTab = tab;
  }

  protected setViewerTab(tab: ViewerTab): void {
    this.viewerTab = tab;
    this.buildViewer();
  }

  /** Anterior/próxima ocorrência da mesma falha (dá a volta no fim da lista). */
  protected stepOccurrence(delta: number): void {
    const total = this.selectedEvidence.length;
    if (total === 0) return;
    this.occurrenceIndex = (this.occurrenceIndex + delta + total) % total;
    this.viewerTab = this.availableViewerTab(this.currentEvidence, this.viewerTab);
    this.buildViewer();
  }

  /** Abre a evidência de um local específico (sub-aba Ocorrências). */
  protected openOccurrence(locationId: string): void {
    const index = this.selectedEvidence.findIndex((e) => e.id === locationId);
    if (index < 0) return;
    this.occurrenceIndex = index;
    this.detailTab = 'evidence';
    this.viewerTab = this.availableViewerTab(this.currentEvidence, this.viewerTab);
    this.buildViewer();
  }

  protected hasEvidenceFor(locationId: string): boolean {
    return this.selectedEvidence.some((e) => e.id === locationId);
  }

  /** Severidade + triagem + busca, nessa ordem. */
  private filterList(): Finding[] {
    return filterFindings(filterByStatus(filterBySeverity(this.sortedFindings, this.severityFilter), this.statusFilter), this.query);
  }

  private applyFilter(): void {
    this.filteredFindings = this.filterList();
    // o selecionado saiu do filtro: abre o primeiro que sobrou
    if (!this.selected || !this.filteredFindings.includes(this.selected)) this.select(this.filteredFindings[0] ?? null, false);
  }

  /** Sub-aba que o perfil vê primeiro (RF-11): a dele (Aprender, Ticket, Exploração); Dev a correção. */
  private preferredDetailTab(): DetailTab {
    if (this.role === 'STUDENT') return 'learn';
    if (this.role === 'QA') return 'ticket';
    if (this.role === 'PENTESTER') return 'exploit';
    if (this.hasFixTab(this.selected)) return 'fix';
    return this.selectedEvidence.length > 0 && this.isPremium ? 'evidence' : 'locations';
  }

  private firstViewerTab(e: EvidenceItem | null): ViewerTab {
    if (e?.rawResponse) return 'response';
    if (e?.rawRequest) return 'request';
    return 'curl';
  }

  /** Mantém a aba do visor se a nova ocorrência tem esse conteúdo; senão, a primeira que tiver. */
  private availableViewerTab(e: EvidenceItem | null, wanted: ViewerTab): ViewerTab {
    const has = { response: Boolean(e?.rawResponse), request: Boolean(e?.rawRequest), curl: Boolean(e?.reproduction) };
    return has[wanted] ? wanted : this.firstViewerTab(e);
  }

  /** Linhas numeradas do visor, com a linha que prova a falha marcada. */
  private buildViewer(): void {
    this.viewerLines = highlightedLines(this.rawViewerText, this.selected?.title ?? '', this.currentEvidence?.attack);
  }

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

  protected countOf(severity: FindingSeverity): number {
    return this.scan?.summary.severityCounts[severity] ?? 0;
  }

  /**
   * RF-12: relatório em PDF pela impressão do navegador ("Salvar como PDF").
   * O @media print esconde o menu e mostra a seção .print-report.
   */
  protected exportPdf(): void {
    if (!this.isPremium) return; // relatório é recurso Premium (shared/ui/plans.ts)
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
        this.loadError = null;
        // derive antes: a visão do perfil abre o primeiro achado da lista já montada
        this.derive(scan);
        this.applyRoleView(scan);
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
    if (scan.role) {
      this.role = scan.role;
      this.view = roleView(scan.role);
    }
    if (this.viewApplied || !hasResults(scan.status)) return;
    this.viewApplied = true;
    // todos abrem no painel de achados, com o mais grave aberto na sub-aba do perfil
    this.tab = 'findings';
    this.select(this.filteredFindings[0] ?? null, false);
  }

  private derive(scan: ScanDetail): void {
    this.sortedFindings = sortBySeverity(scan.findings);
    // recarga (polling): mantém o mesmo achado aberto, agora com os dados novos
    const selectedId = this.selected?.id;
    this.filteredFindings = this.filterList();
    const again = this.filteredFindings.find((f) => f.id === selectedId);
    if (again) this.select(again);
    else if (this.viewApplied) this.select(this.filteredFindings[0] ?? null, false);
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
