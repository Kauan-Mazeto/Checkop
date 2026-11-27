// Abas de relatório do Painel: Riscos, Varreduras e Alvos. Cada uma junta vários
// gráficos e uma lista com os dados que o Checkop já coleta (GET /api/scans,
// /api/scans/stats e os achados das varreduras concluídas mais recentes).
import { CommonModule } from '@angular/common';
import { Component, Input, OnChanges } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { UserRole } from '../../core/services/auth.service';
import { Finding, Scan, ScanStats } from '../../core/services/scan.service';
import { GuideLink, guideFor, isKnownGuide, owaspLink } from '../scan-detail-page/role-guides';
import { ChartComponent } from '../../shared/components/chart/chart.component';
import {
  BAR_OPTIONS,
  COLUMN_OPTIONS,
  DOUGHNUT_OPTIONS,
  ENVIRONMENT_COLOR,
  ENVIRONMENT_ORDER,
  LINE_LEGEND_OPTIONS,
  LINE_OPTIONS,
  STACKED_COLUMN_OPTIONS,
  TriageRun,
  SCAN_STATUS_COLOR,
  SCAN_STATUS_ORDER,
  avgDurationBar,
  chartTotal,
  confidenceDoughnut,
  countBar,
  countDoughnut,
  cvssHistogram,
  endpointsBar,
  findingsByTargetBar,
  scansPerDay,
  owaspBar,
  targetTrendLine,
  timelineLine,
  triageDoughnut,
  triageEvolutionBar,
} from '../../shared/ui/chart-data';
import { CONFIDENCE_LABEL, ENVIRONMENT_LABEL, SEVERITY_LABEL, SEVERITY_ORDER, STATUS_LABEL, owaspExplanation, shortOwasp } from '../../shared/ui/labels';
import { PLAN_DEFINITIONS, PlanDefinition } from '../../shared/ui/plans';
import { topTypes } from './role-panels';

/** Achado com a varredura e o site de onde veio (para listar e abrir). */
export interface FindingRow {
  finding: Finding;
  scanId: string;
  targetUrl: string;
}

const host = (url: string): string => url.replace(/^https?:\/\//, '').replace(/\/$/, '');

/**
 * Quais blocos cada perfil vê (RF-11): cada um só o que ajuda no trabalho dele.
 * QA: o que foi corrigido e o que voltou; Pentester: onde está o risco e por onde
 * atacar; Dev: o que corrigir no código e se a falha chega à produção. O Admin vê tudo.
 */
export const REPORT_TILES: Record<string, UserRole[]> = {
  // Riscos / Correções
  worst: ['QA', 'DEV', 'PENTESTER'],
  triage: ['QA', 'DEV'],
  cvss: ['PENTESTER'],
  confidence: ['PENTESTER', 'QA'],
  types: ['QA'],
  fixGuide: ['DEV'],
  byEnvironment: ['DEV'],
  // Varreduras
  scanStatus: ['QA'],
  scanEnvironment: ['PENTESTER'],
  tools: ['PENTESTER'],
  perDay: ['QA', 'DEV'],
  objectives: ['QA', 'PENTESTER'],
  duration: ['QA', 'DEV'],
  // Alvos
  targetsTable: ['QA', 'DEV', 'PENTESTER'],
  byTarget: ['QA', 'DEV'],
  endpoints: ['PENTESTER', 'DEV'],
  trend: ['QA', 'DEV'],
};

const canSee = (role: UserRole, tile: string): boolean => role === 'ADM' || (REPORT_TILES[tile] ?? []).includes(role);

// ---------- Riscos ----------

@Component({
  selector: 'app-risk-report',
  standalone: true,
  imports: [CommonModule, RouterLink, ChartComponent],
  template: `
    <div class="dash-grid">
      <!-- o que corrigir primeiro -->
      <section *ngIf="show('worst')" class="dash-tile dash-span-2" aria-label="Falhas mais graves">
        <header class="dash-tile-head"><h3>Corrigir primeiro</h3><span>as {{ worst.length }} falhas mais graves</span></header>
        <div *ngIf="worst.length === 0" class="empty-box">As falhas mais graves aparecem aqui quando uma varredura terminar.</div>
        <ul *ngIf="worst.length > 0" class="rank-list">
          <li *ngFor="let row of worst; let i = index">
            <a [routerLink]="['/scans', row.scanId]">
              <span class="rank-n">{{ i + 1 }}</span>
              <span class="badge sev" [attr.data-severity]="row.finding.severity">{{ severityLabel[row.finding.severity] }}</span>
              <span class="rank-main">
                <strong>{{ row.finding.title }}</strong>
                <small class="mono">{{ host(row.targetUrl) }}<ng-container *ngIf="row.finding.parameter"> · {{ row.finding.parameter }}</ng-container></small>
              </span>
              <span class="rank-meta">
                <span *ngIf="row.finding.cvssScore !== null" class="mono">CVSS {{ row.finding.cvssScore | number: '1.1-1' }}</span>
                <span *ngIf="row.finding.confidence">{{ confidenceLabel[row.finding.confidence] }}</span>
              </span>
            </a>
          </li>
        </ul>
      </section>

      <section *ngIf="show('triage')" class="dash-tile" aria-label="Status da correção">
        <header class="dash-tile-head"><h3>Status da correção</h3><span>{{ resolvedPct }}% tratado</span></header>
        <app-chart type="doughnut" [data]="triageChart" [options]="doughnutOptions" [height]="200" [empty]="chartTotal(triageChart) === 0"
          emptyText="Marque achados como corrigidos ou falso positivo para acompanhar aqui." ariaLabel="Achados por status da correção" />
      </section>

      <!-- Dev: a falha está chegando à produção? -->
      <section *ngIf="show('byEnvironment')" class="dash-tile" aria-label="Achados por ambiente">
        <header class="dash-tile-head"><h3>Por ambiente</h3><span>pegar antes de produção</span></header>
        <app-chart type="doughnut" [data]="environmentChart" [options]="doughnutOptions" [height]="200" [empty]="rows.length === 0"
          ariaLabel="Achados por ambiente" />
        <p *ngIf="rows.length > 0" class="dash-note">
          <ng-container *ngIf="inProduction > 0; else noProd"><strong>{{ inProduction }}</strong> achado(s) já em produção: corrija primeiro.</ng-container>
          <ng-template #noProd>Nenhum achado em produção: as falhas estão sendo pegas antes do deploy.</ng-template>
        </p>
      </section>

      <!-- Dev: como corrigir os erros que mais se repetem, com o guia oficial -->
      <section *ngIf="show('fixGuide')" class="dash-tile dash-span-2" aria-label="Como corrigir os mais frequentes">
        <header class="dash-tile-head"><h3>Como corrigir os que mais se repetem</h3><span>corrija o padrão, não só a linha</span></header>
        <div *ngIf="fixGuide.length === 0" class="empty-box">Os erros mais frequentes e a correção de cada um aparecem aqui depois da primeira varredura.</div>
        <ul *ngIf="fixGuide.length > 0" class="fix-guide">
          <li *ngFor="let g of fixGuide">
            <div class="fix-guide-head"><strong>{{ g.name }}</strong><span class="badge">{{ g.count }}×</span></div>
            <p>{{ g.fix }}</p>
            <a *ngIf="g.link" class="link" [href]="g.link.url" target="_blank" rel="noopener noreferrer">{{ g.link.label }} <span aria-hidden="true">↗</span></a>
          </li>
        </ul>
      </section>

      <section *ngIf="show('cvss')" class="dash-tile" aria-label="Nota CVSS">
        <header class="dash-tile-head"><h3>Nota CVSS</h3><span>faixas oficiais (FIRST)</span></header>
        <app-chart type="bar" [data]="cvssChart" [options]="columnOptions" [height]="200" [empty]="rows.length === 0" ariaLabel="Achados por faixa de nota CVSS" />
      </section>

      <section *ngIf="show('confidence')" class="dash-tile" aria-label="Confiança dos achados">
        <header class="dash-tile-head"><h3>Confiança</h3><span>o que confirmar à mão</span></header>
        <app-chart type="doughnut" [data]="confidenceChart" [options]="doughnutOptions" [height]="200" [empty]="rows.length === 0" ariaLabel="Achados por confiança" />
      </section>

      <section *ngIf="show('types')" class="dash-tile" aria-label="Tipos de falha mais frequentes">
        <header class="dash-tile-head"><h3>Tipos mais frequentes</h3><span>{{ rows.length }} achados</span></header>
        <app-chart type="bar" [data]="typesChart" [options]="barOptions" [height]="200" [empty]="rows.length === 0" ariaLabel="Achados por tipo de falha" />
      </section>
    </div>
    <p class="dash-note top-gap">Listas e gráficos de achados usam as {{ scansWithFindings }} varreduras concluídas mais recentes; o status da correção usa todas.</p>
  `,
})
export class RiskReportComponent implements OnChanges {
  @Input() rows: FindingRow[] = [];
  @Input() scans: Scan[] = [];
  @Input() stats: ScanStats | null = null;
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;
  @Input() scansWithFindings = 0;
  @Input() role: UserRole = 'ADM';

  protected show(tile: string): boolean {
    return canSee(this.role, tile);
  }

  protected readonly severityLabel = SEVERITY_LABEL;
  protected readonly confidenceLabel = CONFIDENCE_LABEL;
  protected readonly doughnutOptions = DOUGHNUT_OPTIONS as ChartOptions;
  protected readonly barOptions = BAR_OPTIONS as ChartOptions;
  protected readonly columnOptions = COLUMN_OPTIONS as ChartOptions;
  protected readonly chartTotal = chartTotal;
  protected readonly host = host;

  protected worst: FindingRow[] = [];
  protected triageChart: ChartData = triageDoughnut({}) as ChartData;
  protected resolvedPct = 0;
  protected cvssChart: ChartData = cvssHistogram([]) as ChartData;
  protected confidenceChart: ChartData = confidenceDoughnut([]) as ChartData;
  protected typesChart: ChartData = countBar({}) as ChartData;
  protected environmentChart: ChartData = countDoughnut({}, ENVIRONMENT_ORDER, ENVIRONMENT_LABEL, ENVIRONMENT_COLOR) as ChartData;
  protected inProduction = 0;
  protected fixGuide: { name: string; count: number; fix: string; link: GuideLink | null }[] = [];

  ngOnChanges(): void {
    const findings = this.rows.map((r) => r.finding);

    // Dev: achados por ambiente da varredura de onde vieram
    const environmentOf = new Map(this.scans.map((s) => [s.id, s.environment as string]));
    const byEnvironment: Record<string, number> = {};
    for (const row of this.rows) {
      const env = environmentOf.get(row.scanId);
      if (env) byEnvironment[env] = (byEnvironment[env] ?? 0) + 1;
    }
    this.environmentChart = countDoughnut(byEnvironment, ENVIRONMENT_ORDER, ENVIRONMENT_LABEL, ENVIRONMENT_COLOR) as ChartData;
    this.inProduction = byEnvironment['PRODUCTION'] ?? 0;

    // Dev: os tipos que mais se repetem, com a correção do guia da classe e o link oficial
    const byClass = new Map<string, { name: string; count: number; fix: string; link: GuideLink | null }>();
    for (const finding of findings) {
      const guide = guideFor(finding);
      if (!isKnownGuide(guide)) continue;
      const entry = byClass.get(guide.name) ?? {
        name: guide.name,
        count: 0,
        fix: guide.fix[0] ?? guide.acceptance,
        link: guide.learn.find((l) => l.url.includes('cheatsheetseries')) ?? guide.learn[0] ?? owaspLink(finding.owaspUrl),
      };
      entry.count += 1;
      byClass.set(guide.name, entry);
    }
    this.fixGuide = [...byClass.values()].sort((a, b) => b.count - a.count).slice(0, 5);
    this.worst = [...this.rows]
      .filter((r) => r.finding.status === 'OPEN' || !r.finding.status)
      .sort(
        (a, b) =>
          SEVERITY_ORDER.indexOf(a.finding.severity) - SEVERITY_ORDER.indexOf(b.finding.severity) ||
          (b.finding.cvssScore ?? 0) - (a.finding.cvssScore ?? 0),
      )
      .slice(0, 8);
    const byStatus = this.stats?.findings.byStatus ?? {};
    this.triageChart = triageDoughnut(byStatus) as ChartData;
    const total = chartTotal(this.triageChart);
    const resolved = (byStatus['FIXED'] ?? 0) + (byStatus['FALSE_POSITIVE'] ?? 0) + (byStatus['IGNORED'] ?? 0);
    this.resolvedPct = total ? Math.round((resolved / total) * 100) : 0;
    this.cvssChart = cvssHistogram(findings) as ChartData;
    this.confidenceChart = confidenceDoughnut(findings) as ChartData;
    this.typesChart = countBar(Object.fromEntries(topTypes(findings, 7).map((t) => [t.title, t.count])), (k) => k) as ChartData;
  }
}

// ---------- Varreduras ----------

@Component({
  selector: 'app-scans-report',
  standalone: true,
  imports: [CommonModule, ChartComponent],
  template: `
    <div class="dash-grid">
      <section *ngIf="show('scanStatus')" class="dash-tile" aria-label="Varreduras por status">
        <header class="dash-tile-head"><h3>Por status</h3><span>{{ scans.length }} varreduras</span></header>
        <app-chart type="doughnut" [data]="statusChart" [options]="doughnutOptions" [height]="200" [empty]="scans.length === 0" ariaLabel="Varreduras por status" />
        <p *ngIf="scans.length > 0" class="dash-note"><strong>{{ successPct }}%</strong> terminaram com sucesso.</p>
      </section>

      <section *ngIf="show('scanEnvironment')" class="dash-tile" aria-label="Varreduras por ambiente">
        <header class="dash-tile-head"><h3>Por ambiente</h3><span>detectado pelo Checkop</span></header>
        <app-chart type="doughnut" [data]="environmentChart" [options]="doughnutOptions" [height]="200" [empty]="scans.length === 0" ariaLabel="Varreduras por ambiente" />
      </section>

      <section *ngIf="show('tools')" class="dash-tile" aria-label="Achados por ferramenta">
        <header class="dash-tile-head"><h3>Achados por ferramenta</h3><span>quem encontrou</span></header>
        <app-chart type="bar" [data]="toolsChart" [options]="barOptions" [height]="200" [empty]="chartTotal(toolsChart) === 0" ariaLabel="Achados por ferramenta" />
      </section>

      <section *ngIf="show('perDay')" class="dash-tile dash-span-2" aria-label="Varreduras por dia">
        <header class="dash-tile-head"><h3>Varreduras por dia</h3><span>últimos 30 dias</span></header>
        <app-chart type="line" [data]="perDayChart" [options]="lineOptions" [height]="200" [empty]="scans.length === 0" ariaLabel="Varreduras por dia nos últimos 30 dias" />
      </section>

      <section *ngIf="show('objectives')" class="dash-tile" aria-label="Tipos de teste usados">
        <header class="dash-tile-head"><h3>Tipos de teste usados</h3><span>objetivos escolhidos</span></header>
        <app-chart type="bar" [data]="objectiveChart" [options]="barOptions" [height]="200" [empty]="scans.length === 0" ariaLabel="Varreduras por tipo de teste" />
      </section>

      <section *ngIf="show('duration')" class="dash-tile dash-span-all" aria-label="Duração média por tipo de teste">
        <header class="dash-tile-head"><h3>Duração média</h3><span>minutos, por tipo de teste (só concluídas)</span></header>
        <app-chart type="bar" [data]="durationChart" [options]="barOptions" [height]="200" [empty]="chartTotal(durationChart) === 0"
          emptyText="A duração aparece quando uma varredura terminar." ariaLabel="Duração média das varreduras por tipo de teste" />
      </section>
    </div>
  `,
})
export class ScansReportComponent implements OnChanges {
  @Input() role: UserRole = 'ADM';

  protected show(tile: string): boolean {
    return canSee(this.role, tile);
  }

  @Input() scans: Scan[] = [];
  @Input() stats: ScanStats | null = null;

  protected readonly doughnutOptions = DOUGHNUT_OPTIONS as ChartOptions;
  protected readonly barOptions = BAR_OPTIONS as ChartOptions;
  protected readonly lineOptions = LINE_OPTIONS as ChartOptions;
  protected readonly chartTotal = chartTotal;

  protected statusChart: ChartData = countDoughnut({}, SCAN_STATUS_ORDER, STATUS_LABEL, SCAN_STATUS_COLOR) as ChartData;
  protected environmentChart: ChartData = countDoughnut({}, ENVIRONMENT_ORDER, ENVIRONMENT_LABEL, ENVIRONMENT_COLOR) as ChartData;
  protected toolsChart: ChartData = countBar({}) as ChartData;
  protected perDayChart: ChartData = timelineLine({}) as ChartData;
  protected objectiveChart: ChartData = countBar({}) as ChartData;
  protected durationChart: ChartData = countBar({}) as ChartData;
  protected successPct = 0;

  ngOnChanges(): void {
    const count = (key: (s: Scan) => string) =>
      this.scans.reduce<Record<string, number>>((acc, s) => ({ ...acc, [key(s)]: (acc[key(s)] ?? 0) + 1 }), {});
    const byStatus = count((s) => s.status);
    this.statusChart = countDoughnut(byStatus, SCAN_STATUS_ORDER, STATUS_LABEL, SCAN_STATUS_COLOR) as ChartData;
    this.environmentChart = countDoughnut(count((s) => s.environment), ENVIRONMENT_ORDER, ENVIRONMENT_LABEL, ENVIRONMENT_COLOR) as ChartData;
    this.toolsChart = countBar(this.stats?.findings.byTool ?? {}) as ChartData;
    const perDay = timelineLine(scansPerDay(this.scans)) as ChartData;
    perDay.datasets[0].label = 'Varreduras';
    this.perDayChart = perDay;
    this.objectiveChart = countBar(count((s) => s.objectiveLabel), (k) => k) as ChartData;
    this.durationChart = avgDurationBar(this.scans) as ChartData;
    this.successPct = this.scans.length ? Math.round(((byStatus['COMPLETED'] ?? 0) / this.scans.length) * 100) : 0;
  }
}

// ---------- Alvos ----------

interface TargetRow {
  targetUrl: string;
  environment: string;
  runs: number;
  last: Scan;
  /** achados da última varredura concluída (null: nenhuma concluída ainda) */
  findings: number | null;
  /** diferença para a concluída anterior (+ piorou, − melhorou) */
  delta: number | null;
}

@Component({
  selector: 'app-targets-report',
  standalone: true,
  imports: [CommonModule, RouterLink, ChartComponent],
  template: `
    <div class="dash-grid">
      <section *ngIf="show('targetsTable')" class="dash-tile dash-span-all" aria-label="Seus alvos">
        <header class="dash-tile-head"><h3>Seus alvos</h3><span>{{ targets.length }} sites analisados</span></header>
        <div *ngIf="targets.length === 0" class="empty-box">Os sites aparecem aqui depois da primeira varredura.</div>
        <div *ngIf="targets.length > 0" class="table-scroll">
          <table class="target-table">
            <thead>
              <tr><th scope="col">Site</th><th scope="col">Ambiente</th><th scope="col">Varreduras</th><th scope="col">Última</th><th scope="col">Achados</th><th scope="col">Vs. anterior (mesmo teste)</th></tr>
            </thead>
            <tbody>
              <tr *ngFor="let t of targets">
                <td><a class="mono" [routerLink]="['/scans', t.last.id]">{{ host(t.targetUrl) }}</a></td>
                <td>{{ environmentLabel[t.environment] || t.environment }}</td>
                <td>{{ t.runs }}</td>
                <td>{{ t.last.createdAt | date: 'dd/MM HH:mm' }} · {{ statusLabel[t.last.status] }}</td>
                <td><strong>{{ t.findings ?? '–' }}</strong></td>
                <td>
                  <span *ngIf="t.delta === null" class="meta">–</span>
                  <span *ngIf="t.delta !== null && t.delta > 0" class="delta worse">▲ {{ t.delta }} a mais</span>
                  <span *ngIf="t.delta !== null && t.delta < 0" class="delta better">▼ {{ -t.delta }} a menos</span>
                  <span *ngIf="t.delta === 0" class="meta">igual</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section *ngIf="show('byTarget')" class="dash-tile" aria-label="Achados por site">
        <header class="dash-tile-head"><h3>Achados por site</h3><span>última varredura de cada um</span></header>
        <app-chart type="bar" [data]="byTargetChart" [options]="barOptions" [height]="220" [empty]="chartTotal(byTargetChart) === 0" ariaLabel="Achados por site" />
      </section>

      <section *ngIf="show('endpoints')" class="dash-tile" aria-label="Endpoints com mais achados">
        <header class="dash-tile-head"><h3>Endpoints com mais achados</h3><span>superfície de ataque</span></header>
        <app-chart type="bar" [data]="endpointsChart" [options]="barOptions" [height]="220" [empty]="chartTotal(endpointsChart) === 0" ariaLabel="Achados por endpoint" />
      </section>

      <section *ngIf="show('trend')" class="dash-tile dash-span-all" aria-label="Evolução por site">
        <header class="dash-tile-head"><h3>Evolução por site</h3><span>achados nas últimas execuções do mesmo teste no mesmo site</span></header>
        <app-chart type="line" [data]="trendChart" [options]="trendOptions" [height]="220" [empty]="trendChart.datasets.length === 0"
          [emptyText]="plan.canViewHistory ? 'Analise o mesmo site mais de uma vez para ver se as falhas diminuem (ou voltam).' : 'Comparar execuções do mesmo site exige o histórico do Premium.'"
          ariaLabel="Achados por execução de cada site" />
      </section>
    </div>
  `,
})
export class TargetsReportComponent implements OnChanges {
  @Input() role: UserRole = 'ADM';

  protected show(tile: string): boolean {
    return canSee(this.role, tile);
  }

  @Input() scans: Scan[] = [];
  @Input() rows: FindingRow[] = [];
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly environmentLabel: Record<string, string> = ENVIRONMENT_LABEL;
  protected readonly statusLabel = STATUS_LABEL;
  protected readonly barOptions = BAR_OPTIONS as ChartOptions;
  protected readonly trendOptions = LINE_LEGEND_OPTIONS as ChartOptions;
  protected readonly chartTotal = chartTotal;
  protected readonly host = host;

  protected targets: TargetRow[] = [];
  protected byTargetChart: ChartData = countBar({}) as ChartData;
  protected endpointsChart: ChartData = endpointsBar([]) as ChartData;
  protected trendChart: ChartData = targetTrendLine([]) as ChartData;

  ngOnChanges(): void {
    // a lista de varreduras vem da mais nova para a mais antiga
    const byTarget = new Map<string, Scan[]>();
    for (const scan of this.scans) byTarget.set(scan.targetUrl, [...(byTarget.get(scan.targetUrl) ?? []), scan]);
    this.targets = [...byTarget.entries()]
      .map(([targetUrl, runs]) => {
        const done = runs.filter((s) => s.status === 'COMPLETED' || s.status === 'CANCELED');
        // compara com a execução anterior do MESMO tipo de teste, concluída (testes
        // diferentes ou uma cancelada no meio dariam uma melhora/piora falsa)
        const previous = done[0] && done[0].status === 'COMPLETED'
          ? done.slice(1).find((s) => s.status === 'COMPLETED' && s.objective === done[0].objective)
          : undefined;
        return {
          targetUrl,
          environment: runs[0].environment,
          runs: runs.length,
          last: runs[0],
          findings: done[0]?.findingsCount ?? null,
          delta: previous ? done[0].findingsCount - previous.findingsCount : null,
        };
      })
      .sort((a, b) => (b.findings ?? -1) - (a.findings ?? -1));
    this.byTargetChart = findingsByTargetBar(this.scans) as ChartData;
    this.endpointsChart = endpointsBar(this.rows.map((r) => r.finding), 8) as ChartData;
    this.trendChart = targetTrendLine(this.scans) as ChartData;
  }
}

// ---------- Estudante: Aprender ----------

/** O que cada severidade quer dizer, nas faixas oficiais da nota CVSS 3.1 (FIRST). */
const SEVERITY_MEANING: { severity: string; range: string; text: string }[] = [
  { severity: 'CRITICAL', range: 'CVSS 9,0–10', text: 'Um atacante consegue tomar o sistema ou os dados sem esforço e sem login. Corrija antes de qualquer outra coisa.' },
  { severity: 'HIGH', range: 'CVSS 7,0–8,9', text: 'Dá acesso a dados ou funções que não deveria, com pouco esforço. Corrija logo.' },
  { severity: 'MEDIUM', range: 'CVSS 4,0–6,9', text: 'Precisa de alguma condição extra (login, clique da vítima), mas é real. Entra no planejamento.' },
  { severity: 'LOW', range: 'CVSS 0,1–3,9', text: 'Pouco impacto sozinha, mas ajuda um ataque maior. Boa prática corrigir.' },
  { severity: 'INFO', range: 'sem nota', text: 'Não é uma falha: é uma informação sobre o site que vale conhecer.' },
];

@Component({
  selector: 'app-learn-report',
  standalone: true,
  imports: [CommonModule, ChartComponent],
  template: `
    <div class="dash-grid">
      <!-- cada falha encontrada, explicada, com onde estudar -->
      <section class="dash-tile dash-span-2" aria-label="As falhas que você encontrou, explicadas">
        <header class="dash-tile-head"><h3>As falhas que você encontrou</h3><span>clique para abrir</span></header>
        <div *ngIf="classes.length === 0" class="empty-box">Rode uma varredura (o laboratório em localhost é um bom começo) e as falhas aparecem aqui explicadas.</div>
        <ul *ngIf="classes.length > 0" class="fix-list fix-list-collapsible">
          <li *ngFor="let c of classes">
            <details>
              <summary><span class="badge">{{ c.count }}×</span><span class="fix-title">{{ c.name }}</span><span class="fix-arrow" aria-hidden="true"></span></summary>
              <div class="learn-part"><h4>O que é</h4><p>{{ c.what }}</p></div>
              <div class="learn-part"><h4>Por que é perigoso</h4><p>{{ c.impact }}</p></div>
              <div class="learn-part" *ngIf="c.links.length">
                <h4>Para estudar</h4>
                <ul class="learn-links">
                  <li *ngFor="let l of c.links"><a class="link" [href]="l.url" target="_blank" rel="noopener noreferrer">{{ l.label }} <span aria-hidden="true">↗</span></a></li>
                </ul>
              </div>
            </details>
          </li>
        </ul>
      </section>

      <!-- severidade explicada -->
      <section class="dash-tile" aria-label="O que significa cada severidade">
        <header class="dash-tile-head"><h3>O que é cada severidade</h3></header>
        <ul class="severity-legend">
          <li *ngFor="let s of severityMeaning">
            <span class="badge sev" [attr.data-severity]="s.severity">{{ severityLabel[s.severity] }}</span>
            <span><small>{{ s.range }}</small> {{ s.text }}</span>
          </li>
        </ul>
        <a class="link" href="https://www.first.org/cvss/v3.1/specification-document" target="_blank" rel="noopener noreferrer">Como a nota CVSS é calculada (FIRST) <span aria-hidden="true">↗</span></a>
      </section>

      <!-- OWASP Top 10: onde estão as suas falhas e o que cada categoria significa -->
      <section class="dash-tile dash-span-all" aria-label="Suas falhas no OWASP Top 10">
        <header class="dash-tile-head"><h3>Suas falhas no OWASP Top 10</h3><span>a lista dos riscos mais comuns na web</span></header>
        <app-chart type="bar" [data]="owaspChart" [options]="barOptions" [height]="200" [empty]="chartTotal(owaspChart) === 0" ariaLabel="Achados por categoria OWASP" />
        <ul *ngIf="topCategories.length" class="learn-links">
          <li *ngFor="let c of topCategories">
            <strong>{{ c.code }}</strong> · {{ c.text }}
            <a *ngIf="c.link" class="link" [href]="c.link.url" target="_blank" rel="noopener noreferrer">ler na OWASP <span aria-hidden="true">↗</span></a>
          </li>
        </ul>
      </section>
    </div>
  `,
})
export class LearnReportComponent implements OnChanges {
  @Input() rows: FindingRow[] = [];
  @Input() stats: ScanStats | null = null;

  protected readonly severityLabel: Record<string, string> = SEVERITY_LABEL;
  protected readonly severityMeaning = SEVERITY_MEANING;
  protected readonly barOptions = BAR_OPTIONS as ChartOptions;
  protected readonly chartTotal = chartTotal;

  protected classes: { name: string; count: number; what: string; impact: string; links: GuideLink[] }[] = [];
  protected owaspChart: ChartData = owaspBar({}) as ChartData;
  protected topCategories: { code: string; text: string; link: GuideLink | null }[] = [];

  ngOnChanges(): void {
    const byClass = new Map<string, { name: string; count: number; what: string; impact: string; links: GuideLink[] }>();
    for (const { finding } of this.rows) {
      const guide = guideFor(finding);
      const known = isKnownGuide(guide);
      const name = known ? guide.name : finding.title;
      const entry = byClass.get(name) ?? {
        name,
        count: 0,
        what: known ? guide.what : (owaspExplanation(finding.owaspUrl) ?? guide.what),
        impact: guide.impact,
        links: [...guide.learn, owaspLink(finding.owaspUrl)].filter((l): l is GuideLink => Boolean(l)).slice(0, 3),
      };
      entry.count += 1;
      byClass.set(name, entry);
    }
    this.classes = [...byClass.values()].sort((a, b) => b.count - a.count).slice(0, 8);
    const byCategory = this.stats?.findings.byOwaspCategory ?? {};
    this.owaspChart = owaspBar(byCategory) as ChartData;
    this.topCategories = Object.entries(byCategory)
      .filter(([category]) => /A(0[1-9]|10)/.test(category))
      .sort(([, a], [, b]) => b - a)
      .slice(0, 3)
      .map(([category]) => ({ code: shortOwasp(category), text: owaspExplanation(category) ?? '', link: owaspLink(category) }));
  }
}

// ---------- Estudante: Seu progresso ----------

@Component({
  selector: 'app-progress-report',
  standalone: true,
  imports: [CommonModule, ChartComponent],
  template: `
    <div class="dash-grid">
      <section class="dash-tile dash-span-2" aria-label="Evolução das suas correções">
        <header class="dash-tile-head"><h3>Evolução das suas correções</h3><span>corrigidos × abertos em cada varredura</span></header>
        <app-chart type="bar" [data]="evolutionChart" [options]="stackedOptions" [height]="220" [empty]="chartTotal(evolutionChart) === 0"
          emptyText="Corrija uma falha no laboratório, marque como corrigida no detalhe da varredura e rode de novo: a evolução aparece aqui."
          ariaLabel="Achados corrigidos e abertos em cada varredura" />
      </section>

      <section class="dash-tile" aria-label="O que você já corrigiu">
        <header class="dash-tile-head"><h3>Já corrigiu</h3><span>{{ fixedTotal }} falha(s)</span></header>
        <div *ngIf="fixedClasses.length === 0" class="empty-box">Marque uma falha como corrigida no detalhe da varredura para começar.</div>
        <ul *ngIf="fixedClasses.length > 0" class="chips-list">
          <li *ngFor="let c of fixedClasses"><span class="badge">{{ c.name }} · {{ c.count }}</span></li>
        </ul>
      </section>

      <section *ngIf="nextTopic" class="dash-tile" aria-label="Próximo passo">
        <header class="dash-tile-head"><h3>Próximo passo</h3><span>a falha aberta que mais aparece</span></header>
        <p class="dash-note"><strong>{{ nextTopic.name }}</strong> aparece {{ nextTopic.count }} vez(es) e ainda está aberta. Estude e tente corrigir no laboratório.</p>
        <a *ngIf="nextTopic.link" class="link" [href]="nextTopic.link.url" target="_blank" rel="noopener noreferrer">{{ nextTopic.link.label }} <span aria-hidden="true">↗</span></a>
      </section>

      <section class="dash-tile" aria-label="Status da correção">
        <header class="dash-tile-head"><h3>Status da correção</h3><span>todas as varreduras</span></header>
        <app-chart type="doughnut" [data]="triageChart" [options]="doughnutOptions" [height]="190" [empty]="chartTotal(triageChart) === 0" ariaLabel="Achados por status da correção" />
      </section>

      <section class="dash-tile dash-span-2" aria-label="Sua prática">
        <header class="dash-tile-head"><h3>Sua prática</h3><span>varreduras por dia, últimos 30 dias</span></header>
        <app-chart type="line" [data]="practiceChart" [options]="lineOptions" [height]="190" [empty]="scans.length === 0" ariaLabel="Varreduras por dia" />
      </section>
    </div>
  `,
})
export class ProgressReportComponent implements OnChanges {
  @Input() rows: FindingRow[] = [];
  @Input() scans: Scan[] = [];
  @Input() stats: ScanStats | null = null;
  @Input() triageRuns: TriageRun[] = [];

  protected readonly doughnutOptions = DOUGHNUT_OPTIONS as ChartOptions;
  protected readonly lineOptions = LINE_OPTIONS as ChartOptions;
  protected readonly stackedOptions = STACKED_COLUMN_OPTIONS as ChartOptions;
  protected readonly chartTotal = chartTotal;

  protected evolutionChart: ChartData = triageEvolutionBar([]) as ChartData;
  protected triageChart: ChartData = triageDoughnut({}) as ChartData;
  protected practiceChart: ChartData = timelineLine({}) as ChartData;
  protected fixedClasses: { name: string; count: number }[] = [];
  protected fixedTotal = 0;
  protected nextTopic: { name: string; count: number; link: GuideLink | null } | null = null;

  ngOnChanges(): void {
    this.evolutionChart = triageEvolutionBar(this.triageRuns) as ChartData;
    this.triageChart = triageDoughnut(this.stats?.findings.byStatus ?? {}) as ChartData;
    const practice = timelineLine(scansPerDay(this.scans)) as ChartData;
    practice.datasets[0].label = 'Varreduras';
    this.practiceChart = practice;

    const fixed = new Map<string, number>();
    const open = new Map<string, { name: string; count: number; link: GuideLink | null }>();
    for (const { finding } of this.rows) {
      const guide = guideFor(finding);
      const name = isKnownGuide(guide) ? guide.name : finding.title;
      if (finding.status === 'FIXED') {
        fixed.set(name, (fixed.get(name) ?? 0) + 1);
      } else if (!finding.status || finding.status === 'OPEN') {
        const entry = open.get(name) ?? { name, count: 0, link: guide.learn[0] ?? owaspLink(finding.owaspUrl) };
        entry.count += 1;
        open.set(name, entry);
      }
    }
    this.fixedClasses = [...fixed.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
    this.fixedTotal = this.fixedClasses.reduce((sum, c) => sum + c.count, 0);
    this.nextTopic = [...open.values()].sort((a, b) => b.count - a.count)[0] ?? null;
  }
}
