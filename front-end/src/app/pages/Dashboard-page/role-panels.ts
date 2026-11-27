// Painéis do Painel (dashboard), portados da branch `front` (Kauan):
// cada perfil vê UM painel extra além do núcleo comum (RF-11).
// Todos recebem dados reais: as varreduras (GET /api/scans) e os achados das
// varreduras concluídas mais recentes (GET /api/scans/:id). No plano Free o
// backend não envia correção nem PoC, e o painel mostra o que fica no Premium.
import { CommonModule } from '@angular/common';
import { Component, Input, OnChanges } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { Finding, FindingSeverity, Scan, ScanStats } from '../../core/services/scan.service';
import { ChartComponent } from '../../shared/components/chart/chart.component';
import {
  STACKED_COLUMN_OPTIONS,
  TriageRun,
  chartTotal,
  triageEvolutionBar,
} from '../../shared/ui/chart-data';
import { SEVERITY_LABEL, SEVERITY_ORDER, TOOL_LABEL, owaspExplanation } from '../../shared/ui/labels';
import { PLAN_DEFINITIONS, PLAN_FEATURES, PlanDefinition } from '../../shared/ui/plans';
import { GuideLink, guideFor, isKnownGuide, owaspLink, summarizeRemediation } from '../scan-detail-page/role-guides';

export type RolePanel = 'qa' | 'dev' | 'pentester' | 'student';

// ---------- funções puras (testadas em role-panels.spec.ts) ----------

export const severityCounts = (findings: Finding[]): { severity: FindingSeverity; count: number }[] =>
  SEVERITY_ORDER.map((severity) => ({ severity, count: findings.filter((f) => f.severity === severity).length }));

/** "Tipo" = título do achado, top 5. Subdomínios do Subfinder viram um tipo só. */
export const topTypes = (findings: Finding[], limit = 5): { title: string; count: number }[] => {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    const type = finding.tool === 'SUBFINDER' ? 'Subdomínio encontrado' : finding.title;
    counts.set(type, (counts.get(type) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([title, count]) => ({ title, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
};

/** Alvos varridos mais de uma vez = candidatos a comparar regressão. */
export const repeatedTargets = (scans: Scan[]): { targetUrl: string; runs: number }[] => {
  const counts = new Map<string, number>();
  for (const scan of scans) counts.set(scan.targetUrl, (counts.get(scan.targetUrl) ?? 0) + 1);
  return [...counts.entries()].filter(([, runs]) => runs > 1).map(([targetUrl, runs]) => ({ targetUrl, runs }));
};

const percent = (count: number, max: number): number => (count / Math.max(1, max)) * 100;

// ---------- QA: resultados e relatórios ----------

@Component({
  selector: 'app-qa-panel',
  standalone: true,
  imports: [CommonModule, RouterLink, ChartComponent],
  template: `
    <!-- status da correção e tipos mais frequentes ficam na aba Riscos (sem repetir aqui) -->
    <div class="dash-grid">
      <!-- relatórios -->
      <section class="dash-tile" aria-label="Relatórios">
        <header class="dash-tile-head"><h3>Relatórios</h3></header>
        <ng-container *ngIf="plan.canExportReports; else reportsLocked">
          <p class="dash-note">Abra a análise concluída mais recente e exporte em PDF ou JSON para anexar no chamado.</p>
          <a *ngIf="latestCompleted" class="button button-outline button-sm" [routerLink]="['/scans', latestCompleted.id]">Abrir último relatório</a>
          <span *ngIf="!latestCompleted" class="hint">Nenhuma análise concluída ainda.</span>
        </ng-container>
        <ng-template #reportsLocked>
          <p class="dash-note">Relatórios em PDF e JSON ficam no plano Premium.</p>
          <a class="button button-outline button-sm" routerLink="/plans">Ver planos</a>
        </ng-template>
      </section>

      <!-- correções ao longo das varreduras: quanto foi corrigido e quanto ainda está aberto -->
      <section class="dash-tile dash-span-all" aria-label="Evolução das correções">
        <header class="dash-tile-head"><h3>Evolução das correções</h3><span>corrigidos × abertos em cada varredura recente</span></header>
        <app-chart type="bar" [data]="evolutionChart" [options]="stackedOptions" [height]="230" [empty]="chartTotal(evolutionChart) === 0"
          emptyText="Marque os achados como corrigidos (ou falso positivo) no detalhe da varredura para acompanhar a evolução aqui."
          ariaLabel="Achados corrigidos, descartados e abertos em cada varredura" />
        <p *ngIf="lastRun" class="dash-note">
          Na varredura mais recente: <strong>{{ lastRun.fixed }}</strong> corrigidos, <strong>{{ lastRun.dismissed }}</strong> descartados e
          <strong>{{ lastRun.open }}</strong> abertos.
        </p>
      </section>
    </div>
  `,
})
export class QaPanelComponent implements OnChanges {
  @Input() scans: Scan[] = [];
  @Input() findings: Finding[] = [];
  @Input() stats: ScanStats | null = null;
  /** abertos × corrigidos × descartados das varreduras concluídas mais recentes */
  @Input() triageRuns: TriageRun[] = [];
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly stackedOptions = STACKED_COLUMN_OPTIONS as ChartOptions;
  protected readonly chartTotal = chartTotal;

  // Calculados só quando as entradas mudam. Como getters, cada verificação do
  // Angular criava objetos novos, os gráficos (ResizeObserver) redesenhavam e
  // disparavam outra verificação: loop infinito que congelava o painel.
  protected evolutionChart: ChartData = triageEvolutionBar([]) as ChartData;
  protected lastRun: TriageRun | null = null;
  protected latestCompleted: Scan | undefined;

  ngOnChanges(): void {
    this.evolutionChart = triageEvolutionBar(this.triageRuns) as ChartData;
    this.lastRun = [...this.triageRuns].sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0] ?? null;
    this.latestCompleted = this.scans.find((s) => s.status === 'COMPLETED');
  }
}

// ---------- Dev: alertas e depuração ----------

@Component({
  selector: 'app-dev-panel',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <section class="card">
      <header class="card-header">
        <div><h2>Alertas e depuração</h2><p>Acompanhe somente o que precisa de atenção no desenvolvimento.</p></div>
      </header>
      <div class="card-body grid grid-2">
        <div class="subcard">
          <h3>Alertas</h3>
          <div class="chips top-gap"><span class="chip">Scan falho</span><span class="chip">Ambiente suspeito</span><span class="chip">Falha crítica ou alta</span></div>
          <div *ngIf="flagged.length === 0 && highRisk === 0" class="empty-box">Nenhum alerta novo</div>
          <ul *ngIf="flagged.length > 0 || highRisk > 0" class="alert-list">
            <li *ngIf="highRisk > 0">
              <span class="alert-dot alert-dot-danger"></span>
              <div><p>{{ highRisk }} falha(s) crítica(s) ou alta(s) aguardando correção.</p></div>
            </li>
            <li *ngFor="let scan of flagged">
              <span class="alert-dot" [class.alert-dot-danger]="scan.status === 'FAILED'"></span>
              <div>
                <p *ngIf="scan.status === 'FAILED'">Falha ao escanear <a class="mono" [routerLink]="['/scans', scan.id]">{{ scan.targetUrl }}</a></p>
                <p *ngIf="scan.status !== 'FAILED'"><a class="mono" [routerLink]="['/scans', scan.id]">{{ scan.targetUrl }}</a> aponta para rede interna e foi bloqueada</p>
                <small>{{ scan.createdAt | date: 'dd/MM/yyyy HH:mm' }}</small>
              </div>
            </li>
          </ul>
        </div>

        <div class="subcard">
          <h3>Modo debug</h3>
          <p>Respostas cruas e stack traces só aparecem em DEV/STAGING. Em produção, o Modo Seguro filtra essas informações.</p>
        </div>

        <div class="subcard span-2">
          <h3>Sugestões de correção</h3>
          <ng-container *ngIf="plan.canSeeDetails; else fixLocked">
            <div *ngIf="fixes.length === 0" class="empty-box">As sugestões aparecerão após a primeira varredura.</div>
            <!-- recolhidas por padrão: a correção é longa; a seta abre cada uma -->
            <ul *ngIf="fixes.length > 0" class="fix-list fix-list-collapsible">
              <li *ngFor="let finding of fixes">
                <details>
                  <summary>
                    <span class="badge sev" [attr.data-severity]="finding.severity">{{ severityLabel[finding.severity] }}</span>
                    <span class="fix-title">{{ finding.title }}</span>
                    <span class="fix-arrow" aria-hidden="true"></span>
                  </summary>
                  <p>{{ finding.remediation }}</p>
                </details>
              </li>
            </ul>
          </ng-container>
          <ng-template #fixLocked>
            <div class="locked-card top-gap">
              <div><strong>Correção exata no Premium</strong><p>O Free mostra o diagnóstico de cada falha; o que mudar no código fica no Premium.</p></div>
              <a class="button button-outline button-sm" routerLink="/plans">Ver planos</a>
            </div>
          </ng-template>
        </div>
      </div>
    </section>
  `,
})
export class DevPanelComponent implements OnChanges {
  @Input() scans: Scan[] = [];
  @Input() findings: Finding[] = [];
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly severityLabel = SEVERITY_LABEL;

  // calculados só quando as entradas mudam (ver QaPanelComponent)
  protected flagged: Scan[] = [];
  protected highRisk = 0;
  /** uma sugestão por tipo de falha, das mais graves para as mais leves */
  protected fixes: Finding[] = [];

  ngOnChanges(): void {
    this.flagged = this.scans.filter((s) => s.status === 'FAILED' || s.suspiciousEnvironment).slice(0, 5);
    this.highRisk = this.findings.filter(
      (f) => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && (!f.status || f.status === 'OPEN'),
    ).length;
    const seen = new Set<string>();
    this.fixes = [...this.findings]
      // só o que ainda está aberto: o já corrigido, falso positivo ou ignorado não precisa de sugestão
      .filter((f) => f.remediation && (!f.status || f.status === 'OPEN'))
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
      .filter((f) => !seen.has(f.title) && Boolean(seen.add(f.title)))
      .slice(0, 6);
  }
}

// ---------- Pentester: log, payload e saída bruta ----------

@Component({
  selector: 'app-pentester-panel',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <!-- CVSS, confiança, endpoints e ferramentas ficam nas abas Riscos, Alvos e Varreduras (sem repetir aqui) -->
    <div class="dash-grid">
      <!-- achados com payload e saída bruta -->
      <section class="dash-tile dash-span-all" aria-label="Achados, payload e saída bruta">
        <header class="dash-tile-head">
          <h3>Achados, payload e saída bruta</h3>
          <div class="filters">
            <select class="select" aria-label="Filtrar por severidade" [disabled]="findings.length === 0" [(ngModel)]="severityFilter" (ngModelChange)="applyFilters()">
              <option value="">{{ findings.length === 0 ? 'Severidade: sem dados' : 'Todas as severidades' }}</option>
              <option *ngFor="let s of severityOptions" [value]="s">{{ severityLabel[s] }}</option>
            </select>
            <select class="select" aria-label="Filtrar por ferramenta" [disabled]="findings.length === 0" [(ngModel)]="toolFilter" (ngModelChange)="applyFilters()">
              <option value="">{{ findings.length === 0 ? 'Ferramenta: sem dados' : 'Todas as ferramentas' }}</option>
              <option *ngFor="let t of tools" [value]="t">{{ toolLabel[t] || t }}</option>
            </select>
          </div>
        </header>
        <div *ngIf="filtered.length === 0" class="empty-box">Aguardando a primeira varredura.</div>
        <ul *ngIf="filtered.length > 0" class="finding-list">
          <li *ngFor="let f of filtered">
            <div class="finding-head">
              <span class="badge sev" [attr.data-severity]="f.severity">{{ severityLabel[f.severity] }}</span>
              <strong>{{ f.title }}</strong>
              <span class="badge">{{ toolLabel[f.tool] || f.tool }}</span>
            </div>
            <code *ngIf="f.affectedUrl" class="finding-target">{{ f.affectedUrl }}<ng-container *ngIf="f.parameter"> · {{ f.parameter }}</ng-container></code>
            <ng-container *ngIf="plan.canSeeDetails; else pocLocked">
              <details><summary>Payload / requisição</summary><pre>{{ f.rawRequest || 'Indisponível (Modo Seguro ou sem dados).' }}</pre></details>
              <details><summary>Saída bruta</summary><pre>{{ f.rawResponse || 'Indisponível (Modo Seguro ou sem dados).' }}</pre></details>
            </ng-container>
            <ng-template #pocLocked><p class="hint">Payload e saída bruta (PoC) no <a class="link" routerLink="/plans">Premium</a>.</p></ng-template>
          </li>
        </ul>
        <p class="dash-note">Em varreduras de produção (Modo Seguro) o servidor oculta parâmetro, payload e saída bruta.</p>
      </section>

      <!-- log técnico: recolhido, abre na seta -->
      <section class="dash-tile dash-span-all fix-list-collapsible" aria-label="Log técnico">
        <details>
          <summary><span class="fix-title">Log técnico das varreduras</span><span class="fix-arrow" aria-hidden="true"></span></summary>
          <div *ngIf="scans.length === 0" class="empty-box">Timestamp, IPs resolvidos, safeMode e status: aguardando a primeira varredura.</div>
          <pre *ngIf="scans.length > 0" class="code logs"><ng-container *ngFor="let scan of scans">[{{ scan.createdAt | date: 'dd/MM HH:mm:ss' }}] {{ scan.objective }} {{ scan.targetUrl }} env={{ scan.environment }} safeMode={{ scan.safeMode }} status={{ scan.status }} ips={{ scan.resolvedIps.join(',') || 'n/a' }}
</ng-container></pre>
        </details>
      </section>
    </div>
  `,
})
export class PentesterPanelComponent implements OnChanges {
  @Input() scans: Scan[] = [];
  @Input() findings: Finding[] = [];
  @Input() stats: ScanStats | null = null;
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly severityLabel = SEVERITY_LABEL;
  protected readonly toolLabel = TOOL_LABEL;
  protected readonly severityOptions = SEVERITY_ORDER;
  protected severityFilter: FindingSeverity | '' = '';
  protected toolFilter = '';

  // calculados só quando as entradas ou os filtros mudam (ver QaPanelComponent)
  protected tools: string[] = [];
  protected filtered: Finding[] = [];

  ngOnChanges(): void {
    this.tools = [...new Set(this.findings.map((f) => f.tool))];
    this.applyFilters();
  }

  protected applyFilters(): void {
    this.filtered = this.findings
      .filter((f) => !this.severityFilter || f.severity === this.severityFilter)
      .filter((f) => !this.toolFilter || f.tool === this.toolFilter)
      .slice(0, 30);
  }
}

// ---------- Estudante: aprender com a análise ----------

@Component({
  selector: 'app-student-panel',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <section class="card">
      <header class="card-header">
        <div><h2>Aprenda com a análise</h2><p>O básico para entender uma varredura. Clique para abrir.</p></div>
      </header>
      <div class="card-body">
        <!-- conceitos: fechados por padrão, com a seta para abrir -->
        <div class="learn-grid fix-list-collapsible">
          <details *ngFor="let c of concepts" class="subcard learn-item">
            <summary><span class="fix-title">{{ c.title }}</span><span class="fix-arrow" aria-hidden="true"></span></summary>
            <p>{{ c.text }}</p>
            <ul class="learn-links">
              <li *ngFor="let l of c.links"><a class="link" [href]="l.url" target="_blank" rel="noopener noreferrer">{{ l.label }} <span aria-hidden="true">↗</span></a></li>
            </ul>
          </details>
        </div>

        <div class="subcard top-gap">
          <h3>O que a sua varredura encontrou</h3>
          <div *ngIf="explained.length === 0" class="empty-box">As explicações aparecerão após a primeira varredura.</div>
          <ul *ngIf="explained.length > 0" class="fix-list fix-list-collapsible">
            <li *ngFor="let e of explained">
              <details>
                <summary>
                  <span class="badge sev" [attr.data-severity]="e.finding.severity">{{ severityLabel[e.finding.severity] }}</span>
                  <span class="fix-title">{{ e.finding.title }}</span>
                  <span class="fix-arrow" aria-hidden="true"></span>
                </summary>

                <div class="learn-part" *ngIf="e.what">
                  <h4>O que é</h4>
                  <p>{{ e.what }}</p>
                </div>

                <div class="learn-part" *ngIf="e.fix.length">
                  <h4>Como corrigir</h4>
                  <ul class="learn-steps">
                    <li *ngFor="let step of e.fix">{{ step }}</li>
                  </ul>
                  <details *ngIf="e.full" class="learn-full">
                    <summary><span class="fix-title">Texto completo da ferramenta</span><span class="fix-arrow" aria-hidden="true"></span></summary>
                    <p>{{ e.full }}</p>
                  </details>
                </div>
                <p *ngIf="!plan.canSeeDetails" class="hint">Como corrigir: disponível no <a class="link" routerLink="/plans">Premium</a>.</p>

                <div class="learn-part" *ngIf="e.links.length">
                  <h4>Para estudar</h4>
                  <ul class="learn-links">
                    <li *ngFor="let l of e.links"><a class="link" [href]="l.url" target="_blank" rel="noopener noreferrer">{{ l.label }} <span aria-hidden="true">↗</span></a></li>
                  </ul>
                </div>
              </details>
            </li>
          </ul>
        </div>
      </div>
    </section>
  `,
})
export class StudentPanelComponent implements OnChanges {
  @Input() findings: Finding[] = [];
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly severityLabel = SEVERITY_LABEL;

  /** conceitos básicos, curtos, cada um com a fonte oficial */
  protected readonly concepts: { title: string; text: string; links: GuideLink[] }[] = [
    {
      title: 'Modo Seguro e Modo Verboso',
      text: 'O Verboso mostra tudo, para estudar em ambiente de teste. O Seguro esconde dados sensíveis em produção.',
      links: [{ label: 'OWASP · Tratamento de erros', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html' }],
    },
    {
      title: 'Varredura passiva e ativa',
      text: 'A passiva só observa as respostas. A ativa envia ataques de verdade e por isso pede a sua autorização.',
      links: [
        { label: 'OWASP ZAP · Varredura passiva', url: 'https://www.zaproxy.org/docs/desktop/start/features/pscan/' },
        { label: 'OWASP ZAP · Varredura ativa', url: 'https://www.zaproxy.org/docs/desktop/start/features/ascan/' },
      ],
    },
    {
      title: 'Por que provar que o domínio é seu?',
      text: 'Testar o site de outra pessoa sem autorização é crime (art. 154-A do Código Penal).',
      links: [{ label: 'Lei 12.737/2012 (art. 154-A)', url: 'https://www.planalto.gov.br/ccivil_03/_ato2011-2014/2012/lei/l12737.htm' }],
    },
    {
      title: 'Onde praticar sem risco',
      text: 'Use sites feitos para serem atacados, rodando no seu computador (localhost).',
      links: [
        { label: 'OWASP Juice Shop', url: 'https://owasp.org/www-project-juice-shop/' },
        { label: 'DVWA', url: 'https://github.com/digininja/DVWA' },
        { label: 'PortSwigger Academy (laboratórios grátis)', url: 'https://portswigger.net/web-security' },
      ],
    },
  ];

  /** um exemplo por tipo de falha, dos mais graves para os mais leves (calculado só quando muda) */
  protected explained: {
    finding: Finding;
    what: string | null;
    fix: string[];
    full: string | null;
    links: GuideLink[];
  }[] = [];

  ngOnChanges(): void {
    const seen = new Set<string>();
    this.explained = [...this.findings]
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
      .filter((f) => !seen.has(f.title) && Boolean(seen.add(f.title)))
      .slice(0, 5)
      .map((finding) => {
        const guide = guideFor(finding);
        const known = isKnownGuide(guide);
        // correção em poucos passos: a do guia da classe (curta, em português) ou o começo
        // do texto da ferramenta; o texto inteiro fica recolhido, para quem quiser
        // (a correção é recurso Premium: no Free fica só o aviso)
        const fix = !this.plan.canSeeDetails ? [] : known && guide.fix.length ? guide.fix : summarizeRemediation(finding.remediation);
        const links = [...guide.learn, owaspLink(finding.owaspUrl)].filter((l): l is GuideLink => Boolean(l));
        return {
          finding,
          what: known ? guide.what : owaspExplanation(finding.owaspUrl),
          fix,
          full: fix.length && finding.remediation && finding.remediation.length > 160 ? finding.remediation : null,
          links: links.filter((l, i) => links.findIndex((o) => o.url === l.url) === i).slice(0, 3),
        };
      });
  }
}

// ---------- Planos: o que cada um libera ----------

@Component({
  selector: 'app-plans-panel',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <section class="card">
      <header class="card-header">
        <div><h2>Recursos do seu plano</h2><p>Compare os planos Free e Premium.</p></div>
        <a class="link" routerLink="/plans">Ver detalhes</a>
      </header>
      <div class="card-body grid grid-2">
        <article *ngFor="let p of plans" class="plan-tile" [class.selected]="p.id === plan.id">
          <div class="plan-tile-head">
            <h3>{{ p.name }}</h3>
            <span *ngIf="p.id === plan.id" class="badge badge-brand">Seu plano</span>
          </div>
          <p class="plan-price">{{ p.priceLabel }}</p>
          <ul>
            <li *ngFor="let f of features" [class.off]="!(p.id === 'PREMIUM' ? f.premium : f.free)">
              <span class="mark" aria-hidden="true">{{ (p.id === 'PREMIUM' ? f.premium : f.free) ? '✓' : '–' }}</span>
              {{ f.label }}
            </li>
          </ul>
        </article>
      </div>
    </section>
  `,
})
export class PlansPanelComponent {
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly plans = [PLAN_DEFINITIONS.FREE, PLAN_DEFINITIONS.PREMIUM];
  protected readonly features = PLAN_FEATURES;
}
