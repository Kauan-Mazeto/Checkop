// Painéis do Painel (dashboard), portados da branch `front` (Kauan):
// cada perfil vê UM painel extra além do núcleo comum (RF-11).
// Todos recebem dados reais: as varreduras (GET /api/scans) e os achados das
// varreduras concluídas mais recentes (GET /api/scans/:id). No plano Free o
// backend não envia correção nem PoC, e o painel mostra o que fica no Premium.
import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Finding, FindingSeverity, Scan } from '../../core/services/scan.service';
import { SEVERITY_LABEL, SEVERITY_ORDER, owaspExplanation } from '../../shared/ui/labels';
import { PLAN_DEFINITIONS, PLAN_FEATURES, PlanDefinition } from '../../shared/ui/plans';

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
  imports: [CommonModule, RouterLink],
  template: `
    <section class="card">
      <header class="card-header">
        <div><h2>Resultados das análises</h2><p>Vulnerabilidades encontradas, relatórios e URLs analisadas mais de uma vez.</p></div>
      </header>
      <div class="card-body grid grid-2">
        <div class="subcard">
          <div class="subcard-head"><h3>Por severidade</h3><span>{{ findings.length }} encontradas</span></div>
          <div *ngIf="findings.length === 0" class="empty-box">Os resultados aparecem aqui quando uma análise terminar.</div>
          <ul *ngIf="findings.length > 0" class="bars">
            <li *ngFor="let item of bySeverity">
              <span class="bar-label">{{ severityLabel[item.severity] }}</span>
              <span class="bar-track"><span class="bar-fill" [attr.data-severity]="item.severity" [style.width.%]="pct(item.count, maxSeverity)"></span></span>
              <span class="bar-value">{{ item.count }}</span>
            </li>
          </ul>
        </div>

        <div class="subcard">
          <div class="subcard-head"><h3>Por tipo</h3><span>mais frequentes</span></div>
          <div *ngIf="types.length === 0" class="empty-box">Os tipos identificados serão listados após a análise.</div>
          <ul *ngIf="types.length > 0" class="bars">
            <li *ngFor="let item of types">
              <span class="bar-label" [title]="item.title">{{ item.title }}</span>
              <span class="bar-track"><span class="bar-fill" [style.width.%]="pct(item.count, maxType)"></span></span>
              <span class="bar-value">{{ item.count }}</span>
            </li>
          </ul>
        </div>

        <div class="subcard">
          <h3>Relatórios</h3>
          <ng-container *ngIf="plan.canExportReports; else reportsLocked">
            <p>Abra a análise concluída mais recente para exportar o relatório em PDF ou JSON.</p>
            <div class="actions top-gap">
              <a *ngIf="latestCompleted" class="button button-outline button-sm" [routerLink]="['/scans', latestCompleted.id]">Abrir relatório</a>
              <span *ngIf="!latestCompleted" class="hint">Nenhuma análise concluída disponível.</span>
            </div>
          </ng-container>
          <ng-template #reportsLocked>
            <p>Relatórios em PDF e JSON estão disponíveis no plano Premium.</p>
            <div class="actions top-gap"><a class="button button-outline button-sm" routerLink="/plans">Ver planos</a></div>
          </ng-template>
        </div>

        <div class="subcard">
          <div class="subcard-head"><h3>URLs analisadas mais de uma vez</h3><span>{{ repeated.length }} URLs</span></div>
          <div *ngIf="repeated.length === 0" class="empty-box">
            {{ plan.canViewHistory ? 'Quando uma URL tiver mais de uma análise, ela aparecerá aqui.' : 'Comparar análises da mesma URL exige o histórico do Premium.' }}
          </div>
          <ul *ngIf="repeated.length > 0" class="plain-list">
            <li *ngFor="let item of repeated"><span class="cell-url">{{ item.targetUrl }}</span><span class="badge">{{ item.runs }} execuções</span></li>
          </ul>
        </div>
      </div>
    </section>
  `,
})
export class QaPanelComponent {
  @Input() scans: Scan[] = [];
  @Input() findings: Finding[] = [];
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly severityLabel = SEVERITY_LABEL;
  protected readonly pct = percent;

  protected get bySeverity() {
    return severityCounts(this.findings);
  }
  protected get maxSeverity(): number {
    return Math.max(...this.bySeverity.map((i) => i.count));
  }
  protected get types() {
    return topTypes(this.findings);
  }
  protected get maxType(): number {
    return Math.max(0, ...this.types.map((i) => i.count));
  }
  protected get repeated() {
    return repeatedTargets(this.scans);
  }
  protected get latestCompleted(): Scan | undefined {
    return this.scans.find((s) => s.status === 'COMPLETED');
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
            <ul *ngIf="fixes.length > 0" class="fix-list">
              <li *ngFor="let finding of fixes">
                <strong><span class="badge sev" [attr.data-severity]="finding.severity">{{ severityLabel[finding.severity] }}</span> {{ finding.title }}</strong>
                <p>{{ finding.remediation }}</p>
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
export class DevPanelComponent {
  @Input() scans: Scan[] = [];
  @Input() findings: Finding[] = [];
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly severityLabel = SEVERITY_LABEL;

  protected get flagged(): Scan[] {
    return this.scans.filter((s) => s.status === 'FAILED' || s.suspiciousEnvironment).slice(0, 5);
  }
  protected get highRisk(): number {
    return this.findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
  }
  /** uma sugestão por tipo de falha, das mais graves para as mais leves */
  protected get fixes(): Finding[] {
    const seen = new Set<string>();
    return [...this.findings]
      .filter((f) => f.remediation)
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
    <section class="card">
      <header class="card-header">
        <div><h2>Análise técnica</h2><p>Log, payload e saída bruta das varreduras concluídas.</p></div>
        <div class="filters">
          <select class="select" aria-label="Filtrar por severidade" [disabled]="findings.length === 0" [(ngModel)]="severityFilter">
            <option value="">{{ findings.length === 0 ? 'Severidade: sem dados' : 'Todas as severidades' }}</option>
            <option *ngFor="let s of severityOptions" [value]="s">{{ severityLabel[s] }}</option>
          </select>
          <select class="select" aria-label="Filtrar por ferramenta" [disabled]="findings.length === 0" [(ngModel)]="toolFilter">
            <option value="">{{ findings.length === 0 ? 'Ferramenta: sem dados' : 'Todas as ferramentas' }}</option>
            <option *ngFor="let t of tools" [value]="t">{{ t }}</option>
          </select>
        </div>
      </header>
      <div class="card-body grid grid-2">
        <div class="subcard">
          <h3>Log técnico</h3>
          <div *ngIf="scans.length === 0" class="empty-box">Timestamp, IPs resolvidos, safeMode e status: aguardando primeira varredura.</div>
          <pre *ngIf="scans.length > 0" class="code logs"><ng-container *ngFor="let scan of scans">[{{ scan.createdAt | date: 'dd/MM HH:mm:ss' }}] {{ scan.objective }} {{ scan.targetUrl }} env={{ scan.environment }} safeMode={{ scan.safeMode }} status={{ scan.status }} ips={{ scan.resolvedIps.join(',') || 'n/a' }}
</ng-container></pre>
        </div>

        <div class="subcard">
          <h3>Achados, payload e saída bruta</h3>
          <div *ngIf="filtered.length === 0" class="empty-box">Aguardando primeira varredura.</div>
          <ul *ngIf="filtered.length > 0" class="finding-list">
            <li *ngFor="let f of filtered">
              <div class="finding-head">
                <span class="badge sev" [attr.data-severity]="f.severity">{{ severityLabel[f.severity] }}</span>
                <strong>{{ f.title }}</strong>
                <span class="badge">{{ f.tool }}</span>
              </div>
              <code *ngIf="f.affectedUrl" class="finding-target">{{ f.affectedUrl }}<ng-container *ngIf="f.parameter"> · {{ f.parameter }}</ng-container></code>
              <ng-container *ngIf="plan.canSeeDetails; else pocLocked">
                <details><summary>Payload / requisição</summary><pre>{{ f.rawRequest || 'Indisponível (Modo Seguro ou sem dados).' }}</pre></details>
                <details><summary>Saída bruta</summary><pre>{{ f.rawResponse || 'Indisponível (Modo Seguro ou sem dados).' }}</pre></details>
              </ng-container>
              <ng-template #pocLocked><p class="hint">Payload e saída bruta (PoC) no <a class="link" routerLink="/plans">Premium</a>.</p></ng-template>
            </li>
          </ul>
        </div>
      </div>
      <p class="card-body hint no-top">Em scans de produção (Modo Seguro) o servidor oculta parâmetro, payload e saída bruta.</p>
    </section>
  `,
})
export class PentesterPanelComponent {
  @Input() scans: Scan[] = [];
  @Input() findings: Finding[] = [];
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly severityLabel = SEVERITY_LABEL;
  protected readonly severityOptions = SEVERITY_ORDER;
  protected severityFilter: FindingSeverity | '' = '';
  protected toolFilter = '';

  protected get tools(): string[] {
    return [...new Set(this.findings.map((f) => f.tool))];
  }
  protected get filtered(): Finding[] {
    return this.findings
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
        <div><h2>Aprenda com a análise</h2><p>Entenda o básico antes de interpretar uma varredura.</p></div>
      </header>
      <div class="card-body grid grid-2">
        <div class="subcard"><h3>Modo Seguro e Modo Verboso</h3><p>O Verboso mostra mais detalhes para estudo em ambientes controlados. O Seguro protege informações em produção.</p></div>
        <div class="subcard"><h3>Passiva e ativa</h3><p>A varredura passiva só observa as respostas. A ativa envia ataques reais e pede a sua autorização.</p></div>
        <div class="subcard"><h3>Por que verificar o domínio?</h3><p>Testar sistema alheio sem autorização é crime (art. 154-A do Código Penal). Por isso o Checkop pede a prova de que o site é seu.</p></div>
        <div class="subcard"><h3>Laboratório seguro</h3><p>Rode o OWASP Juice Shop ou o DVWA em <code>localhost</code> e veja as falhas aparecerem sem risco.</p></div>

        <div class="subcard span-2">
          <h3>O que a sua varredura encontrou</h3>
          <div *ngIf="explained.length === 0" class="empty-box">As explicações aparecerão após a primeira varredura.</div>
          <ul *ngIf="explained.length > 0" class="fix-list">
            <li *ngFor="let f of explained">
              <strong><span class="badge sev" [attr.data-severity]="f.severity">{{ severityLabel[f.severity] }}</span> {{ f.title }}</strong>
              <p *ngIf="explain(f.owaspUrl) as text"><b>O que é:</b> {{ text }}</p>
              <p *ngIf="f.remediation"><b>Como corrigir:</b> {{ f.remediation }}</p>
              <p *ngIf="!plan.canSeeDetails" class="hint">Como corrigir: disponível no <a class="link" routerLink="/plans">Premium</a>.</p>
            </li>
          </ul>
        </div>
      </div>
    </section>
  `,
})
export class StudentPanelComponent {
  @Input() findings: Finding[] = [];
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly severityLabel = SEVERITY_LABEL;
  protected readonly explain = owaspExplanation;

  /** um exemplo por tipo de falha, dos mais graves para os mais leves */
  protected get explained(): Finding[] {
    const seen = new Set<string>();
    return [...this.findings]
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
      .filter((f) => !seen.has(f.title) && Boolean(seen.add(f.title)))
      .slice(0, 5);
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
      <p class="card-body hint no-top">Valores demonstrativos, sem cobrança no MVP.</p>
    </section>
  `,
})
export class PlansPanelComponent {
  @Input() plan: PlanDefinition = PLAN_DEFINITIONS.FREE;

  protected readonly plans = [PLAN_DEFINITIONS.FREE, PLAN_DEFINITIONS.PREMIUM];
  protected readonly features = PLAN_FEATURES;
}
