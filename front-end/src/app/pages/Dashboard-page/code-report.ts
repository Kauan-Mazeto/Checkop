// Aba "Análise de código" do Painel (Dev, Estudante e Admin).
// Usa só o histórico guardado no servidor, que tem o RESUMO de cada análise
// (arquivos, contagens e, por achado, título/severidade/categoria/arquivo/linha/regra),
// nunca o código. Compara análises, mostra a evolução e gera relatórios.
import { Component, Input, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { UserRole } from '../../core/services/auth.service';
import { FindingSeverity } from '../../core/services/scan.service';
import { SastCategory, SastHistoryFinding, SastHistoryItem, SastService } from '../../core/services/sast.service';
import { ReportCarouselComponent, ReportSlide } from '../../shared/components/report-carousel/report-carousel.component';
import { BAR_OPTIONS, DOUGHNUT_OPTIONS, LINE_OPTIONS, STACKED_COLUMN_OPTIONS, chartTotal, countBar, countDoughnut } from '../../shared/ui/chart-data';
import { SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_ORDER } from '../../shared/ui/labels';
import { PlanDefinition } from '../../shared/ui/plans';

export const CATEGORY_ORDER: SastCategory[] = ['SECURITY', 'LOGIC', 'SYNTAX', 'DEPENDENCY', 'QUALITY'];
export const CATEGORY_LABEL: Record<SastCategory, string> = {
  SECURITY: 'Segurança', LOGIC: 'Lógica', SYNTAX: 'Sintaxe', DEPENDENCY: 'Dependência', QUALITY: 'Boa prática',
};
const CATEGORY_COLOR: Record<SastCategory, string> = {
  SECURITY: '#d84a56', LOGIC: '#e5b24c', SYNTAX: '#c678dd', DEPENDENCY: '#79b8ff', QUALITY: '#4fb276',
};
// gráficos de evolução: as últimas N análises, da mais antiga para a mais nova
const EVOLUTION_RUNS = 12;
const LIST_LIMIT = 15;

/** Mesma falha em duas análises: regra (ou título) + arquivo. A linha muda quando o código muda, então fica fora. */
export const findingKey = (f: SastHistoryFinding): string => `${f.ruleId || f.title}\u0000${f.file}`;

export interface AnalysisDiff {
  added: SastHistoryFinding[];
  fixed: SastHistoryFinding[];
  kept: SastHistoryFinding[];
  files: { file: string; before: number; after: number }[];
}

/** O que apareceu, o que sumiu (corrigido) e o que continuou entre duas análises. */
export const diffAnalyses = (before: SastHistoryItem, after: SastHistoryItem): AnalysisDiff => {
  const pool = new Map<string, SastHistoryFinding[]>();
  for (const f of before.findings) pool.set(findingKey(f), [...(pool.get(findingKey(f)) ?? []), f]);

  const added: SastHistoryFinding[] = [];
  const kept: SastHistoryFinding[] = [];
  for (const f of after.findings) {
    const same = pool.get(findingKey(f));
    if (same?.length) {
      same.shift();
      kept.push(f);
    } else {
      added.push(f);
    }
  }
  const fixed = [...pool.values()].flat();

  const perFile = new Map<string, { before: number; after: number }>();
  for (const f of before.findings) perFile.set(f.file, { before: (perFile.get(f.file)?.before ?? 0) + 1, after: perFile.get(f.file)?.after ?? 0 });
  for (const f of after.findings) perFile.set(f.file, { before: perFile.get(f.file)?.before ?? 0, after: (perFile.get(f.file)?.after ?? 0) + 1 });
  const files = [...perFile.entries()]
    .map(([file, n]) => ({ file, ...n }))
    .sort((a, b) => Math.abs(b.after - b.before) - Math.abs(a.after - a.before) || b.after - a.after);

  const bySeverity = (a: SastHistoryFinding, b: SastHistoryFinding) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  return { added: added.sort(bySeverity), fixed: fixed.sort(bySeverity), kept: kept.sort(bySeverity), files };
};

const pad = (n: number) => String(n).padStart(2, '0');
export const shortDate = (iso: string): string => {
  const d = new Date(iso);
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

const csvCell = (value: unknown): string => {
  const text = String(value ?? '');
  // evita fórmula ao abrir no Excel (injeção de CSV)
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[";\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
};

@Component({
  selector: 'app-code-report',
  standalone: true,
  imports: [FormsModule, RouterLink, ReportCarouselComponent],
  template: `
    @if (!plan.canAnalyzeCode) {
      <section class="dash-tile" aria-label="Análise de código">
        <header class="dash-tile-head"><h3>Relatórios da análise de código</h3><span class="badge badge-pro">PRO</span></header>
        <p class="dash-note">A análise de código e o histórico com comparações fazem parte do plano Premium.</p>
        <a class="button button-primary button-sm" routerLink="/plans">Ver planos</a>
      </section>
    } @else if (loading) {
      <p class="dash-note" role="status">Carregando o histórico da análise de código...</p>
    } @else if (error) {
      <div class="alert alert-error" role="alert">{{ error }}</div>
    } @else if (analyses.length === 0) {
      <section class="dash-tile" aria-label="Análise de código">
        <header class="dash-tile-head"><h3>Nenhuma análise de código ainda</h3></header>
        <p class="dash-note">
          Cada análise que você fizer aparece aqui com a evolução, as comparações e os relatórios.
          O Checkop guarda só o resumo (arquivos, contagens e onde cada falha está), nunca o seu código.
        </p>
        <a class="button button-primary button-sm" routerLink="/code-analysis">Analisar código</a>
      </section>
    } @else {
      <section class="code-kpis" aria-label="Indicadores da análise de código">
        <div class="code-kpi">
          <span class="meta-text">Análises</span>
          <strong>{{ analyses.length }}</strong>
          <small>{{ analyses.length >= limit ? 'as ' + limit + ' mais recentes' : 'no seu histórico' }}</small>
        </div>
        <div class="code-kpi" [class.kpi-alert]="latest.findingsCount > 0">
          <span class="meta-text">Achados na última</span>
          <strong>{{ latest.findingsCount }}</strong>
          @if (previous) {
            <small><span class="delta" [class.worse]="latestDelta > 0" [class.better]="latestDelta < 0">{{ signed(latestDelta) }}</span> vs a anterior</small>
          } @else {
            <small>primeira análise</small>
          }
        </div>
        <div class="code-kpi" [class.kpi-alert]="latestHighRisk > 0">
          <span class="meta-text">Críticas e altas</span>
          <strong>{{ latestHighRisk }}</strong>
          <small>na última análise</small>
        </div>
        <div class="code-kpi">
          <span class="meta-text">Corrigidos</span>
          <strong>{{ totalFixed }}</strong>
          <small>somando todas as comparações seguidas</small>
        </div>
      </section>

      @if (role === 'STUDENT') {
        <p class="dash-note code-tip">
          <strong>Dica de estudo:</strong> corrija um tipo de falha por vez e analise de novo. Na comparação abaixo,
          "corrigidos" mostra o que você já aprendeu a resolver e "novos" o que apareceu com o código novo.
        </p>
      }

      <div class="dash-grid">
        <app-report-carousel [slides]="evolutionSlides" [minHeight]="200" />
        <app-report-carousel [slides]="breakdownSlides" [minHeight]="200" />

        <!-- comparação entre duas análises -->
        <section class="dash-tile dash-span-all" aria-label="Comparar análises">
          <header class="dash-tile-head">
            <h3>Comparar análises</h3>
            <span>mesma falha = mesma regra no mesmo arquivo (a linha pode mudar)</span>
          </header>

          @if (analyses.length < 2) {
            <p class="dash-note">Faça mais uma análise para comparar com esta.</p>
          } @else {
            <div class="code-compare-pick">
              <label>
                <span class="meta-text">Antes</span>
                <select [(ngModel)]="beforeId" (ngModelChange)="compare()" aria-label="Análise de antes">
                  @for (a of analyses; track a.id) {
                    <option [value]="a.id">{{ describe(a) }}</option>
                  }
                </select>
              </label>
              <label>
                <span class="meta-text">Depois</span>
                <select [(ngModel)]="afterId" (ngModelChange)="compare()" aria-label="Análise de depois">
                  @for (a of analyses; track a.id) {
                    <option [value]="a.id">{{ describe(a) }}</option>
                  }
                </select>
              </label>
              <button type="button" class="button button-outline button-sm" (click)="downloadComparison()" [disabled]="!diff">Baixar comparação (CSV)</button>
            </div>

            @if (diff) {
              <div class="code-diff-sum">
                <div><strong class="delta worse">{{ diff.added.length }}</strong><span>novos</span></div>
                <div><strong class="delta better">{{ diff.fixed.length }}</strong><span>corrigidos</span></div>
                <div><strong>{{ diff.kept.length }}</strong><span>continuam</span></div>
              </div>

              <div class="table-scroll">
                <table class="target-table">
                  <thead><tr><th>Severidade</th><th>Antes</th><th>Depois</th><th>Diferença</th></tr></thead>
                  <tbody>
                    @for (s of severityOrder; track s) {
                      <tr>
                        <td><span class="badge sev" [attr.data-severity]="s">{{ severityLabel[s] }}</span></td>
                        <td>{{ before?.severityCounts?.[s] ?? 0 }}</td>
                        <td>{{ after?.severityCounts?.[s] ?? 0 }}</td>
                        <td><span class="delta" [class.worse]="sevDelta(s) > 0" [class.better]="sevDelta(s) < 0">{{ signed(sevDelta(s)) }}</span></td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>

              <div class="code-diff-lists">
                <div>
                  <h4>Novos ({{ diff.added.length }})</h4>
                  <ul class="code-list">
                    @for (f of diff.added.slice(0, listLimit); track $index) {
                      <li><span class="badge sev" [attr.data-severity]="f.severity">{{ severityLabel[f.severity] }}</span><span><strong>{{ f.title }}</strong><small class="mono">{{ where(f) }}</small></span></li>
                    } @empty {
                      <li class="meta-text">Nada novo. Bom sinal.</li>
                    }
                  </ul>
                </div>
                <div>
                  <h4>Corrigidos ({{ diff.fixed.length }})</h4>
                  <ul class="code-list">
                    @for (f of diff.fixed.slice(0, listLimit); track $index) {
                      <li><span class="badge sev" [attr.data-severity]="f.severity">{{ severityLabel[f.severity] }}</span><span><strong>{{ f.title }}</strong><small class="mono">{{ where(f) }}</small></span></li>
                    } @empty {
                      <li class="meta-text">Nenhum achado da análise de antes sumiu.</li>
                    }
                  </ul>
                </div>
              </div>

              @if (diff.files.length > 0) {
                <h4 class="code-h4">Por arquivo</h4>
                <div class="table-scroll">
                  <table class="target-table">
                    <thead><tr><th>Arquivo</th><th>Antes</th><th>Depois</th><th>Diferença</th></tr></thead>
                    <tbody>
                      @for (row of diff.files.slice(0, listLimit); track row.file) {
                        <tr>
                          <td class="mono">{{ row.file }}</td>
                          <td>{{ row.before }}</td>
                          <td>{{ row.after }}</td>
                          <td><span class="delta" [class.worse]="row.after > row.before" [class.better]="row.after < row.before">{{ signed(row.after - row.before) }}</span></td>
                        </tr>
                      }
                    </tbody>
                  </table>
                </div>
              }
            }
          }
        </section>

        <!-- arquivos da última análise -->
        <section class="dash-tile" aria-label="Arquivos com mais achados">
          <header class="dash-tile-head"><h3>Arquivos com mais achados</h3><span>última análise</span></header>
          <ul class="rank-list code-rank">
            @for (row of topFiles; track row.file; let i = $index) {
              <li>
                <div>
                  <span class="rank-n">{{ i + 1 }}</span>
                  <span class="rank-main"><strong class="mono">{{ row.file }}</strong><small>{{ row.language }}</small></span>
                  <span class="rank-meta"><strong>{{ row.count }}</strong>{{ row.count === 1 ? 'achado' : 'achados' }}</span>
                </div>
              </li>
            } @empty {
              <li class="meta-text">Nenhum achado na última análise.</li>
            }
          </ul>
        </section>

        <!-- falhas que voltam: aparecem em várias análises -->
        <section class="dash-tile" aria-label="Falhas recorrentes">
          <header class="dash-tile-head"><h3>Falhas que se repetem</h3><span>em quantas análises aparecem</span></header>
          <ul class="rank-list code-rank">
            @for (row of recurring; track row.title; let i = $index) {
              <li>
                <div>
                  <span class="rank-n">{{ i + 1 }}</span>
                  <span class="rank-main"><strong>{{ row.title }}</strong><small>{{ categoryLabel[row.category] }}</small></span>
                  <span class="rank-meta"><strong>{{ row.runs }}</strong>de {{ analyses.length }}</span>
                </div>
              </li>
            } @empty {
              <li class="meta-text">Nenhuma falha se repetiu entre as análises.</li>
            }
          </ul>
        </section>

        <!-- histórico -->
        <section class="dash-tile dash-span-all" aria-label="Histórico de análises">
          <header class="dash-tile-head">
            <h3>Histórico</h3>
            <span class="code-actions">
              <button type="button" class="button button-outline button-sm" (click)="downloadHistory()">Baixar relatório (CSV)</button>
              <button type="button" class="button button-outline button-sm code-danger" (click)="clearAll()" [disabled]="busy">Apagar histórico</button>
            </span>
          </header>
          <p class="dash-note">Guardamos só o resumo de cada análise: nomes dos arquivos, contagens e onde cada falha está. O código não fica salvo.</p>
          <div class="table-scroll">
            <table class="target-table">
              <thead><tr><th>Data</th><th>Arquivos</th><th>Modo</th><th>Achados</th><th>Críticas/altas</th><th>Tempo</th><th><span class="sr-only">Ações</span></th></tr></thead>
              <tbody>
                @for (a of analyses; track a.id) {
                  <tr>
                    <td class="mono">{{ shortDate(a.createdAt) }}</td>
                    <td [title]="fileNames(a)">{{ filesSummary(a) }}</td>
                    <td>{{ a.depth === 'ESSENTIAL' ? 'Essencial' : 'Completa' }}</td>
                    <td>{{ a.findingsCount }}</td>
                    <td>{{ highRiskOf(a) }}</td>
                    <td class="meta">{{ a.durationSeconds.toFixed(1) }} s</td>
                    <td><button type="button" class="link-button" (click)="remove(a)" [disabled]="busy" [attr.aria-label]="'Apagar a análise de ' + shortDate(a.createdAt)">Apagar</button></td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </section>
      </div>
    }
  `,
  styles: [
    `
      :host { display: flex; flex-direction: column; gap: 14px; }
      .code-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(170px, 100%), 1fr)); gap: 12px; }
      .code-kpi { display: flex; flex-direction: column; gap: 4px; padding: 14px 16px; border-radius: 12px; background: rgba(255, 255, 255, 0.025); border: 1px solid rgba(255, 255, 255, 0.08); }
      .code-kpi strong { font-size: 26px; font-weight: 700; color: var(--text); }
      .code-kpi small { color: var(--faint); font-size: 12px; }
      .code-kpi.kpi-alert strong { color: var(--sev-critical, #f2777b); }
      .code-tip { padding: 12px 14px; border-radius: 10px; background: rgba(121, 184, 255, 0.06); }
      .code-compare-pick { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 12px; }
      .code-compare-pick label { display: flex; flex-direction: column; gap: 4px; flex: 1 1 220px; min-width: 0; }
      .code-compare-pick select { width: 100%; }
      .code-diff-sum { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
      .code-diff-sum div { display: flex; flex-direction: column; align-items: center; gap: 2px; padding: 10px; border-radius: 10px; background: rgba(255, 255, 255, 0.03); }
      .code-diff-sum strong { font-size: 22px; }
      .code-diff-sum span { color: var(--muted); font-size: 12px; }
      .code-diff-lists { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(280px, 100%), 1fr)); gap: 14px; }
      h4, .code-h4 { margin: 4px 0 6px; font-size: 13px; font-weight: 650; color: var(--text-2); }
      .code-list { display: flex; flex-direction: column; gap: 6px; margin: 0; padding: 0; list-style: none; }
      .code-list li { display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: start; gap: 10px; font-size: 13px; }
      .code-list li > span:last-child { display: flex; flex-direction: column; min-width: 0; }
      .code-list strong, .code-list small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .code-list small { color: var(--faint); font-size: 12px; }
      .code-rank li > div { display: grid; grid-template-columns: 22px minmax(0, 1fr) auto; align-items: center; gap: 12px; padding: 10px 6px; }
      .code-actions { display: inline-flex; flex-wrap: wrap; gap: 8px; }
      .code-danger { color: var(--sev-critical, #f2777b); }
      .link-button { padding: 0; border: 0; background: none; color: var(--muted); cursor: pointer; font-size: 12.5px; text-decoration: underline; }
      .link-button:hover { color: var(--sev-critical, #f2777b); }
      .link-button:focus-visible { outline: 2px solid var(--info, #79b8ff); outline-offset: 2px; }
      .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
    `,
  ],
})
export class CodeReportComponent implements OnInit {
  private readonly sast = inject(SastService);

  @Input({ required: true }) plan!: PlanDefinition;
  @Input() role: UserRole = 'DEV';

  protected readonly severityOrder = SEVERITY_ORDER;
  protected readonly severityLabel = SEVERITY_LABEL;
  protected readonly categoryLabel = CATEGORY_LABEL;
  protected readonly listLimit = LIST_LIMIT;
  protected readonly shortDate = shortDate;

  protected loading = true;
  protected busy = false;
  protected error = '';
  /** da mais nova para a mais antiga */
  protected analyses: SastHistoryItem[] = [];
  protected limit = 100;

  protected beforeId = '';
  protected afterId = '';
  protected diff: AnalysisDiff | null = null;

  protected evolutionSlides: ReportSlide[] = [];
  protected breakdownSlides: ReportSlide[] = [];
  protected topFiles: { file: string; language: string; count: number }[] = [];
  protected recurring: { title: string; category: SastCategory; runs: number }[] = [];
  protected totalFixed = 0;

  ngOnInit(): void {
    if (!this.plan.canAnalyzeCode) {
      this.loading = false;
      return;
    }
    this.load();
  }

  private load(): void {
    this.loading = true;
    this.sast.history().subscribe({
      next: ({ analyses, limit }) => {
        this.analyses = analyses;
        this.limit = limit;
        this.loading = false;
        this.rebuild();
      },
      error: (err: { message?: string }) => {
        this.error = err?.message || 'Não foi possível carregar o histórico da análise de código.';
        this.loading = false;
      },
    });
  }

  protected get latest(): SastHistoryItem {
    return this.analyses[0];
  }

  protected get previous(): SastHistoryItem | null {
    return this.analyses[1] ?? null;
  }

  protected get latestDelta(): number {
    return this.previous ? this.latest.findingsCount - this.previous.findingsCount : 0;
  }

  protected get latestHighRisk(): number {
    return this.highRiskOf(this.latest);
  }

  protected highRiskOf(a: SastHistoryItem): number {
    return (a.severityCounts.CRITICAL || 0) + (a.severityCounts.HIGH || 0);
  }

  protected get before(): SastHistoryItem | undefined {
    return this.analyses.find((a) => a.id === this.beforeId);
  }

  protected get after(): SastHistoryItem | undefined {
    return this.analyses.find((a) => a.id === this.afterId);
  }

  protected sevDelta(s: FindingSeverity): number {
    return (this.after?.severityCounts?.[s] ?? 0) - (this.before?.severityCounts?.[s] ?? 0);
  }

  protected signed(n: number): string {
    return n > 0 ? `+${n}` : String(n);
  }

  protected where(f: SastHistoryFinding): string {
    return f.line ? `${f.file}:${f.line}` : f.file;
  }

  protected fileNames(a: SastHistoryItem): string {
    return a.files.map((f) => f.name).join(', ');
  }

  protected filesSummary(a: SastHistoryItem): string {
    if (a.files.length === 0) return '–';
    const first = a.files[0].name.split(/[\\/]/).pop();
    return a.files.length === 1 ? `${first}` : `${first} +${a.files.length - 1}`;
  }

  protected describe(a: SastHistoryItem): string {
    return `${shortDate(a.createdAt)} · ${this.filesSummary(a)} · ${a.findingsCount} achados`;
  }

  protected compare(): void {
    const before = this.before;
    const after = this.after;
    this.diff = before && after && before.id !== after.id ? diffAnalyses(before, after) : null;
  }

  private rebuild(): void {
    if (this.analyses.length === 0) return;
    // comparação padrão: a penúltima contra a última
    this.afterId = this.latest.id;
    this.beforeId = this.previous?.id ?? '';
    this.compare();

    const chrono = this.analyses.slice(0, EVOLUTION_RUNS).reverse();
    const labels = chrono.map((a) => shortDate(a.createdAt));

    // corrigidos somando cada par seguido (do mais antigo para o mais novo)
    const all = [...this.analyses].reverse();
    this.totalFixed = all.slice(1).reduce((sum, a, i) => sum + diffAnalyses(all[i], a).fixed.length, 0);
    const fixedPerRun = chrono.map((a) => {
      const index = all.indexOf(a);
      return index > 0 ? diffAnalyses(all[index - 1], a) : null;
    });

    const severityEvolution: ChartData<'bar'> = {
      labels,
      datasets: SEVERITY_ORDER.map((s) => ({
        label: SEVERITY_LABEL[s],
        data: chrono.map((a) => a.severityCounts[s] ?? 0),
        backgroundColor: SEVERITY_COLOR[s],
        maxBarThickness: 28,
      })),
    };
    const categoryEvolution: ChartData<'bar'> = {
      labels,
      datasets: CATEGORY_ORDER.map((c) => ({
        label: CATEGORY_LABEL[c],
        data: chrono.map((a) => a.categoryCounts[c] ?? 0),
        backgroundColor: CATEGORY_COLOR[c],
        maxBarThickness: 28,
      })),
    };
    const fixedVsNew: ChartData<'bar'> = {
      labels,
      datasets: [
        { label: 'Corrigidos', data: fixedPerRun.map((d) => d?.fixed.length ?? 0), backgroundColor: '#4fb276', maxBarThickness: 22 },
        { label: 'Novos', data: fixedPerRun.map((d) => d?.added.length ?? 0), backgroundColor: '#d84a56', maxBarThickness: 22 },
      ],
    };
    const duration: ChartData<'line'> = {
      labels,
      datasets: [{ label: 'Segundos', data: chrono.map((a) => Math.round(a.durationSeconds * 10) / 10), borderColor: '#79b8ff', backgroundColor: '#79b8ff', tension: 0.3 }],
    };
    const groupedOptions: ChartOptions<'bar'> = {
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 12 } } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { grid: { display: false } } },
    };

    this.evolutionSlides = [
      {
        title: 'Achados por severidade', subtitle: `últimas ${chrono.length} análises`, type: 'bar',
        data: severityEvolution as ChartData, options: STACKED_COLUMN_OPTIONS as ChartOptions,
        empty: chartTotal(severityEvolution) === 0, emptyText: 'Nenhum achado nas análises. Bom trabalho.', ariaLabel: 'Achados por severidade em cada análise',
      },
      {
        title: 'Corrigidos e novos', subtitle: 'cada análise contra a anterior', type: 'bar',
        data: fixedVsNew as ChartData, options: groupedOptions as ChartOptions,
        empty: chartTotal(fixedVsNew) === 0, emptyText: 'Faça mais uma análise para ver o que foi corrigido.', ariaLabel: 'Achados corrigidos e novos em cada análise',
      },
      {
        title: 'Achados por categoria', subtitle: 'segurança, lógica, sintaxe...', type: 'bar',
        data: categoryEvolution as ChartData, options: STACKED_COLUMN_OPTIONS as ChartOptions,
        empty: chartTotal(categoryEvolution) === 0, emptyText: 'Nenhum achado nas análises.', ariaLabel: 'Achados por categoria em cada análise',
      },
      {
        title: 'Tempo de análise', subtitle: 'em segundos', type: 'line',
        data: duration as ChartData, options: LINE_OPTIONS as ChartOptions, ariaLabel: 'Tempo de cada análise em segundos',
      },
    ];

    // composição da última análise
    const latest = this.latest;
    const languageOf = new Map(latest.files.map((f) => [f.name, f.language]));
    const byLanguage: Record<string, number> = {};
    for (const f of latest.findings) {
      const language = languageOf.get(f.file) ?? 'Outra';
      byLanguage[language] = (byLanguage[language] ?? 0) + 1;
    }
    const byRule: Record<string, number> = {};
    const byTool: Record<string, number> = {};
    for (const a of this.analyses) {
      for (const f of a.findings) {
        byRule[f.title] = (byRule[f.title] ?? 0) + 1;
        for (const tool of f.tools) byTool[tool] = (byTool[tool] ?? 0) + 1;
      }
    }
    const top = (counts: Record<string, number>, n = 10) => Object.fromEntries(Object.entries(counts).sort(([, x], [, y]) => y - x).slice(0, n));

    const categoryChart = countDoughnut(latest.categoryCounts, CATEGORY_ORDER, CATEGORY_LABEL, CATEGORY_COLOR);
    const languageChart = countBar(byLanguage, (k) => k, '#c5a66c');
    const ruleChart = countBar(top(byRule), (k) => k, '#d84a56');
    const toolChart = countBar(top(byTool), (k) => k);
    this.breakdownSlides = [
      {
        title: 'Categorias da última análise', subtitle: shortDate(latest.createdAt), type: 'doughnut',
        data: categoryChart as ChartData, options: DOUGHNUT_OPTIONS as ChartOptions, height: 200,
        empty: chartTotal(categoryChart) === 0, emptyText: 'Nenhum achado na última análise.', ariaLabel: 'Achados da última análise por categoria',
      },
      {
        title: 'Falhas mais frequentes', subtitle: 'todas as análises', type: 'bar',
        data: ruleChart as ChartData, options: BAR_OPTIONS as ChartOptions,
        empty: chartTotal(ruleChart) === 0, emptyText: 'Nenhum achado nas análises.', ariaLabel: 'Falhas que mais aparecem nas análises',
      },
      {
        title: 'Achados por linguagem', subtitle: 'última análise', type: 'bar',
        data: languageChart as ChartData, options: BAR_OPTIONS as ChartOptions,
        empty: chartTotal(languageChart) === 0, emptyText: 'Nenhum achado na última análise.', ariaLabel: 'Achados da última análise por linguagem',
      },
      {
        title: 'Ferramentas que apontaram', subtitle: 'todas as análises', type: 'bar',
        data: toolChart as ChartData, options: BAR_OPTIONS as ChartOptions,
        empty: chartTotal(toolChart) === 0, emptyText: 'Nenhum achado nas análises.', ariaLabel: 'Achados por ferramenta de análise',
      },
    ];

    const perFile: Record<string, number> = {};
    for (const f of latest.findings) perFile[f.file] = (perFile[f.file] ?? 0) + 1;
    this.topFiles = Object.entries(perFile)
      .sort(([, x], [, y]) => y - x)
      .slice(0, 8)
      .map(([file, count]) => ({ file, count, language: languageOf.get(file) ?? '' }));

    const runsByTitle = new Map<string, { category: SastCategory; runs: number }>();
    for (const a of this.analyses) {
      const seen = new Set<string>();
      for (const f of a.findings) {
        if (seen.has(f.title)) continue;
        seen.add(f.title);
        runsByTitle.set(f.title, { category: f.category, runs: (runsByTitle.get(f.title)?.runs ?? 0) + 1 });
      }
    }
    this.recurring = [...runsByTitle.entries()]
      .filter(([, v]) => v.runs > 1)
      .sort(([, x], [, y]) => y.runs - x.runs)
      .slice(0, 8)
      .map(([title, v]) => ({ title, ...v }));
  }

  protected remove(a: SastHistoryItem): void {
    if (!confirm(`Apagar a análise de ${shortDate(a.createdAt)} do histórico?`)) return;
    this.busy = true;
    this.sast.deleteHistoryItem(a.id).subscribe({
      next: () => {
        this.analyses = this.analyses.filter((x) => x.id !== a.id);
        this.busy = false;
        this.rebuild();
      },
      error: (err: { message?: string }) => {
        this.error = err?.message || 'Não foi possível apagar a análise.';
        this.busy = false;
      },
    });
  }

  protected clearAll(): void {
    if (!confirm('Apagar todo o histórico da análise de código? Isso não pode ser desfeito.')) return;
    this.busy = true;
    this.sast.clearHistory().subscribe({
      next: () => {
        this.analyses = [];
        this.diff = null;
        this.busy = false;
      },
      error: (err: { message?: string }) => {
        this.error = err?.message || 'Não foi possível apagar o histórico.';
        this.busy = false;
      },
    });
  }

  private download(name: string, rows: unknown[][]): void {
    const csv = '﻿' + rows.map((row) => row.map(csvCell).join(';')).join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.click();
    URL.revokeObjectURL(url);
  }

  protected downloadHistory(): void {
    this.download(`checkop-analises-de-codigo-${new Date().toISOString().slice(0, 10)}.csv`, [
      ['Data', 'Modo', 'Arquivos', 'Achados', ...SEVERITY_ORDER.map((s) => SEVERITY_LABEL[s]), ...CATEGORY_ORDER.map((c) => CATEGORY_LABEL[c]), 'Tempo (s)'],
      ...this.analyses.map((a) => [
        new Date(a.createdAt).toLocaleString('pt-BR'),
        a.depth === 'ESSENTIAL' ? 'Essencial' : 'Completa',
        this.fileNames(a),
        a.findingsCount,
        ...SEVERITY_ORDER.map((s) => a.severityCounts[s] ?? 0),
        ...CATEGORY_ORDER.map((c) => a.categoryCounts[c] ?? 0),
        a.durationSeconds.toFixed(1),
      ]),
    ]);
  }

  protected downloadComparison(): void {
    if (!this.diff || !this.before || !this.after) return;
    const row = (status: string, f: SastHistoryFinding) => [status, SEVERITY_LABEL[f.severity], CATEGORY_LABEL[f.category], f.title, f.file, f.line ?? '', f.ruleId ?? '', f.tools.join(', ')];
    this.download(`checkop-comparacao-${new Date().toISOString().slice(0, 10)}.csv`, [
      [`Antes: ${shortDate(this.before.createdAt)}`, `Depois: ${shortDate(this.after.createdAt)}`],
      ['Situação', 'Severidade', 'Categoria', 'Achado', 'Arquivo', 'Linha', 'Regra', 'Ferramentas'],
      ...this.diff.added.map((f) => row('Novo', f)),
      ...this.diff.fixed.map((f) => row('Corrigido', f)),
      ...this.diff.kept.map((f) => row('Continua', f)),
    ]);
  }
}
