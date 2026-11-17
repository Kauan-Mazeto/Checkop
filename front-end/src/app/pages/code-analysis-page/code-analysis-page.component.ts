import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { ApiError } from '../../core/http/api-error';
import { AuthService } from '../../core/services/auth.service';
import { DraftService } from '../../core/services/draft.service';
import { AiFixResult, SAST_MAX_TOTAL_BYTES, SastFinding, SastResult, SastService, parseSastLocation, AiCreditPack, FullFixResult } from '../../core/services/sast.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ChartComponent } from '../../shared/components/chart/chart.component';
import { DOUGHNUT_OPTIONS, severityCountsFrom, severityDoughnut } from '../../shared/ui/chart-data';
import { SEVERITY_LABEL, SEVERITY_ORDER } from '../../shared/ui/labels';
import { CodeLanguage, CodeLine, DiffRow, LANGUAGES, LANGUAGE_GROUPS, buildCodeView, codeWindow, isAcceptedFile, sideBySideDiff } from './code-view';

type InputMode = 'paste' | 'upload';

interface FindingView {
  finding: SastFinding;
  file: string;
  start: number;
  end: number;
  code: CodeLine[];
  /** janela enviada para a IA quando o usuário pede a correção */
  source: { code: string; firstLine: number };
  ai: { loading: boolean; error: string | null; result: AiFixResult | null; rows: DiffRow[] };
}

interface CodeDraft {
  filename: string;
  code: string;
}

const DRAFT_KEY = 'code-analysis';

@Component({
  selector: 'app-code-analysis-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, AppShellComponent, ChartComponent],
  templateUrl: './code-analysis-page.component.html',
  styleUrl: './code-analysis-page.component.scss',
})
export class CodeAnalysisPageComponent implements OnInit {
  private readonly sastService = inject(SastService);
  private readonly auth = inject(AuthService);
  private readonly drafts = inject(DraftService);

  protected readonly languages = LANGUAGES;
  /** seletor agrupado por categoria (Web, JVM/.NET, sistemas, infraestrutura) */
  protected readonly languageGroups = LANGUAGE_GROUPS.map((name) => ({ name, items: LANGUAGES.filter((l) => l.group === name) }));
  protected readonly severityLabel = SEVERITY_LABEL;
  protected readonly doughnutOptions = DOUGHNUT_OPTIONS as ChartOptions;
  protected readonly isPremium = this.auth.getCachedUser()?.plan === 'PREMIUM';

  protected mode: InputMode = 'paste';
  protected filename = LANGUAGES[0].filename;
  protected code = '';
  protected uploaded: Record<string, string> = {};
  protected uploadWarning: string | null = null;

  protected isAnalyzing = false;
  protected error: string | null = null;
  protected needsPremium = false;
  protected result: SastResult | null = null;
  protected views: FindingView[] = [];
  protected severityChart: ChartData | null = null;
  private analyzedFiles: Record<string, string> = {};
  /** correção com IA disponível neste servidor (há credencial da Anthropic) */
  protected aiEnabled = false;

  // correção do arquivo inteiro: paga à parte, com créditos de IA
  protected aiCredits = 0;
  protected fullFixCost = 1;
  protected creditPacks: AiCreditPack[] = [];
  protected showPacks = false;
  protected buyingPackId: string | null = null;
  protected creditMessage: string | null = null;
  protected fullFix: { loading: boolean; error: string | null; result: FullFixResult | null; rows: DiffRow[]; file: string | null } = {
    loading: false, error: null, result: null, rows: [], file: null,
  };
  protected copied = false;

  ngOnInit(): void {
    const draft = this.drafts.load<CodeDraft>(DRAFT_KEY);
    if (draft.filename && LANGUAGES.some((l) => l.filename === draft.filename)) this.filename = draft.filename;
    this.code = draft.code ?? '';
    if (this.isPremium) {
      this.sastService.aiConfig().subscribe({
        next: (config) => {
          this.aiEnabled = config.enabled;
          this.aiCredits = config.credits;
          this.fullFixCost = config.fullFixCost;
          this.creditPacks = config.packs;
        },
        error: () => (this.aiEnabled = false),
      });
    }
  }

  protected get language(): CodeLanguage {
    return LANGUAGES.find((l) => l.filename === this.filename) ?? LANGUAGES[0];
  }

  protected get uploadedNames(): string[] {
    return Object.keys(this.uploaded);
  }

  protected saveDraft(): void {
    this.drafts.save<CodeDraft>(DRAFT_KEY, { filename: this.filename, code: this.code });
  }

  protected loadExample(): void {
    this.code = this.language.example;
    this.saveDraft();
  }

  protected async onFiles(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    const skipped: string[] = [];
    const read: Record<string, string> = {};
    let total = 0;
    this.uploadWarning = null;

    for (const file of files) {
      if (!isAcceptedFile(file.name)) {
        skipped.push(file.name);
        continue;
      }
      total += file.size;
      if (total > SAST_MAX_TOTAL_BYTES) {
        this.uploadWarning = 'O total passou de 9 MB; os demais arquivos foram ignorados.';
        break;
      }
      read[file.webkitRelativePath || file.name] = await file.text();
    }

    this.uploaded = read;
    if (skipped.length) this.uploadWarning = `Ignorados (extensão não suportada): ${skipped.join(', ')}`;
    input.value = '';
  }

  protected analyze(): void {
    if (this.isAnalyzing) return;
    const files = this.mode === 'paste' ? (this.code.trim() ? { [this.filename]: this.code } : {}) : this.uploaded;

    if (Object.keys(files).length === 0) {
      this.error = this.mode === 'paste' ? 'Cole um trecho de código ou carregue o exemplo.' : 'Selecione ao menos um arquivo.';
      return;
    }

    this.isAnalyzing = true;
    this.error = null;
    this.needsPremium = false;
    this.result = null;
    this.analyzedFiles = files;
    this.fullFix = { loading: false, error: null, result: null, rows: [], file: null };

    this.sastService.analyze(files).subscribe({
      next: (result) => {
        this.isAnalyzing = false;
        this.result = result;
        this.views = this.buildViews(result.findings);
        this.severityChart = severityDoughnut(severityCountsFrom(result.findings)) as ChartData;
      },
      error: (error: ApiError) => {
        this.isAnalyzing = false;
        this.error = error.message;
        this.needsPremium = error.code === 'PREMIUM_REQUIRED';
      },
    });
  }

  private buildViews(findings: SastFinding[]): FindingView[] {
    return [...findings]
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
      .map((finding) => {
        const location = parseSastLocation(finding.affectedUrl);
        const file = location?.file ?? finding.affectedUrl;
        const start = location?.start ?? 1;
        const end = location?.end ?? start;
        const original = this.analyzedFiles[file];
        // sem o arquivo original (nome normalizado pelo motor), mostra o trecho devolvido
        const code = original
          ? buildCodeView(original, start, end)
          : buildCodeView(finding.rawResponse ?? '', 1, (finding.rawResponse ?? '').split('\n').length, 0).map((l) => ({
              ...l,
              number: l.number + start - 1,
              vulnerable: true,
            }));
        // janela em volta do achado; sem o arquivo original, o trecho devolvido pelo motor
        const source = original
          ? codeWindow(original, start, end)
          : { code: finding.rawResponse ?? '', firstLine: start };
        return { finding, file, start, end, code, source, ai: { loading: false, error: null, result: null, rows: [] } };
      });
  }
  /** Arquivo que a correção completa vai corrigir: o código colado (um arquivo só). */
  protected get fullFixFile(): string | null {
    const files = Object.keys(this.analyzedFiles);
    return files.length === 1 ? files[0] : null;
  }

  /** Corrige o arquivo inteiro com IA (consome créditos, pagos à parte do plano). */
  protected fixFullFile(): void {
    const file = this.fullFixFile;
    if (!file || this.fullFix.loading) return;
    if (this.aiCredits < this.fullFixCost) {
      this.showPacks = true;
      return;
    }
    const code = this.analyzedFiles[file];
    this.fullFix = { loading: true, error: null, result: null, rows: [], file };
    this.sastService
      .fixFullFile({
        filename: file,
        language: languageOf(file),
        code,
        findings: this.views
          .filter((v) => v.file === file)
          .map((v) => ({
            title: v.finding.title,
            startLine: v.start,
            endLine: v.end,
            description: v.finding.description,
            remediation: v.finding.remediation,
          })),
      })
      .subscribe({
        next: (result) => {
          this.aiCredits = result.credits;
          this.fullFix = { loading: false, error: null, result, rows: sideBySideDiff(code, result.fixedCode, 1), file };
        },
        error: (error: ApiError) => {
          if (error.code === 'AI_CREDITS_REQUIRED') this.showPacks = true;
          this.fullFix = { loading: false, error: error.message, result: null, rows: [], file };
        },
      });
  }

  /** Compra demonstrativa de créditos (sem cobrança no TCC). */
  protected buyCredits(pack: AiCreditPack): void {
    if (this.buyingPackId) return;
    this.buyingPackId = pack.id;
    this.creditMessage = null;
    this.sastService.purchaseCredits(pack.id).subscribe({
      next: (r) => {
        this.buyingPackId = null;
        this.aiCredits = r.credits;
        this.creditMessage = r.message;
        this.showPacks = false;
      },
      error: (error: ApiError) => {
        this.buyingPackId = null;
        this.creditMessage = error.message;
      },
    });
  }

  /** Copia o arquivo corrigido inteiro. */
  protected copyFixed(): void {
    const code = this.fullFix.result?.fixedCode;
    if (!code) return;
    navigator.clipboard?.writeText(code).then(() => {
      this.copied = true;
      setTimeout(() => (this.copied = false), 1500);
    });
  }

  /** espec.txt 3.2: pede à IA o trecho corrigido e monta o diff lado a lado. */
  protected suggestFix(view: FindingView): void {
    if (view.ai.loading || !view.source.code.trim()) return;
    view.ai = { loading: true, error: null, result: null, rows: [] };
    this.sastService
      .suggestFix({
        code: view.source.code,
        firstLine: view.source.firstLine,
        startLine: view.start,
        endLine: view.end,
        language: languageOf(view.file),
        title: view.finding.title,
        description: view.finding.description,
        remediation: view.finding.remediation,
      })
      .subscribe({
        next: (result) => {
          view.ai = { loading: false, error: null, result, rows: sideBySideDiff(view.source.code, result.fixedCode, view.source.firstLine) };
        },
        error: (error: ApiError) => (view.ai = { loading: false, error: error.message, result: null, rows: [] }),
      });
  }
}

/** Nome da linguagem pela extensão do arquivo, para orientar a IA. */
export const languageOf = (file: string): string => {
  const base = file.split(/[\/]/).pop()?.toLowerCase() ?? '';
  if (base === 'dockerfile' || base === 'containerfile' || base.startsWith('dockerfile.')) return 'Dockerfile';
  // sem extensão (Makefile...): o próprio nome descreve o arquivo
  const ext = base.includes('.') ? base.split('.').pop()! : base;
  const map: Record<string, string> = {
    js: 'JavaScript', mjs: 'JavaScript', cjs: 'JavaScript', jsx: 'JavaScript (React)', ts: 'TypeScript', tsx: 'TypeScript (React)',
    vue: 'Vue', html: 'HTML', htm: 'HTML', py: 'Python', php: 'PHP', rb: 'Ruby', go: 'Go',
    java: 'Java', kt: 'Kotlin', kts: 'Kotlin', scala: 'Scala', cs: 'C#',
    c: 'C', h: 'C', cpp: 'C++', cc: 'C++', cxx: 'C++', hpp: 'C++', hh: 'C++', rs: 'Rust', swift: 'Swift',
    sh: 'Shell (Bash)', bash: 'Shell (Bash)', zsh: 'Shell (Zsh)', tf: 'Terraform', hcl: 'HCL', dockerfile: 'Dockerfile',
    yml: 'YAML', yaml: 'YAML', json: 'JSON', sql: 'SQL', cls: 'Apex', ml: 'OCaml', sol: 'Solidity',
  };
  return map[ext] ?? (ext || 'desconhecida');
};
