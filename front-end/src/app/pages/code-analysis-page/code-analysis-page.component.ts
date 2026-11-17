import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { ApiError } from '../../core/http/api-error';
import { AuthService } from '../../core/services/auth.service';
import { DraftService } from '../../core/services/draft.service';
import { AiFixResult, SAST_MAX_TOTAL_BYTES, SastFinding, SastResult, SastService, parseSastLocation } from '../../core/services/sast.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ChartComponent } from '../../shared/components/chart/chart.component';
import { DOUGHNUT_OPTIONS, severityCountsFrom, severityDoughnut } from '../../shared/ui/chart-data';
import { SEVERITY_LABEL, SEVERITY_ORDER } from '../../shared/ui/labels';
import { CodeLanguage, CodeLine, DiffRow, LANGUAGES, buildCodeView, codeWindow, isAcceptedFile, sideBySideDiff } from './code-view';

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

  ngOnInit(): void {
    const draft = this.drafts.load<CodeDraft>(DRAFT_KEY);
    if (draft.filename && LANGUAGES.some((l) => l.filename === draft.filename)) this.filename = draft.filename;
    this.code = draft.code ?? '';
    if (this.isPremium) {
      this.sastService.aiConfig().subscribe({ next: ({ enabled }) => (this.aiEnabled = enabled), error: () => (this.aiEnabled = false) });
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
  const ext = file.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = { js: 'JavaScript', mjs: 'JavaScript', cjs: 'JavaScript', jsx: 'JavaScript (React)', ts: 'TypeScript', tsx: 'TypeScript (React)', py: 'Python', php: 'PHP', java: 'Java', go: 'Go', rb: 'Ruby', cs: 'C#', kt: 'Kotlin', html: 'HTML', sql: 'SQL', yml: 'YAML', yaml: 'YAML', json: 'JSON' };
  return map[ext] ?? (ext || 'desconhecida');
};
