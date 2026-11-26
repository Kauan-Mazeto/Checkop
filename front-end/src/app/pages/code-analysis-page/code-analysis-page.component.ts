import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ChartData, ChartOptions } from 'chart.js';
import { ApiError } from '../../core/http/api-error';
import { AuthService } from '../../core/services/auth.service';
import { DraftService } from '../../core/services/draft.service';
import { AiFixResult, SAST_MAX_TOTAL_BYTES, SastFinding, SastResult, SastService, parseSastLocation, AiCreditPack, FullFixResult, SastCategory, SastDepth } from '../../core/services/sast.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ChartComponent } from '../../shared/components/chart/chart.component';
import { DOUGHNUT_OPTIONS, severityCountsFrom, severityDoughnut } from '../../shared/ui/chart-data';
import { SEVERITY_LABEL, SEVERITY_ORDER } from '../../shared/ui/labels';
import { highlightCode } from './highlight';
import { languageMismatch } from './language-detect';
import { CodeLanguage, CodeLine, DiffRow, LANGUAGES, LANGUAGE_GROUPS, buildCodeView, codeWindow, isAcceptedFile, sideBySideDiff } from './code-view';

type InputMode = 'paste' | 'upload';

interface FindingView {
  finding: SastFinding;
  file: string;
  start: number;
  end: number;
  code: CodeLine[];
  /** título sem o "(arquivo:linha)" do fim e sem o código técnico da regra */
  displayTitle: string;
  /** código da regra que vinha entre parênteses (eqeqeq, DL3064, SC2035...) */
  ruleCode: string | null;
  /** rótulo do trecho: "Código inseguro" só para falha de segurança */
  snippetLabel: string;
  /** correção sem as referências, que viram links logo abaixo */
  fixText: string;
  references: { url: string; label: string }[];
  /** janela enviada para a IA quando o usuário pede a correção */
  source: { code: string; firstLine: number };
  ai: { loading: boolean; error: string | null; result: AiFixResult | null; rows: DiffRow[] };
}

interface CodeDraft {
  filename: string;
  code: string;
  depth?: SastDepth;
}

const DRAFT_KEY = 'code-analysis';
// último resultado: sobrevive ao F5 (sessionStorage da aba), some ao fechar a aba
const RESULT_KEY = 'code-analysis-result';
const RESULT_MAX_CHARS = 4_000_000;

interface SavedResult {
  result: SastResult;
  files: Record<string, string>;
}

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

  // tipo do problema: sintaxe, lógica, segurança ou dependência (filtro da lista)
  protected readonly categoryLabel: Record<SastCategory, string> = {
    SYNTAX: 'Sintaxe', LOGIC: 'Lógica', SECURITY: 'Segurança', DEPENDENCY: 'Dependência', QUALITY: 'Boa prática',
  };
  protected readonly categoryOrder: SastCategory[] = ['SECURITY', 'DEPENDENCY', 'LOGIC', 'SYNTAX', 'QUALITY'];
  protected categoryFilter: SastCategory | 'ALL' = 'ALL';
  protected categoryCounts: Record<SastCategory, number> = { SYNTAX: 0, LOGIC: 0, SECURITY: 0, DEPENDENCY: 0, QUALITY: 0 };

  // profundidade da análise: completa (padrão) ou essencial
  protected depth: SastDepth = 'COMPLETE';
  protected readonly depthOptions: { id: SastDepth; label: string; hint: string }[] = [
    { id: 'COMPLETE', label: 'Completa', hint: 'Todas as regras de todas as ferramentas: segurança, erros de lógica e de sintaxe, dependências e boas práticas.' },
    { id: 'ESSENTIAL', label: 'Essencial', hint: 'Só o mais importante: falhas de segurança, bugs e erros de sintaxe. Mais rápida e direta.' },
  ];

  protected setDepth(depth: SastDepth): void {
    this.depth = depth;
    this.saveDraft();
  }
  protected visibleViews: FindingView[] = [];

  protected categoryOf(view: FindingView): SastCategory {
    return view.finding.category ?? 'SECURITY';
  }

  protected setCategory(category: SastCategory | 'ALL'): void {
    this.categoryFilter = category;
    this.visibleViews = category === 'ALL' ? this.views : this.views.filter((v) => this.categoryOf(v) === category);
  }
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
    this.updateLineNumbers();
    if (draft.depth === 'ESSENTIAL' || draft.depth === 'COMPLETE') this.depth = draft.depth;
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
    // resultado da análise anterior desta aba (F5 não apaga)
    const saved = this.drafts.load<SavedResult>(RESULT_KEY);
    if (saved.result && saved.files) {
      this.analyzedFiles = saved.files;
      this.applyResult(saved.result);
    }
  }

  protected get language(): CodeLanguage {
    return LANGUAGES.find((l) => l.filename === this.filename) ?? LANGUAGES[0];
  }

  protected get uploadedNames(): string[] {
    return Object.keys(this.uploaded);
  }

  protected saveDraft(): void {
    this.updateLineNumbers();
    this.drafts.save<CodeDraft>(DRAFT_KEY, { filename: this.filename, code: this.code, depth: this.depth });
  }

  /** Linguagem detectada quando a análise foi barrada por não bater com a escolhida. */
  protected languageSuggestion: CodeLanguage | null = null;

  /** Botão do aviso: troca para a linguagem detectada (a análise continua manual). */
  protected useSuggestedLanguage(): void {
    if (!this.languageSuggestion) return;
    this.filename = this.languageSuggestion.filename;
    this.languageSuggestion = null;
    this.error = null;
    this.saveDraft();
  }

  protected loadExample(): void {
    this.code = this.language.example;
    this.saveDraft();
  }

  // ---------- editor estilo IDE ----------
  /** números da calha; campo (não getter) para não recriar o array a cada detecção */
  protected lineNumbers: number[] = [1];
  protected cursor = { line: 1, col: 1 };
  /** código colorido (fica atrás do textarea transparente); recalculado só quando o código muda */
  protected highlighted = '';

  private updateLineNumbers(): void {
    const count = Math.max(1, this.code.split('\n').length);
    if (count !== this.lineNumbers.length) this.lineNumbers = Array.from({ length: count }, (_, i) => i + 1);
    // o espaço final mantém a última linha vazia com altura, igual ao textarea
    this.highlighted = highlightCode(this.code, this.filename) + '\n ';
  }

  /** calha de números e camada colorida acompanham a rolagem do código */
  protected syncGutter(textarea: HTMLTextAreaElement, gutter: HTMLElement, colors: HTMLElement): void {
    gutter.scrollTop = textarea.scrollTop;
    colors.scrollTop = textarea.scrollTop;
    colors.scrollLeft = textarea.scrollLeft;
  }

  protected updateCursor(textarea: HTMLTextAreaElement): void {
    const before = textarea.value.slice(0, textarea.selectionStart);
    const lines = before.split('\n');
    this.cursor = { line: lines.length, col: lines[lines.length - 1].length + 1 };
  }

  /** Tab indenta (4 espaços) em vez de pular para o próximo campo, como num editor */
  protected onEditorTab(event: Event, textarea: HTMLTextAreaElement): void {
    event.preventDefault();
    const { selectionStart: s, selectionEnd: e } = textarea;
    this.code = this.code.slice(0, s) + '    ' + this.code.slice(e);
    textarea.value = this.code;
    textarea.selectionStart = textarea.selectionEnd = s + 4;
    this.saveDraft();
    this.updateCursor(textarea);
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

    // a linguagem escolhida decide quais ferramentas rodam: código Python analisado como
    // JavaScript não passa pelo Ruff/Bandit e o resultado sai pobre. Bloqueia e avisa.
    this.languageSuggestion = null;
    if (this.mode === 'paste') {
      const detected = languageMismatch(this.code, this.filename);
      const suggestion = detected ? LANGUAGES.find((l) => l.filename === detected) ?? null : null;
      if (suggestion) {
        this.languageSuggestion = suggestion;
        this.needsPremium = false;
        this.error =
          `O código parece ser ${suggestion.label}, mas a linguagem selecionada é ${this.language.label}. ` +
          'Com a linguagem errada, as ferramentas certas não rodam e o resultado sai incompleto. ' +
          'Troque a linguagem e analise de novo.';
        return;
      }
    }

    this.isAnalyzing = true;
    this.error = null;
    this.needsPremium = false;
    this.result = null;
    this.analyzedFiles = files;
    this.fullFix = { loading: false, error: null, result: null, rows: [], file: null };
    this.drafts.clear(RESULT_KEY);

    this.sastService.analyze(files, this.depth).subscribe({
      next: (result) => {
        this.isAnalyzing = false;
        this.applyResult(result);
        // guarda para o F5; resultado gigante (upload de muitos arquivos) não cabe no navegador
        const saved: SavedResult = { result, files };
        if (JSON.stringify(saved).length <= RESULT_MAX_CHARS) this.drafts.save<SavedResult>(RESULT_KEY, saved);
      },
      error: (error: ApiError) => {
        this.isAnalyzing = false;
        this.error = error.message;
        this.needsPremium = error.code === 'PREMIUM_REQUIRED';
      },
    });
  }

  private applyResult(result: SastResult): void {
    this.result = result;
    this.views = this.buildViews(result.findings);
    this.categoryCounts = { SYNTAX: 0, LOGIC: 0, SECURITY: 0, DEPENDENCY: 0, QUALITY: 0 };
    for (const v of this.views) this.categoryCounts[this.categoryOf(v)]++;
    this.setCategory('ALL');
    this.severityChart = severityDoughnut(severityCountsFrom(result.findings)) as ChartData;
  }

  /** Limpa o resultado salvo (botão "Limpar resultado"). */
  protected clearResult(): void {
    this.drafts.clear(RESULT_KEY);
    this.result = null;
    this.views = [];
    this.visibleViews = [];
    this.fullFix = { loading: false, error: null, result: null, rows: [], file: null };
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
        const { title, ruleCode } = splitTitle(finding.title, file);
        const { text, references } = splitReferences(finding.remediation ?? '');
        return {
          finding, file, start, end, code, source,
          displayTitle: title, ruleCode,
          snippetLabel: SNIPPET_LABEL[finding.category ?? 'SECURITY'],
          fixText: text, references,
          ai: { loading: false, error: null, result: null, rows: [] },
        };
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

/** Rótulo do trecho destacado conforme o tipo: código com erro não é "inseguro". */
const SNIPPET_LABEL: Record<SastCategory, string> = {
  SECURITY: 'Código inseguro',
  DEPENDENCY: 'Dependência vulnerável',
  LOGIC: 'Código com erro de lógica',
  SYNTAX: 'Erro de sintaxe',
  QUALITY: 'Ponto a melhorar',
};

/**
 * "Boa prática (eqeqeq) (app.js:24)" vira título "Boa prática" + código "eqeqeq".
 * Sai o "(arquivo:linha)" do fim (o arquivo já aparece no visualizador) e o
 * identificador técnico entre parênteses (com minúscula, dígito ou hífen). Siglas
 * como "(XSS)" e explicações com espaço "(pode quebrar ...)" ficam no título.
 */
export const splitTitle = (raw: string, file: string): { title: string; ruleCode: string | null } => {
  let title = raw.trim();
  const at = title.lastIndexOf(` (${file}:`);
  if (at > 0 && title.endsWith(')')) title = title.slice(0, at).trim();
  const match = /^(.*\S)\s*\(([^()\s]+|[A-Za-z]+ [A-Z]+\d+)\)$/.exec(title);
  if (match && /[a-z0-9@-]/.test(match[2]) && !/^[A-Z/]+$/.test(match[2])) {
    return { title: match[1], ruleCode: match[2] };
  }
  return { title, ruleCode: null };
};

/** Tira "Referência: <url>" (e URLs soltas) do texto da correção e devolve como links. */
export const splitReferences = (raw: string): { text: string; references: { url: string; label: string }[] } => {
  const urls = Array.from(new Set(raw.match(/https?:\/\/[^\s)<>"']+/g) ?? [])).map((u) => u.replace(/[.,;]+$/, ''));
  const text = raw
    .replace(/Refer[eê]ncias?:\s*/gi, '')
    .replace(/https?:\/\/[^\s)<>"']+/g, '')
    .replace(/\s+([.,;])/g, '$1')
    .replace(/[ \t]+\n/g, '\n')
    .trim();
  const references = urls.map((url) => {
    try {
      const u = new URL(url);
      return { url, label: u.hostname.replace(/^www\./, '') + (u.hash ? ` · ${decodeURIComponent(u.hash.slice(1))}` : '') };
    } catch {
      return { url, label: url };
    }
  });
  return { text, references };
};

/** Nome da linguagem pela extensão do arquivo, para orientar a IA. */
export const languageOf = (file: string): string => {
  const base = file.split(/[\/]/).pop()?.toLowerCase() ?? '';
  if (base === 'dockerfile' || base === 'containerfile' || base.startsWith('dockerfile.')) return 'Dockerfile';
  const manifests: Record<string, string> = {
    'requirements.txt': 'Dependências Python (pip)', 'go.mod': 'Dependências Go (go.mod)', 'pom.xml': 'Dependências Java (Maven)',
    'package-lock.json': 'Dependências Node (npm)', 'composer.lock': 'Dependências PHP (Composer)', 'cargo.lock': 'Dependências Rust (Cargo)',
  };
  if (manifests[base]) return manifests[base];
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
