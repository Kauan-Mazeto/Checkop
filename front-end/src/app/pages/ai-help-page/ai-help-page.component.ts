import { DatePipe, NgTemplateOutlet } from '@angular/common';
import { Component, ElementRef, OnInit, ViewChild, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ApiError } from '../../core/http/api-error';
import { AuthService } from '../../core/services/auth.service';
import { AiChatMessage, AiHelpContext, AiHelpKind, AiHelpService, AiHelpSources } from '../../core/services/ai-help.service';
import { AiCreditPack, SastService } from '../../core/services/sast.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { ChatBlock, chatInline, parseChatMarkdown } from '../../shared/ui/chat-markdown';

interface ChatTurn extends AiChatMessage {
  blocks?: ChatBlock[];
  truncated?: boolean;
}

const MAX_QUESTION_CHARS = 2000;
// o backend aceita até 20 falas; a 19ª é a última pergunta possível
const MAX_TURNS = 19;

const SUGGESTIONS: Record<AiHelpKind, string[]> = {
  scan: [
    'O que devo corrigir primeiro e por quê?',
    'Explique a falha mais grave em termos simples.',
    'Quais destes achados podem ser falso positivo?',
    'Como eu confirmo que a correção funcionou?',
  ],
  code: [
    'Quais arquivos devo corrigir primeiro?',
    'Explique a falha mais grave e como corrigir.',
    'Monte um plano de correção em etapas.',
    'Que boas práticas evitariam esses erros?',
  ],
};

/**
 * Ajuda por IA: a pessoa escolhe uma varredura ou análise de código, vê exatamente
 * o que será enviado ao provedor de IA e pergunta. Cada pergunta usa 1 crédito de IA.
 * A conversa fica só nesta tela (não é gravada no servidor nem no navegador).
 */
@Component({
  selector: 'app-ai-help-page',
  standalone: true,
  imports: [AppShellComponent, FormsModule, RouterLink, DatePipe, NgTemplateOutlet],
  templateUrl: './ai-help-page.component.html',
  styleUrl: './ai-help-page.component.scss',
})
export class AiHelpPageComponent implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly aiHelp = inject(AiHelpService);
  private readonly sast = inject(SastService);
  private readonly route = inject(ActivatedRoute);

  @ViewChild('thread') private thread?: ElementRef<HTMLElement>;

  protected readonly isPremium = this.auth.getCachedUser()?.plan === 'PREMIUM';
  protected readonly isStudent = this.auth.getCachedUser()?.role === 'STUDENT';
  protected readonly maxQuestion = MAX_QUESTION_CHARS;
  protected readonly inline = chatInline;

  protected loading = true;
  protected loadError = '';
  protected sources: AiHelpSources | null = null;

  protected kind: AiHelpKind = 'scan';
  protected selectedId = '';
  protected context: AiHelpContext | null = null;
  protected contextLoading = false;
  protected contextError = '';
  /** a pessoa confirmou que viu o que vai ser enviado (vale para o item escolhido) */
  protected consent = false;

  protected turns: ChatTurn[] = [];
  protected question = '';
  protected sending = false;
  protected chatError = '';

  protected packs: AiCreditPack[] = [];
  protected showPacks = false;
  protected buyingPackId: string | null = null;
  protected creditMessage = '';

  ngOnInit(): void {
    if (!this.isPremium) {
      this.loading = false;
      return;
    }
    this.aiHelp.sources().subscribe({
      next: (sources) => {
        this.sources = sources;
        this.loading = false;
        // atalho vindo de outra tela: /ai-help?kind=scan&id=...
        const params = this.route.snapshot.queryParamMap;
        const kind = params.get('kind') === 'code' ? 'code' : params.get('kind') === 'scan' ? 'scan' : null;
        const id = params.get('id');
        if (kind && id) {
          this.kind = kind;
          this.select(id);
        } else if (sources.scans.length === 0 && sources.analyses.length > 0) {
          this.kind = 'code';
        }
      },
      error: (error: ApiError) => {
        this.loadError = error.message;
        this.loading = false;
      },
    });
    this.sast.aiConfig().subscribe({ next: (config) => (this.packs = config.packs), error: () => (this.packs = []) });
  }

  protected get items(): { id: string; label: string; meta: string; date: string }[] {
    if (!this.sources) return [];
    return this.kind === 'scan'
      ? this.sources.scans.map((s) => ({ id: s.id, label: s.targetUrl.replace(/^https?:\/\//, ''), meta: `${s.findingsCount} achados`, date: s.createdAt }))
      : this.sources.analyses.map((a) => ({
          id: a.id,
          label: a.files.length > 1 ? `${a.files[0]} +${a.files.length - 1}` : (a.files[0] ?? 'análise'),
          meta: `${a.findingsCount} achados`,
          date: a.createdAt,
        }));
  }

  protected get suggestions(): string[] {
    const base = SUGGESTIONS[this.kind];
    return this.isStudent ? ['Explique estes resultados como se eu estivesse começando.', ...base.slice(0, 3)] : base;
  }

  protected get credits(): number {
    return this.sources?.credits ?? 0;
  }

  /** quem recebe os dados (Anthropic ou Google), mostrado antes do envio */
  protected get provider(): string {
    return this.sources?.provider ?? 'provedor de IA';
  }

  /** Gemini no plano gratuito: o Google pode usar o conteúdo para melhorar os produtos dele */
  protected get isFreeTier(): boolean {
    return /gemini/i.test(this.sources?.provider ?? '');
  }

  protected get cost(): number {
    return this.sources?.cost ?? 1;
  }

  protected get canAsk(): boolean {
    const q = this.question.trim();
    return !!this.context && this.consent && !this.sending && q.length > 0 && q.length <= MAX_QUESTION_CHARS && this.turns.length < MAX_TURNS;
  }

  protected setKind(kind: AiHelpKind): void {
    if (kind === this.kind || !this.confirmReset()) return;
    this.kind = kind;
    this.clearSelection();
  }

  protected select(id: string): void {
    if (id === this.selectedId) return;
    if (!this.confirmReset()) return;
    this.clearSelection();
    this.selectedId = id;
    this.contextLoading = true;
    this.aiHelp.context(this.kind, id).subscribe({
      next: (context) => {
        this.context = context;
        this.contextLoading = false;
      },
      error: (error: ApiError) => {
        this.contextError = error.message;
        this.contextLoading = false;
      },
    });
  }

  private clearSelection(): void {
    this.selectedId = '';
    this.context = null;
    this.contextError = '';
    this.consent = false;
    this.turns = [];
    this.chatError = '';
  }

  /** Trocar de item apaga a conversa: avisa antes, se houver uma. */
  private confirmReset(): boolean {
    return this.turns.length === 0 || confirm('Trocar de item apaga esta conversa (ela não é salva). Continuar?');
  }

  protected newConversation(): void {
    if (this.turns.length && !confirm('Apagar esta conversa e começar outra?')) return;
    this.turns = [];
    this.chatError = '';
  }

  protected useSuggestion(text: string): void {
    this.question = text;
  }

  protected onKeydown(event: KeyboardEvent): void {
    // Enter envia; Shift+Enter quebra a linha
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      this.send();
    }
  }

  protected send(): void {
    if (!this.canAsk || !this.context) return;
    if (this.credits < this.cost) {
      this.chatError = 'Você não tem créditos de IA. Compre um pacote para perguntar.';
      this.showPacks = true;
      return;
    }
    const question = this.question.trim();
    this.turns = [...this.turns, { role: 'user', content: question }];
    this.question = '';
    this.sending = true;
    this.chatError = '';
    this.scrollDown();

    const messages: AiChatMessage[] = this.turns.map(({ role, content }) => ({ role, content }));
    this.aiHelp.chat(this.kind, this.selectedId, messages).subscribe({
      next: (result) => {
        this.turns = [...this.turns, { role: 'assistant', content: result.answer, blocks: parseChatMarkdown(result.answer), truncated: result.truncated }];
        if (this.sources) this.sources = { ...this.sources, credits: result.credits };
        this.sending = false;
        this.scrollDown();
      },
      error: (error: ApiError) => {
        // a pergunta volta para a caixa, para não perder o texto
        this.turns = this.turns.slice(0, -1);
        this.question = question;
        this.chatError = error.message + (error.body?.['refunded'] ? ' O crédito foi devolvido.' : '');
        if (error.code === 'AI_CREDITS_REQUIRED') this.showPacks = true;
        this.sending = false;
      },
    });
  }

  protected buyCredits(pack: AiCreditPack): void {
    this.buyingPackId = pack.id;
    this.sast.purchaseCredits(pack.id).subscribe({
      next: (r) => {
        this.buyingPackId = null;
        if (this.sources) this.sources = { ...this.sources, credits: r.credits };
        this.creditMessage = r.message;
        this.showPacks = false;
        this.chatError = '';
      },
      error: (error: ApiError) => {
        this.buyingPackId = null;
        this.creditMessage = error.message;
      },
    });
  }

  private scrollDown(): void {
    setTimeout(() => {
      const el = this.thread?.nativeElement;
      if (el) el.scrollTop = el.scrollHeight;
    });
  }
}
