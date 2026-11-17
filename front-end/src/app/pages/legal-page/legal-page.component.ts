import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Observable } from 'rxjs';
import { AccountService, PrivacyPolicy } from '../../core/services/account.service';
import { InlineSegment, MarkdownBlock, inlineSegments, parseSimpleMarkdown, tableOfContents } from '../../shared/ui/markdown';

export type LegalDocument = 'terms' | 'privacy';

const TITLES: Record<LegalDocument, { title: string; other: string; otherLink: string }> = {
  terms: { title: 'Termos de Uso', other: 'Política de Privacidade', otherLink: '/privacy' },
  privacy: { title: 'Política de Privacidade', other: 'Termos de Uso', otherLink: '/terms' },
};

/** Páginas públicas de Termos de Uso e Política de Privacidade (o texto vem do backend). */
@Component({
  selector: 'app-legal-page',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './legal-page.component.html',
  styleUrl: './legal-page.component.scss',
})
export class LegalPageComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly account = inject(AccountService);

  protected doc: LegalDocument = 'terms';
  protected blocks: MarkdownBlock[] = [];
  protected toc: { id: string; text: string }[] = [];
  protected lastUpdated = '';
  protected version = '';
  protected error: string | null = null;
  protected isLoading = true;

  protected get info() {
    return TITLES[this.doc];
  }

  ngOnInit(): void {
    this.doc = (this.route.snapshot.data['doc'] as LegalDocument) ?? 'terms';
    const source: Observable<PrivacyPolicy & { version?: string }> =
      this.doc === 'terms' ? this.account.termsOfUse() : this.account.privacyPolicy();

    source.subscribe({
      next: (document) => {
        // o título vem no topo da página; o "# ..." do texto não se repete
        this.blocks = parseSimpleMarkdown(document.content).filter((b) => b.kind !== 'h1');
        this.toc = tableOfContents(this.blocks);
        this.lastUpdated = document.lastUpdated;
        this.version = document.version ?? '';
        this.isLoading = false;
      },
      error: () => {
        this.error = 'Não foi possível carregar o documento. Verifique se a API está rodando e tente de novo.';
        this.isLoading = false;
      },
    });
  }

  protected segments(block: MarkdownBlock): InlineSegment[] {
    return 'text' in block ? inlineSegments(block.text) : [];
  }

  protected items(block: MarkdownBlock): InlineSegment[][] {
    return 'items' in block ? block.items.map(inlineSegments) : [];
  }

  protected anchor(block: MarkdownBlock): string | null {
    return block.kind === 'h2' ? block.id : null;
  }

  protected print(): void {
    window.print();
  }
}
