import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Observable } from 'rxjs';
import { AccountService, PrivacyPolicy } from '../../core/services/account.service';
import { MarkdownBlock, parseSimpleMarkdown } from '../../shared/ui/markdown';

export type LegalDocument = 'terms' | 'privacy';

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
  protected lastUpdated = '';
  protected version = '';
  protected error: string | null = null;
  protected isLoading = true;

  ngOnInit(): void {
    this.doc = (this.route.snapshot.data['doc'] as LegalDocument) ?? 'terms';
    const source: Observable<PrivacyPolicy & { version?: string }> =
      this.doc === 'terms' ? this.account.termsOfUse() : this.account.privacyPolicy();

    source.subscribe({
      next: (document) => {
        this.blocks = parseSimpleMarkdown(document.content);
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

  protected asText(block: MarkdownBlock): string {
    return 'text' in block ? block.text : '';
  }

  protected asItems(block: MarkdownBlock): string[] {
    return 'items' in block ? block.items : [];
  }
}
