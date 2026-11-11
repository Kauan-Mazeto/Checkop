import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ApiError } from '../../core/http/api-error';
import { DraftService } from '../../core/services/draft.service';
import { Target, TargetService, VerificationMethod } from '../../core/services/target.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';

interface MethodOption {
  value: VerificationMethod;
  label: string;
  description: string;
}

// Os três métodos da seção 9 do TCC (backend/src/lib/target_verification.js).
export const METHOD_OPTIONS: MethodOption[] = [
  {
    value: 'DNS_TXT',
    label: 'Registro DNS (TXT)',
    description: 'Prova o domínio inteiro e todos os subdomínios. Feito no painel do seu provedor de DNS.',
  },
  {
    value: 'HTTP_FILE',
    label: 'Arquivo no site',
    description: 'Publique um arquivo em /.well-known/. Vale só para o endereço exato.',
  },
  {
    value: 'META_TAG',
    label: 'Meta tag no HTML',
    description: 'Adicione uma tag no <head> da página inicial. Vale só para o endereço exato.',
  },
];

export const METHOD_LABEL: Record<VerificationMethod, string> = {
  DNS_TXT: 'DNS TXT',
  HTTP_FILE: 'Arquivo',
  META_TAG: 'Meta tag',
};

@Component({
  selector: 'app-targets-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, AppShellComponent],
  templateUrl: './targets-page.component.html',
  styleUrl: './targets-page.component.scss',
})
export class TargetsPageComponent implements OnInit {
  private readonly targetService = inject(TargetService);
  private readonly route = inject(ActivatedRoute);
  private readonly drafts = inject(DraftService);

  protected readonly methodOptions = METHOD_OPTIONS;
  protected readonly methodLabel = METHOD_LABEL;

  protected targets: Target[] = [];
  protected isLoading = true;
  protected loadError: string | null = null;

  protected newUrl = '';
  protected newMethod: VerificationMethod = 'DNS_TXT';
  protected isCreating = false;
  protected createError: string | null = null;

  /** alvo com as instruções abertas */
  protected expandedId: string | null = null;
  protected verifyingId: string | null = null;
  protected feedback: Record<string, { type: 'success' | 'error'; text: string }> = {};
  protected copiedKey: string | null = null;

  ngOnInit(): void {
    // vindo de "Nova varredura" com TARGET_NOT_VERIFIED, a URL já chega preenchida
    const draft = this.drafts.load<{ url: string; method: VerificationMethod }>('new-target');
    this.newUrl = this.route.snapshot.queryParamMap.get('url') ?? draft.url ?? '';
    this.newMethod = draft.method ?? 'DNS_TXT';
    this.load();
  }

  protected load(): void {
    this.isLoading = true;
    this.targetService.listTargets().subscribe({
      next: (targets) => {
        this.targets = targets;
        this.isLoading = false;
        this.expandedId ??= targets.find((t) => !t.verified)?.id ?? null;
      },
      error: (error: ApiError) => {
        this.loadError = error.message;
        this.isLoading = false;
      },
    });
  }

  protected saveDraft(): void {
    this.drafts.save('new-target', { url: this.newUrl, method: this.newMethod });
  }

  protected create(): void {
    if (this.isCreating) return;
    if (!this.newUrl.trim()) {
      this.createError = 'Informe a URL do site que você quer verificar.';
      return;
    }

    this.isCreating = true;
    this.createError = null;

    this.targetService.createTarget(this.newUrl.trim(), this.newMethod).subscribe({
      next: (target) => {
        this.isCreating = false;
        this.targets = [target, ...this.targets];
        this.expandedId = target.id;
        this.newUrl = '';
        this.drafts.clear('new-target');
      },
      error: (error: ApiError) => {
        this.isCreating = false;
        // 409: já cadastrado — abre o existente em vez de só mostrar erro
        const existing = error.status === 409 ? (error.body?.['target'] as Target | undefined) : undefined;
        if (existing) {
          this.expandedId = existing.id;
          this.createError = 'Este alvo já está cadastrado; as instruções estão abertas abaixo.';
          return;
        }
        this.createError = error.message;
      },
    });
  }

  protected verify(target: Target): void {
    if (this.verifyingId) return;
    this.verifyingId = target.id;
    delete this.feedback[target.id];

    this.targetService.verifyTarget(target.id).subscribe({
      next: (updated) => {
        this.verifyingId = null;
        this.replace(updated);
        this.feedback[target.id] = { type: 'success', text: 'Domínio verificado! Você já pode varrer este site.' };
      },
      error: (error: ApiError) => {
        this.verifyingId = null;
        const updated = error.body?.['target'] as Target | undefined;
        if (updated) this.replace(updated);
        this.feedback[target.id] = { type: 'error', text: error.message };
      },
    });
  }

  protected remove(target: Target): void {
    if (!confirm(`Remover o alvo ${target.hostname}? As varreduras já feitas continuam no histórico.`)) return;
    this.targetService.deleteTarget(target.id).subscribe({
      next: () => (this.targets = this.targets.filter((t) => t.id !== target.id)),
      error: (error: ApiError) => (this.feedback[target.id] = { type: 'error', text: error.message }),
    });
  }

  protected toggle(target: Target): void {
    this.expandedId = this.expandedId === target.id ? null : target.id;
  }

  protected copy(value: string | undefined, key: string): void {
    if (!value) return;
    navigator.clipboard?.writeText(value).then(() => {
      this.copiedKey = key;
      setTimeout(() => (this.copiedKey = this.copiedKey === key ? null : this.copiedKey), 1500);
    });
  }

  private replace(updated: Target): void {
    this.targets = this.targets.map((t) => (t.id === updated.id ? updated : t));
  }
}
