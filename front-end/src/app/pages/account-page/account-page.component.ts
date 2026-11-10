import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiError } from '../../core/http/api-error';
import { AccountService, LoginAttempt } from '../../core/services/account.service';
import { AuthService, AuthUser, UserPlan } from '../../core/services/auth.service';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { CheckComponent } from '../../shared/components/check/check.component';
import { ROLE_LABEL } from '../../shared/ui/labels';
import { MarkdownBlock, parseSimpleMarkdown } from '../../shared/ui/markdown';

// o parser fica em shared/ui/markdown.ts (também usado nas páginas públicas de termos/privacidade)
export type PolicyBlock = MarkdownBlock;
export const parsePolicy = parseSimpleMarkdown;

const DELETE_PHRASE = 'EXCLUIR MINHA CONTA';

// espec.txt: o que cada plano mostra
// lista completa em shared/ui/plans.ts (tela de Planos)
export const PLAN_FEATURES: { label: string; free: boolean; premium: boolean }[] = [
  { label: 'Varreduras com os 24 tipos de falha', free: true, premium: true },
  { label: 'Diagnóstico, severidade e gráficos', free: true, premium: true },
  { label: 'Correção exata de cada falha', free: false, premium: true },
  { label: 'Prova de conceito (payload e evidência)', free: false, premium: true },
  { label: 'Painel de compliance LGPD / PCI-DSS', free: false, premium: true },
  { label: 'Análise de código-fonte (SAST)', free: false, premium: true },
];

@Component({
  selector: 'app-account-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, AppShellComponent, CheckComponent],
  templateUrl: './account-page.component.html',
  styleUrl: './account-page.component.scss',
})
export class AccountPageComponent implements OnInit {
  private readonly account = inject(AccountService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected readonly roleLabel = ROLE_LABEL;
  protected readonly planFeatures = PLAN_FEATURES;
  protected readonly deletePhrase = DELETE_PHRASE;

  protected user: AuthUser | null = this.auth.getCachedUser();

  protected attempts: LoginAttempt[] = [];
  protected attemptsError: string | null = null;
  protected policy: PolicyBlock[] = [];
  protected policyUpdated = '';

  protected isChangingPlan = false;
  protected planMessage: string | null = null;

  protected googleAccount = false;
  protected deletePassword = '';
  protected deleteConfirmation = '';
  protected deleteAcknowledged = false;
  protected isDeleting = false;
  protected deleteError: string | null = null;

  ngOnInit(): void {
    this.account.loginHistory().subscribe({
      next: (attempts) => (this.attempts = attempts),
      error: (error: ApiError) => (this.attemptsError = error.message),
    });
    this.account.privacyPolicy().subscribe({
      next: (policy) => {
        this.policy = parsePolicy(policy.content);
        this.policyUpdated = policy.lastUpdated;
      },
      error: () => (this.policy = [{ kind: 'p', text: 'Não foi possível carregar a política de privacidade.' }]),
    });
  }

  protected get isPremium(): boolean {
    return this.user?.plan === 'PREMIUM';
  }

  protected changePlan(plan: UserPlan): void {
    if (this.isChangingPlan) return;
    this.isChangingPlan = true;
    this.planMessage = null;
    this.account.changePlan(plan).subscribe({
      next: (user) => {
        this.isChangingPlan = false;
        this.user = { ...this.user!, plan: user.plan };
        this.planMessage = plan === 'PREMIUM' ? 'Premium ativado (demonstração, sem cobrança).' : 'Você voltou para o plano Free.';
      },
      error: (error: ApiError) => {
        this.isChangingPlan = false;
        this.planMessage = error.message;
      },
    });
  }

  protected get canDelete(): boolean {
    const proof = this.googleAccount ? this.deleteConfirmation === DELETE_PHRASE : this.deletePassword.length > 0;
    return proof && this.deleteAcknowledged && !this.isDeleting;
  }

  protected deleteAccount(): void {
    if (!this.canDelete) return;
    this.isDeleting = true;
    this.deleteError = null;
    const body = this.googleAccount ? { confirmation: this.deleteConfirmation } : { password: this.deletePassword };
    this.account.deleteAccount(body).subscribe({
      next: () => this.router.navigateByUrl('/landing'),
      error: (error: ApiError) => {
        this.isDeleting = false;
        this.deleteError = error.message;
      },
    });
  }

  protected browser(userAgent: string | null): string {
    if (!userAgent) return 'Desconhecido';
    const browser = /Edg\//.test(userAgent) ? 'Edge' : /Chrome\//.test(userAgent) ? 'Chrome' : /Firefox\//.test(userAgent) ? 'Firefox' : /Safari\//.test(userAgent) ? 'Safari' : 'Outro';
    const os = /Windows/.test(userAgent) ? 'Windows' : /Android/.test(userAgent) ? 'Android' : /iPhone|iPad/.test(userAgent) ? 'iOS' : /Mac OS/.test(userAgent) ? 'macOS' : /Linux/.test(userAgent) ? 'Linux' : '';
    return os ? `${browser} · ${os}` : browser;
  }
}
