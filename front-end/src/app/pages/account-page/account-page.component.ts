import { CommonModule } from '@angular/common';
import { Component, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiError } from '../../core/http/api-error';
import { AccountService, LoginAttempt, PrivacyPolicy, TermsOfUse } from '../../core/services/account.service';
import { AuthService, AuthUser, UserPlan, UserRole } from '../../core/services/auth.service';
import { ROLE_VIEWS } from '../../shared/ui/role-views';
import { AppShellComponent } from '../../shared/components/app-shell/app-shell.component';
import { CheckComponent } from '../../shared/components/check/check.component';
import { ROLE_LABEL, formatIp } from '../../shared/ui/labels';
import { DEFAULT_LANGUAGE, LANGUAGES } from '../../shared/ui/languages';

const DELETE_PHRASE = 'EXCLUIR MINHA CONTA';

/** Seções do submenu da conta (uma aberta por vez, sem rolar a página inteira). */
export type AccountSection = 'profile' | 'plan' | 'notifications' | 'language' | 'access' | 'legal' | 'data' | 'delete';

export const ACCOUNT_SECTIONS: { id: AccountSection; label: string; danger?: boolean }[] = [
  { id: 'profile', label: 'Perfil' },
  { id: 'plan', label: 'Plano' },
  { id: 'notifications', label: 'Notificações' },
  { id: 'language', label: 'Idioma dos relatórios' },
  { id: 'access', label: 'Acessos recentes' },
  { id: 'legal', label: 'Documentos legais' },
  { id: 'data', label: 'Baixar meus dados' },
  { id: 'delete', label: 'Excluir conta', danger: true },
];

@Component({
  selector: 'app-account-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, AppShellComponent, CheckComponent],
  templateUrl: './account-page.component.html',
  styleUrl: './account-page.component.scss',
})
export class AccountPageComponent implements OnInit {
  protected readonly sections = ACCOUNT_SECTIONS;
  protected section: AccountSection = 'profile';

  private readonly account = inject(AccountService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected readonly roleLabel = ROLE_LABEL;
  protected readonly formatIp = formatIp;
  protected readonly deletePhrase = DELETE_PHRASE;

  protected user: AuthUser | null = this.auth.getCachedUser();

  protected attempts: LoginAttempt[] = [];
  protected attemptsError: string | null = null;
  // só versão e data; o texto completo abre em /terms e /privacy
  protected terms: TermsOfUse | null = null;
  protected policy: PrivacyPolicy | null = null;

  protected isChangingPlan = false;
  protected planMessage: string | null = null;

  // RF-05 / RF-11: troca de perfil de uso
  protected readonly selectableRoles = (['QA', 'DEV', 'PENTESTER', 'STUDENT'] as const).map((id) => ({ id, ...ROLE_VIEWS[id] }));
  protected isChangingRole = false;

  // RF-22: notificação por e-mail (padrão: ligada)
  protected notifyScanEmail = this.auth.getCachedUser()?.notifyScanEmail ?? true;
  protected notifyMessage: { ok: boolean; text: string } | null = null;

  protected toggleNotify(value: boolean): void {
    const previous = this.notifyScanEmail;
    this.notifyScanEmail = value;
    this.notifyMessage = null;
    this.account.updatePreferences({ notifyScanEmail: value }).subscribe({
      next: () => (this.notifyMessage = { ok: true, text: value ? 'Você vai receber um e-mail quando cada varredura terminar.' : 'Notificações por e-mail desligadas.' }),
      error: (error: ApiError) => {
        this.notifyScanEmail = previous;
        this.notifyMessage = { ok: false, text: error.message };
      },
    });
  }
  /** role: perfil escolhido, mostrado com a cor dele na mensagem de sucesso */
  protected roleMessage: { ok: boolean; text: string; role?: UserRole } | null = null;

  // idioma dos textos dos achados (título, descrição e "como corrigir")
  protected readonly languages = LANGUAGES;
  protected language = this.auth.getCachedUser()?.language ?? DEFAULT_LANGUAGE;
  protected isSavingLanguage = false;
  protected languageMessage: { ok: boolean; text: string } | null = null;

  protected changeLanguage(code: string): void {
    const previous = this.language;
    if (code === previous || this.isSavingLanguage) return;
    this.language = code;
    this.isSavingLanguage = true;
    this.languageMessage = null;
    this.account.updatePreferences({ language: code }).subscribe({
      next: () => {
        this.isSavingLanguage = false;
        this.languageMessage = {
          ok: true,
          text: 'Idioma salvo. Ao abrir uma varredura, os textos dos achados aparecem nele (a primeira abertura pode levar alguns segundos).',
        };
      },
      error: (error: ApiError) => {
        this.isSavingLanguage = false;
        this.language = previous;
        this.languageMessage = { ok: false, text: error.message };
      },
    });
  }

  protected changeRole(role: Exclude<UserRole, 'ADM'>): void {
    if (!this.user || this.isChangingRole || this.user.role === role) return;
    this.isChangingRole = true;
    this.roleMessage = null;
    this.account.changeRole(role).subscribe({
      next: (user) => {
        this.isChangingRole = false;
        this.user = { ...this.user!, role: user.role };
        this.roleMessage = { ok: true, role: user.role, text: 'O painel e os relatórios já seguem o novo perfil.' };
      },
      error: (error: ApiError) => {
        this.isChangingRole = false;
        this.roleMessage = { ok: false, text: error.message };
      },
    });
  }

  // LGPD art. 18: cópia dos dados da conta em JSON
  protected isDownloadingData = false;
  protected myDataError: string | null = null;

  protected downloadMyData(): void {
    if (this.isDownloadingData) return;
    this.isDownloadingData = true;
    this.myDataError = null;
    this.account.downloadMyData().subscribe({
      next: (blob) => {
        this.isDownloadingData = false;
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `checkop-meus-dados-${new Date().toISOString().slice(0, 10)}.json`;
        anchor.click();
        URL.revokeObjectURL(url);
      },
      error: (error: ApiError) => {
        this.isDownloadingData = false;
        this.myDataError = error.message;
      },
    });
  }

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
    // sem resposta, os cartões mostram a descrição genérica
    this.account.termsOfUse().subscribe({ next: (terms) => (this.terms = terms), error: () => undefined });
    this.account.privacyPolicy().subscribe({ next: (policy) => (this.policy = policy), error: () => undefined });
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
        this.planMessage = plan === 'PREMIUM' ? 'Premium ativado.' : 'Você voltou para o plano Free.';
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
