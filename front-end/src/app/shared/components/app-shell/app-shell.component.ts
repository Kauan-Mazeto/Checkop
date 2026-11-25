import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink } from '@angular/router';
import { filter } from 'rxjs';
import { ApiError } from '../../../core/http/api-error';
import { AccountService } from '../../../core/services/account.service';
import { AuthService, AuthUser, TermsStatus } from '../../../core/services/auth.service';
import { GoogleAuthService } from '../../../core/services/google-auth.service';
import { CheckComponent } from '../check/check.component';
import { ROLE_LABEL } from '../../ui/labels';
import { planOf } from '../../ui/plans';

interface NavItem {
  path: string;
  label: string;
  /** recurso que o plano atual não libera: mostra o selo PRO */
  locked?: (user: AuthUser | null) => boolean;
  /** decide se o item está ativo para a URL atual */
  match: (url: string) => boolean;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Visão geral',
    items: [{ path: '/dashboard', label: 'Painel', match: (u) => u.startsWith('/dashboard') }],
  },
  {
    label: 'Varreduras',
    items: [
      { path: '/scans/new', label: 'Nova varredura', match: (u) => u.startsWith('/scans/new') },
      {
        path: '/scans',
        label: 'Histórico',
        locked: (user) => !planOf(user).canViewHistory,
        match: (u) => /^\/scans(\/(?!new)[^/?#]+)?([?#].*)?$/.test(u),
      },
    ],
  },
  {
    label: 'Segurança',
    items: [
      { path: '/targets', label: 'Domínios', match: (u) => u.startsWith('/targets') },
      {
        path: '/code-analysis',
        label: 'Análise de código',
        locked: (user) => !planOf(user).canAnalyzeCode,
        match: (u) => u.startsWith('/code-analysis'),
      },
    ],
  },
  {
    label: 'Conta',
    items: [
      { path: '/plans', label: 'Planos', match: (u) => u.startsWith('/plans') },
      { path: '/account', label: 'Conta e privacidade', match: (u) => u.startsWith('/account') },
    ],
  },
];

const HIGH_CONTRAST_KEY = 'checkop-high-contrast';

// preferência só deste navegador; sem storage (aba anônima) vale o padrão
const readHighContrast = (): boolean => {
  try {
    return localStorage.getItem(HIGH_CONTRAST_KEY) === '1';
  } catch {
    return false;
  }
};

const saveHighContrast = (value: boolean): void => {
  try {
    localStorage.setItem(HIGH_CONTRAST_KEY, value ? '1' : '0');
  } catch {
    // sem storage: a escolha vale só até recarregar
  }
};

/**
 * Layout das telas logadas, no visual da branch `front` (Kauan): menu lateral
 * fixo com o perfil e o plano no rodapé, alto contraste e conteúdo à esquerda.
 * Estilos em src/styles/_app-ui.scss (escopo .ck-app).
 */
@Component({
  selector: 'app-shell',
  standalone: true,
  imports: [CommonModule, RouterLink, CheckComponent],
  template: `
    <div class="ck-app" [class.high-contrast]="highContrast">
      <div class="app-layout">
        <aside class="sidebar" [class.open]="menuOpen" aria-label="Menu principal">
          <a class="brand" routerLink="/dashboard" (click)="menuOpen = false">
            <img class="brand-logo" src="/checkop-logo.png" alt="" />
            <span class="brand-name">Checkop</span>
          </a>

          <nav class="nav">
            <div class="nav-group" *ngFor="let group of groups">
              <span class="nav-label">{{ group.label }}</span>
              <a
                *ngFor="let item of group.items"
                class="nav-link"
                [routerLink]="item.path"
                [class.active]="item.match(url)"
                [attr.aria-current]="item.match(url) ? 'page' : null"
                (click)="menuOpen = false"
              >
                {{ item.label }}
                <span *ngIf="item.locked?.(user)" class="badge badge-pro nav-badge">PRO</span>
              </a>
            </div>
          </nav>

          <div class="sidebar-footer" *ngIf="user">
            <div class="identity">
              <span>Perfil atual</span>
              <strong [title]="user.name">{{ user.name }}</strong>
              <div class="identity-plan">
                <span class="plan-badge">{{ roleLabel[user.role] }}</span>
                <span class="plan-badge" [class.plan-badge-premium]="plan.id === 'PREMIUM'">{{ plan.name }}</span>
              </div>
            </div>
            <button
              class="button button-outline button-sm button-block"
              type="button"
              [attr.aria-pressed]="highContrast"
              (click)="toggleHighContrast()"
            >
              Alto contraste
            </button>
            <button class="button button-outline button-sm button-block" type="button" (click)="logout()">Sair</button>
          </div>
        </aside>

        <div class="main">
          <div class="mobile-bar">
            <button class="button button-ghost button-sm" type="button" (click)="menuOpen = !menuOpen" aria-label="Abrir menu">☰</button>
            <span class="brand-name">Checkop</span>
          </div>
          <main class="page">
            <!-- em Conta e privacidade a janela não cobre a tela (dá para baixar os dados ou excluir a conta) -->
            <div *ngIf="termsPending && !gateOpen" class="alert alert-warning terms-banner" role="status">
              <span>Os Termos de Uso foram atualizados (versão {{ terms?.currentVersion }}). Aceite a nova versão para voltar a usar as varreduras.</span>
              <button class="button button-primary button-sm" type="button" (click)="reviewTerms = true">Revisar e aceitar</button>
            </div>
            <ng-content></ng-content>
          </main>
        </div>
      </div>

      <!-- novo aceite quando a versão dos Termos muda (Termos, seção 14) -->
      <div *ngIf="gateOpen && terms" class="terms-gate" role="dialog" aria-modal="true" aria-labelledby="terms-gate-title">
        <div class="card terms-gate-box">
          <div class="card-body form">
            <h2 id="terms-gate-title">Os Termos de Uso foram atualizados</h2>
            <p class="hint">
              A versão {{ terms.currentVersion }}, de {{ terms.lastUpdated | date: 'dd/MM/yyyy' }},
              {{ terms.acceptedVersion ? 'substitui a versão ' + terms.acceptedVersion + ' que você aceitou.' : 'ainda não foi aceita na sua conta.' }}
              Para continuar usando o Checkop, leia e aceite a nova versão.
            </p>
            <a class="link" routerLink="/terms" target="_blank" rel="noopener">Ler os Termos de Uso (abre em outra aba)</a>
            <app-check [(checked)]="termsAgreed">
              <strong>Li e aceito os Termos de Uso</strong>
              e a Política de Privacidade, que faz parte deles.
            </app-check>
            <div *ngIf="termsError" class="alert alert-error" role="alert">{{ termsError }}</div>
            <div class="actions">
              <button class="button button-primary" type="button" (click)="acceptTerms()" [disabled]="!termsAgreed || isAcceptingTerms">
                <span *ngIf="isAcceptingTerms" class="spinner" aria-hidden="true"></span>
                Aceitar e continuar
              </button>
              <button class="button button-outline" type="button" (click)="logout()">Sair</button>
            </div>
            <p class="hint">
              Não concorda? Você ainda pode
              <a class="link" routerLink="/account" (click)="reviewTerms = false">baixar seus dados ou excluir a conta</a>
              em Conta e privacidade.
            </p>
          </div>
        </div>
      </div>
    </div>
  `,
})
export class AppShellComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly google = inject(GoogleAuthService);
  private readonly account = inject(AccountService);

  protected readonly groups = NAV_GROUPS;
  protected readonly roleLabel = ROLE_LABEL;
  protected readonly user: AuthUser | null = this.auth.getCachedUser();
  protected readonly plan = planOf(this.user);
  protected url = this.router.url;
  protected menuOpen = false;
  protected highContrast = readHighContrast();

  // novo aceite dos Termos (o guard atualiza a situação a cada navegação, via /me)
  protected terms: TermsStatus | null = this.user?.terms ?? null;
  protected reviewTerms = false;
  protected termsAgreed = false;
  protected isAcceptingTerms = false;
  protected termsError: string | null = null;

  protected get termsPending(): boolean {
    return Boolean(this.terms?.updateRequired);
  }

  /** Bloqueia as telas logadas, menos Conta e privacidade (lá vira um aviso no topo). */
  protected get gateOpen(): boolean {
    return this.termsPending && (this.reviewTerms || !this.url.startsWith('/account'));
  }

  protected acceptTerms(): void {
    if (!this.termsAgreed || this.isAcceptingTerms) return;
    this.isAcceptingTerms = true;
    this.termsError = null;
    this.account.acceptTerms().subscribe({
      next: (terms) => {
        this.isAcceptingTerms = false;
        this.terms = terms;
        this.reviewTerms = false;
      },
      error: (error: ApiError) => {
        this.isAcceptingTerms = false;
        this.termsError = error.message;
      },
    });
  }

  constructor() {
    this.router.events
      .pipe(
        filter((event) => event instanceof NavigationEnd),
        takeUntilDestroyed()
      )
      .subscribe((event) => (this.url = (event as NavigationEnd).urlAfterRedirects));
  }

  protected toggleHighContrast(): void {
    this.highContrast = !this.highContrast;
    saveHighContrast(this.highContrast);
  }

  protected logout(): void {
    this.google.disableAutoSelect(); // o Google não reentra sozinho na mesma conta
    this.auth.logout().subscribe({
      next: () => this.router.navigateByUrl('/landing'),
      error: () => this.router.navigateByUrl('/landing'),
    });
  }
}
