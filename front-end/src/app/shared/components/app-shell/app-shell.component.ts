import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink } from '@angular/router';
import { filter } from 'rxjs';
import { AuthService, AuthUser } from '../../../core/services/auth.service';
import { GoogleAuthService } from '../../../core/services/google-auth.service';
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
  imports: [CommonModule, RouterLink],
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
            <ng-content></ng-content>
          </main>
        </div>
      </div>
    </div>
  `,
})
export class AppShellComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly google = inject(GoogleAuthService);

  protected readonly groups = NAV_GROUPS;
  protected readonly roleLabel = ROLE_LABEL;
  protected readonly user: AuthUser | null = this.auth.getCachedUser();
  protected readonly plan = planOf(this.user);
  protected url = this.router.url;
  protected menuOpen = false;
  protected highContrast = readHighContrast();

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
