import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink } from '@angular/router';
import { filter } from 'rxjs';
import { AuthService, AuthUser } from '../../../core/services/auth.service';
import { ROLE_LABEL } from '../../ui/labels';

interface NavItem {
  path: string;
  label: string;
  icon: string;
  pro?: boolean;
  /** decide se o item está ativo para a URL atual */
  match: (url: string) => boolean;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

// Ícones SVG (traço) embutidos: sem biblioteca extra.
const ICON = {
  home: 'M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z',
  plus: 'M12 5v14M5 12h14',
  history: 'M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5M12 7v5l3 2',
  globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9S14.5 18.3 12 21c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z',
  code: 'm8 17-5-5 5-5M16 7l5 5-5 5M14 4l-4 16',
  user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0',
  star: 'm12 3 2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9z',
};

export const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Visão geral',
    items: [{ path: '/dashboard', label: 'Painel', icon: ICON.home, match: (u) => u.startsWith('/dashboard') }],
  },
  {
    label: 'Varreduras',
    items: [
      { path: '/scans/new', label: 'Nova varredura', icon: ICON.plus, match: (u) => u.startsWith('/scans/new') },
      {
        path: '/scans',
        label: 'Histórico',
        icon: ICON.history,
        match: (u) => /^\/scans(\/(?!new)[^/?#]+)?([?#].*)?$/.test(u),
      },
    ],
  },
  {
    label: 'Segurança',
    items: [
      { path: '/targets', label: 'Domínios', icon: ICON.globe, match: (u) => u.startsWith('/targets') },
      { path: '/code-analysis', label: 'Análise de código', icon: ICON.code, pro: true, match: (u) => u.startsWith('/code-analysis') },
    ],
  },
  {
    label: 'Conta',
    items: [
      { path: '/plans', label: 'Planos', icon: ICON.star, match: (u) => u.startsWith('/plans') },
      { path: '/account', label: 'Conta e privacidade', icon: ICON.user, match: (u) => u.startsWith('/account') },
    ],
  },
];

/**
 * Layout das telas logadas: menu lateral fixo à esquerda e conteúdo alinhado
 * à esquerda. Estilos em src/styles/_app-ui.scss (escopo .ck-app).
 */
@Component({
  selector: 'app-shell',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="ck-app">
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
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path [attr.d]="item.icon" />
                </svg>
                {{ item.label }}
                <span *ngIf="item.pro && !isPremium" class="badge badge-pro nav-badge">PRO</span>
              </a>
            </div>
          </nav>

          <div class="sidebar-footer" *ngIf="user">
            <div class="user-card">
              <span class="avatar" aria-hidden="true">{{ initials }}</span>
              <div class="user-meta">
                <strong>{{ user.name }}</strong>
                <span>{{ roleLabel[user.role] }} · {{ isPremium ? 'Premium' : 'Free' }}</span>
              </div>
            </div>
            <button class="button button-ghost button-sm button-block" type="button" (click)="logout()">Sair</button>
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

  protected readonly groups = NAV_GROUPS;
  protected readonly roleLabel = ROLE_LABEL;
  protected readonly user: AuthUser | null = this.auth.getCachedUser();
  protected url = this.router.url;
  protected menuOpen = false;

  constructor() {
    this.router.events
      .pipe(
        filter((event) => event instanceof NavigationEnd),
        takeUntilDestroyed()
      )
      .subscribe((event) => (this.url = (event as NavigationEnd).urlAfterRedirects));
  }

  protected get isPremium(): boolean {
    return this.user?.plan === 'PREMIUM';
  }

  protected get initials(): string {
    return (this.user?.name ?? '?')
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase())
      .join('');
  }

  protected logout(): void {
    this.auth.logout().subscribe({
      next: () => this.router.navigateByUrl('/landing'),
      error: () => this.router.navigateByUrl('/landing'),
    });
  }
}
