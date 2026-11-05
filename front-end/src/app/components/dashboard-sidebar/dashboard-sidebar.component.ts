import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { ROLE_LABEL } from '../../core/constants/dashboard.constants';
import { AuthService } from '../../core/services/auth.service';
import { DashboardStateService } from '../../core/services/dashboard-state.service';

type SidebarSection = 'overview' | 'scan' | 'history';

@Component({
  selector: 'app-dashboard-sidebar',
  imports: [RouterLink],
  templateUrl: './dashboard-sidebar.component.html',
  styleUrl: './dashboard-sidebar.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DashboardSidebarComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  protected readonly state = inject(DashboardStateService);

  protected readonly roleLabel = ROLE_LABEL;
  protected readonly activeSection = signal<SidebarSection>('overview');

  // O dashboard é uma página só: os itens do menu rolam até a seção
  // correspondente (ids "scan" e "history" estão nos componentes).
  protected goTo(section: SidebarSection): void {
    this.activeSection.set(section);
    this.state.scrollToSection(section === 'overview' ? 'top' : section);
  }

  protected logout(): void {
    this.auth.logout().subscribe({
      next: () => this.router.navigateByUrl('/landing'),
      error: () => this.router.navigateByUrl('/landing'),
    });
  }
}
